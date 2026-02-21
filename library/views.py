import io
import json
import zipfile

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db.models import Case, F, IntegerField, Q, Value, When
from django.http import FileResponse, Http404, HttpResponseForbidden, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from accounts.utils import get_client_ip

from .models import (
    AccessCode,
    Category,
    CodeUsageLog,
    DownloadSession,
    Ebook,
    EbookDownload,
    EbookFile,
    FailedCodeAttempt,
    Favorite,
    FileDownloadAttempt,
    DownloadHistory,
    Review,
    ReviewAbuseLog,
    SearchQueryLog,
    SecurityEventLog,
    SystemErrorLog,
    BackupRecord,
    SystemSetting,
)
from .security import (
    clear_code_failures,
    is_code_locked,
    issue_code_captcha,
    make_code_session_token,
    make_download_token,
    make_file_link_token,
    needs_code_captcha,
    read_code_session_token,
    read_download_token,
    read_file_link_token,
    register_code_failure,
    safe_storage_path,
)

User = get_user_model()


def _auth_user(request):
    session = getattr(request, 'authenticated_session', None)
    if session:
        return session.user
    return None


def _session_key(request):
    if not request.session.session_key:
        request.session.save()
    return request.session.session_key or 'anonymous'


def _record_successful_download(*, user, ebook_file, ip_address, code=None):
    EbookDownload.objects.create(user=user, ebook_file=ebook_file, ip_address=ip_address)
    Ebook.objects.filter(id=ebook_file.ebook_id).update(download_count=F('download_count') + 1)
    if user:
        DownloadHistory.objects.create(
            user=user,
            ebook_id=ebook_file.ebook_id,
            code=code,
            version_label=ebook_file.version_label,
        )


def _system_setting():
    return SystemSetting.objects.first() or SystemSetting.objects.create()


def _log_security_event(event_type, *, severity='info', request=None, user=None, metadata=None):
    SecurityEventLog.objects.create(
        event_type=event_type,
        severity=severity,
        ip_address=get_client_ip(request) if request else None,
        user=user,
        metadata=metadata or {},
    )


def _maintenance_blocks(request, feature):
    cfg = _system_setting()
    if not cfg.maintenance_mode:
        return None
    user = _auth_user(request)
    if user and user.role == User.Role.ADMIN:
        return None
    if feature == 'downloads' and cfg.disable_downloads:
        return JsonResponse({'error': cfg.notification_message or 'Downloads are temporarily disabled for maintenance.'}, status=503)
    if feature == 'codes' and cfg.disable_code_entry:
        return JsonResponse({'error': cfg.notification_message or 'Code entry is temporarily disabled for maintenance.'}, status=503)
    return None


def _failure_spike_detected(ip):
    window_start = timezone.now() - timezone.timedelta(minutes=10)
    return FailedCodeAttempt.objects.filter(ip_address=ip, created_at__gte=window_start).count() >= settings.CODE_FAILURE_ALERT_THRESHOLD


@require_GET
def homepage(request):
    featured = Ebook.objects.filter(is_active=True, is_featured=True).order_by('-updated_at')[:8]
    top_downloads = Ebook.objects.filter(is_active=True).order_by('-download_count')[:5]
    latest_reviews = Review.objects.select_related('user', 'ebook').order_by('-created_at')[:5]
    categories = Category.objects.all().order_by('name')[:12]
    return render(
        request,
        'home.html',
        {
            'featured_ebooks': featured,
            'top_downloads': top_downloads,
            'latest_reviews': latest_reviews,
            'homepage_categories': categories,
        },
    )


@require_GET
def catalog_listing(request):
    query = request.GET.get('q', '').strip()
    category_slug = request.GET.get('category', '').strip()
    author = request.GET.get('author', '').strip()
    min_rating = request.GET.get('min_rating', '').strip()
    featured = request.GET.get('featured', '').strip().lower()
    sort = request.GET.get('sort', 'newest').strip().lower()
    page = int(request.GET.get('page', '1') or 1)

    ebooks = Ebook.objects.filter(is_active=True).select_related('category')
    if query:
        ebooks = ebooks.filter(Q(title__icontains=query) | Q(author__icontains=query) | Q(description__icontains=query) | Q(keywords__icontains=query))
    if category_slug:
        ebooks = ebooks.filter(category__slug=category_slug)
    if author:
        ebooks = ebooks.filter(author__icontains=author)
    if min_rating:
        try:
            ebooks = ebooks.filter(average_rating__gte=float(min_rating))
        except ValueError:
            pass
    if featured in ('1', 'true', 'yes'):
        ebooks = ebooks.filter(is_featured=True)

    if sort == 'most_downloaded':
        ebooks = ebooks.order_by('-download_count', '-created_at')
    elif sort == 'highest_rated':
        ebooks = ebooks.order_by('-average_rating', '-review_count', '-created_at')
    elif sort == 'alphabetical':
        ebooks = ebooks.order_by('title')
    else:
        ebooks = ebooks.order_by('-created_at')

    paginator = Paginator(ebooks, 12)
    page_obj = paginator.get_page(page)

    return render(
        request,
        'catalog.html',
        {
            'page_obj': page_obj,
            'paginator': paginator,
            'q': query,
            'selected_category': category_slug,
            'selected_author': author,
            'selected_min_rating': min_rating,
            'selected_featured': featured,
            'selected_sort': sort,
            'categories': Category.objects.all().order_by('name'),
            'authors': Ebook.objects.filter(is_active=True).values_list('author', flat=True).distinct().order_by('author')[:200],
        },
    )


@require_GET
def ebook_catalog(request):
    query = request.GET.get('q', '').strip()
    category_slug = request.GET.get('category', '').strip()
    author = request.GET.get('author', '').strip()
    min_rating = request.GET.get('min_rating', '').strip()
    featured = request.GET.get('featured', '').strip().lower()
    recent = request.GET.get('recent', '').strip().lower()
    sort = request.GET.get('sort', 'newest').strip().lower()
    page = int(request.GET.get('page', '1') or 1)
    per_page = min(int(request.GET.get('page_size', '20') or 20), 50)

    ebooks = Ebook.objects.filter(is_active=True).select_related('category').prefetch_related('tags')

    if query:
        ebooks = ebooks.filter(
            Q(title__icontains=query)
            | Q(author__icontains=query)
            | Q(description__icontains=query)
            | Q(category__name__icontains=query)
            | Q(keywords__icontains=query)
            | Q(tags__name__icontains=query)
        ).annotate(
            rank=Case(
                When(title__icontains=query, then=Value(3)),
                When(author__icontains=query, then=Value(2)),
                default=Value(1),
                output_field=IntegerField(),
            )
        )
    else:
        ebooks = ebooks.annotate(rank=Value(0, output_field=IntegerField()))

    if category_slug:
        cache_key = f'category-cache:{category_slug}'
        category_ids = cache.get(cache_key)
        if category_ids is None:
            category_ids = list(Ebook.objects.filter(category__slug=category_slug, is_active=True).values_list('id', flat=True))
            cache.set(cache_key, category_ids, timeout=settings.CATEGORY_CACHE_TTL_SECONDS)
        ebooks = ebooks.filter(id__in=category_ids)
    if author:
        ebooks = ebooks.filter(author__icontains=author)
    if min_rating:
        try:
            ebooks = ebooks.filter(average_rating__gte=float(min_rating))
        except ValueError:
            pass
    if featured in ('1', 'true', 'yes'):
        ebooks = ebooks.filter(is_featured=True)
    if recent in ('1', 'true', 'yes'):
        ebooks = ebooks.filter(created_at__gte=timezone.now() - timezone.timedelta(days=30))

    if sort == 'highest_rated':
        ebooks = ebooks.order_by('-average_rating', '-review_count', '-rank', '-created_at')
    elif sort == 'most_downloaded':
        ebooks = ebooks.order_by('-download_count', '-rank', '-created_at')
    elif sort == 'alphabetical':
        ebooks = ebooks.order_by('title')
    else:
        ebooks = ebooks.order_by('-rank', '-created_at')

    paginator = Paginator(ebooks.distinct(), per_page)
    page_obj = paginator.get_page(page)

    if query:
        SearchQueryLog.objects.create(term=query, result_count=paginator.count, ip_address=get_client_ip(request))

    data = {
        'featured': [
            {'id': e.id, 'slug': e.slug, 'title': e.title, 'author': e.author, 'category': e.category.name, 'summary_text': e.summary_text, 'average_rating': str(e.average_rating)}
            for e in Ebook.objects.filter(is_active=True, is_featured=True).select_related('category').order_by('-updated_at')[:20]
        ],
        'results': [
            {
                'id': e.id,
                'slug': e.slug,
                'title': e.title,
                'author': e.author,
                'category': e.category.name,
                'average_rating': str(e.average_rating),
                'download_count': e.download_count,
                'cover_image_path': e.cover_image_path,
                'lazy_cover': True,
            }
            for e in page_obj.object_list
        ],
        'pagination': {'page': page_obj.number, 'pages': paginator.num_pages, 'total': paginator.count, 'has_next': page_obj.has_next()},
    }
    return JsonResponse(data)


@require_GET
def ebook_preview(request, ebook_id):
    ebook = get_object_or_404(Ebook.objects.select_related('category'), id=ebook_id, is_active=True)
    page_url = f"/ebooks/{ebook.slug}/"
    data = {
        'id': ebook.id,
        'slug': ebook.slug,
        'title': ebook.title,
        'description': ebook.description,
        'author': ebook.author,
        'summary_text': ebook.summary_text,
        'sample_preview_path': ebook.sample_preview_path,
        'meta_title': ebook.meta_title,
        'meta_description': ebook.meta_description,
        'files': [{'name': f.file_name, 'size': f.file_size, 'version': f.version_label} for f in ebook.files.all()],
        'social_share': {'ebook_page': page_url, 'preview_page': f"{page_url}preview/", 'reviews_page': f"{page_url}reviews/"},
        'structured_data': {
            '@context': 'https://schema.org',
            '@type': 'Book',
            'name': ebook.title,
            'author': ebook.author,
            'description': ebook.meta_description,
            'aggregateRating': {'@type': 'AggregateRating', 'ratingValue': str(ebook.average_rating), 'reviewCount': ebook.review_count},
        },
    }
    return JsonResponse(data)


@require_POST
def toggle_favorite(request, ebook_id):
    user = _auth_user(request)
    if not user:
        return HttpResponseForbidden('Authentication required')
    ebook = get_object_or_404(Ebook, id=ebook_id, is_active=True)
    favorite = Favorite.objects.filter(user=user, ebook=ebook)
    if favorite.exists():
        favorite.delete()
        return JsonResponse({'favorited': False})
    Favorite.objects.create(user=user, ebook=ebook)
    return JsonResponse({'favorited': True})




@require_GET
def list_favorites(request):
    user = _auth_user(request)
    if not user:
        return HttpResponseForbidden('Authentication required')

    sort = request.GET.get('sort', 'recent')
    queryset = Favorite.objects.filter(user=user).select_related('ebook')
    if sort == 'rating':
        queryset = queryset.order_by('-ebook__average_rating', 'ebook__title')
    elif sort == 'title':
        queryset = queryset.order_by('ebook__title')
    else:
        queryset = queryset.order_by('-created_at')

    return JsonResponse({'favorites': [{'ebook_id': f.ebook_id, 'title': f.ebook.title, 'average_rating': str(f.ebook.average_rating), 'created_at': f.created_at.isoformat()} for f in queryset[:200]]})


@require_POST
def create_download_link(request, file_id):
    user = _auth_user(request)
    if not user:
        return HttpResponseForbidden('Authentication required')
    ebook_file = get_object_or_404(EbookFile.objects.select_related('ebook'), id=file_id, ebook__is_active=True)
    token = make_download_token(ebook_file.id, user.id)
    return JsonResponse({'download_url': f'/ebooks/download/{token}/'})


@require_GET
def code_entry_interface(request):
    user = _auth_user(request)
    if not user:
        return HttpResponseForbidden('Authentication required')
    return render(request, 'code_entry.html', {'user_obj': user, 'prefill_code': request.GET.get('code', '').strip()})


@require_POST
def generate_code(request, ebook_id):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    ebook = get_object_or_404(Ebook, id=ebook_id, is_active=True)
    expiry_minutes = int(request.POST.get('expiry_minutes', '60'))
    code = AccessCode.issue(ebook=ebook, created_by_admin=user, expiry_minutes=expiry_minutes)
    return JsonResponse({'code_value': code.code_value, 'expires_at': code.expires_at.isoformat()})


@require_POST
def validate_code(request):
    blocked = _maintenance_blocks(request, 'codes')
    if blocked:
        return blocked
    code_value = request.POST.get('code', '').strip()
    ip = get_client_ip(request)
    session_key = _session_key(request)
    user = _auth_user(request)
    if not user:
        return JsonResponse({'error': 'Login required to redeem codes.'}, status=403)

    if is_code_locked(ip, session_key):
        FailedCodeAttempt.objects.create(code_value=code_value, ip_address=ip, session_key=session_key, reason='locked')
        captcha_prompt = issue_code_captcha(request)
        return JsonResponse({'error': 'Too many attempts. Try later.', 'captcha_required': True, 'captcha_prompt': captcha_prompt}, status=429)

    if needs_code_captcha(ip, session_key):
        expected = request.session.get('code_captcha_answer')
        provided = request.POST.get('captcha_answer', '').strip()
        if str(expected) != provided:
            register_code_failure(ip, session_key)
            FailedCodeAttempt.objects.create(code_value=code_value, ip_address=ip, session_key=session_key, reason='captcha_failed')
            captcha_prompt = issue_code_captcha(request)
            return JsonResponse({'error': 'Captcha verification failed.', 'captcha_required': True, 'captcha_prompt': captcha_prompt}, status=400)

    code = AccessCode.objects.filter(code_value=code_value).select_related('ebook').first()
    if not code:
        register_code_failure(ip, session_key)
        FailedCodeAttempt.objects.create(code_value=code_value, ip_address=ip, session_key=session_key, reason='not_found')
        response = {'error': 'Invalid code.'}
        if needs_code_captcha(ip, session_key):
            response['captcha_required'] = True
            response['captcha_prompt'] = issue_code_captcha(request)
        return JsonResponse(response, status=404)

    if not code.is_active:
        register_code_failure(ip, session_key)
        FailedCodeAttempt.objects.create(code_value=code_value, ip_address=ip, session_key=session_key, reason='inactive')
        return JsonResponse({'error': 'Code is deactivated.'}, status=400)

    if code.expires_at <= timezone.now():
        register_code_failure(ip, session_key)
        FailedCodeAttempt.objects.create(code_value=code_value, ip_address=ip, session_key=session_key, reason='expired')
        return JsonResponse({'error': 'Code expired.'}, status=400)

    if code.is_used:
        register_code_failure(ip, session_key)
        FailedCodeAttempt.objects.create(code_value=code_value, ip_address=ip, session_key=session_key, reason='already_used')
        return JsonResponse({'error': 'Code already used.'}, status=400)

    code.is_used = True
    code.save(update_fields=['is_used'])
    usage = CodeUsageLog.objects.create(
        code=code,
        user=user,
        ip_address=ip,
        device_info=request.META.get('HTTP_USER_AGENT', '')[:255],
    )
    expires_at = timezone.now() + timezone.timedelta(seconds=settings.CODE_DOWNLOAD_SESSION_TTL_SECONDS)
    download_session = DownloadSession.objects.create(
        code=code,
        ebook=code.ebook,
        user=user,
        ip_address=ip,
        expires_at=expires_at,
    )
    clear_code_failures(ip, session_key)
    gate_token = make_code_session_token(download_session.id, code.id, code.ebook_id, user.id if user else None, usage.id)

    files = []
    for f in code.ebook.files.all():
        file_token = make_file_link_token(download_session.id, f.id)
        files.append(
            {
                'id': f.id,
                'name': f.file_name,
                'size': f.file_size,
                'version': f.version_label,
                'download_url': f'/ebooks/codes/files/{file_token}/download/',
            }
        )

    response = {
        'message': 'Code accepted. Download session created.',
        'confirmation': {'return_home': '/', 'progress_label': 'Ready to download'},
        'ebook_id': code.ebook_id,
        'files': files,
        'download_session_token': gate_token,
        'download_session_expires_at': expires_at.isoformat(),
        'retry_allowed': True,
    }
    if _failure_spike_detected(ip):
        response['admin_alert_recommended'] = True
    return JsonResponse(response)


@require_GET
def code_download(request, token, file_id):
    blocked = _maintenance_blocks(request, 'downloads')
    if blocked:
        return blocked
    try:
        payload = read_code_session_token(token, max_age_seconds=settings.CODE_DOWNLOAD_SESSION_TTL_SECONDS)
    except signing.BadSignature:
        _log_security_event('invalid_code_session', severity='warning', request=request)
        return HttpResponseForbidden('Invalid or expired code session')

    user = _auth_user(request)
    if payload.get('user_id') and (not user or user.id != payload['user_id']):
        return HttpResponseForbidden('Code session is bound to another user')

    session = get_object_or_404(
        DownloadSession.objects.select_related('ebook', 'user'),
        id=payload['session_id'],
        code_id=payload['code_id'],
        is_active=True,
    )
    if session.expires_at <= timezone.now():
        session.is_active = False
        session.save(update_fields=['is_active'])
        return HttpResponseForbidden('Download session expired')

    ebook_file = get_object_or_404(EbookFile.objects.select_related('ebook'), id=file_id, ebook_id=session.ebook_id, ebook__is_active=True)
    attempt = FileDownloadAttempt.objects.create(session=session, ebook_file=ebook_file, ip_address=get_client_ip(request))
    try:
        path = safe_storage_path(ebook_file.file_path)
        if not path.exists() or not path.is_file():
            raise Http404('File not found')
        attempt.success = True
        attempt.download_completed = True
        attempt.save(update_fields=['success', 'download_completed'])
    except Exception as exc:
        attempt.error_reason = str(exc)[:255]
        attempt.save(update_fields=['error_reason'])
        SystemErrorLog.objects.create(source='download', message=str(exc), metadata={'ebook_file_id': ebook_file.id})
        _log_security_event('download_failure', severity='error', request=request, metadata={'ebook_file_id': ebook_file.id, 'reason': str(exc)[:120]})
        raise

    _record_successful_download(user=user, ebook_file=ebook_file, ip_address=get_client_ip(request), code=session.code)
    CodeUsageLog.objects.filter(id=payload['usage_log_id']).update(download_completed=True)
    return FileResponse(open(path, 'rb'), as_attachment=True, filename=ebook_file.file_name)


@require_GET
def code_file_download(request, file_token):
    blocked = _maintenance_blocks(request, 'downloads')
    if blocked:
        return blocked
    try:
        payload = read_file_link_token(file_token, max_age_seconds=settings.CODE_DOWNLOAD_SESSION_TTL_SECONDS)
    except signing.BadSignature:
        _log_security_event('invalid_file_token', severity='warning', request=request)
        return HttpResponseForbidden('Invalid or expired file token')

    session = get_object_or_404(DownloadSession, id=payload['session_id'], is_active=True)
    if session.expires_at <= timezone.now():
        session.is_active = False
        session.save(update_fields=['is_active'])
        return HttpResponseForbidden('Download session expired')

    ebook_file = get_object_or_404(EbookFile, id=payload['file_id'], ebook_id=session.ebook_id)
    attempt = FileDownloadAttempt.objects.create(session=session, ebook_file=ebook_file, ip_address=get_client_ip(request))

    try:
        path = safe_storage_path(ebook_file.file_path)
        if not path.exists() or not path.is_file():
            raise Http404('File not found')
        attempt.success = True
        attempt.download_completed = True
        attempt.save(update_fields=['success', 'download_completed'])
    except Exception as exc:
        attempt.error_reason = str(exc)[:255]
        attempt.save(update_fields=['error_reason'])
        SystemErrorLog.objects.create(source='download', message=str(exc), metadata={'ebook_file_id': ebook_file.id})
        _log_security_event('download_failure', severity='error', request=request, metadata={'ebook_file_id': ebook_file.id, 'reason': str(exc)[:120]})
        raise

    _record_successful_download(user=session.user, ebook_file=ebook_file, ip_address=get_client_ip(request), code=session.code)
    CodeUsageLog.objects.filter(code=session.code).update(download_completed=True)
    return FileResponse(open(path, 'rb'), as_attachment=True, filename=ebook_file.file_name)


@require_GET
def code_download_bundle_zip(request, token):
    blocked = _maintenance_blocks(request, 'downloads')
    if blocked:
        return blocked
    try:
        payload = read_code_session_token(token, max_age_seconds=settings.CODE_DOWNLOAD_SESSION_TTL_SECONDS)
    except signing.BadSignature:
        _log_security_event('invalid_code_session', severity='warning', request=request)
        return HttpResponseForbidden('Invalid or expired code session')

    session = get_object_or_404(DownloadSession, id=payload['session_id'], is_active=True)
    if session.expires_at <= timezone.now():
        session.is_active = False
        session.save(update_fields=['is_active'])
        return HttpResponseForbidden('Download session expired')

    files = EbookFile.objects.filter(ebook_id=session.ebook_id)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for ebook_file in files:
            attempt = FileDownloadAttempt.objects.create(session=session, ebook_file=ebook_file, ip_address=get_client_ip(request))
            try:
                path = safe_storage_path(ebook_file.file_path)
                if not path.exists() or not path.is_file():
                    raise Http404('File not found')
                zf.write(path, arcname=ebook_file.file_name)
                attempt.success = True
                attempt.download_completed = True
                attempt.save(update_fields=['success', 'download_completed'])
                _record_successful_download(user=session.user, ebook_file=ebook_file, ip_address=get_client_ip(request), code=session.code)
            except Exception as exc:
                attempt.error_reason = str(exc)[:255]
                attempt.save(update_fields=['error_reason'])

    zip_buffer.seek(0)
    CodeUsageLog.objects.filter(id=payload['usage_log_id']).update(download_completed=True)
    return FileResponse(zip_buffer, as_attachment=True, filename=f'ebook-{session.ebook_id}-bundle.zip')


@require_GET
def download_history(request):
    user = _auth_user(request)
    if not user:
        return HttpResponseForbidden('Authentication required')
    logs = DownloadHistory.objects.filter(user=user).select_related('ebook', 'code').order_by('-downloaded_at')[:200]
    return JsonResponse({'history': [{'ebook_title': l.ebook.title, 'code_id': l.code_id, 'downloaded_at': l.downloaded_at.isoformat(), 'version_label': l.version_label} for l in logs]})


@require_GET
def admin_download_history(request):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    logs = DownloadHistory.objects.select_related('user', 'ebook', 'code').order_by('-downloaded_at')[:500]
    return JsonResponse({'history': [{'user_email': l.user.email, 'ebook_title': l.ebook.title, 'code_id': l.code_id, 'downloaded_at': l.downloaded_at.isoformat(), 'version_label': l.version_label} for l in logs]})


@require_POST
def deactivate_code(request, code_id):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    code = get_object_or_404(AccessCode, id=code_id)
    code.is_active = False
    code.save(update_fields=['is_active'])
    return JsonResponse({'deactivated': True})


@require_GET
def secure_download(request, token):
    blocked = _maintenance_blocks(request, 'downloads')
    if blocked:
        return blocked
    try:
        payload = read_download_token(token, max_age_seconds=settings.EBOOK_DOWNLOAD_TOKEN_MAX_AGE_SECONDS)
    except signing.BadSignature:
        _log_security_event('invalid_download_token', severity='warning', request=request)
        return HttpResponseForbidden('Invalid or expired token')
    user = _auth_user(request)
    if payload.get('user_id') and (not user or user.id != payload['user_id']):
        return HttpResponseForbidden('Invalid user')
    ebook_file = get_object_or_404(EbookFile.objects.select_related('ebook'), id=payload['file_id'], ebook__is_active=True)
    path = safe_storage_path(ebook_file.file_path)
    if not path.exists() or not path.is_file():
        raise Http404('File not found')
    _record_successful_download(user=user, ebook_file=ebook_file, ip_address=get_client_ip(request), code=None)
    return FileResponse(open(path, 'rb'), as_attachment=True, filename=ebook_file.file_name)


def _review_rate_key(user_id, ip):
    return f"review-rate:{user_id}:{ip}"


def _review_rate_limited(user_id, ip):
    return cache.get(_review_rate_key(user_id, ip), 0) >= settings.REVIEW_RATE_LIMIT_ATTEMPTS


def _register_review_submission(user_id, ip):
    key = _review_rate_key(user_id, ip)
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, timeout=settings.REVIEW_RATE_LIMIT_WINDOW_SECONDS)


@require_POST
def upsert_review(request, ebook_id):
    user = _auth_user(request)
    if not user:
        return HttpResponseForbidden('Authentication required')
    ebook = get_object_or_404(Ebook, id=ebook_id, is_active=True)
    ip = get_client_ip(request)

    if _review_rate_limited(user.id, ip):
        ReviewAbuseLog.objects.create(user=user, ebook=ebook, ip_address=ip, reason='review_rate_limited')
        return JsonResponse({'error': 'Too many review submissions. Please wait.'}, status=429)

    try:
        rating = int(request.POST.get('rating', '0'))
    except ValueError:
        rating = 0
    review_text = request.POST.get('review_text', '').strip()
    if rating < 1 or rating > 5:
        ReviewAbuseLog.objects.create(user=user, ebook=ebook, ip_address=ip, reason='invalid_rating')
        return JsonResponse({'error': 'Rating must be between 1 and 5.'}, status=400)

    review, created = Review.objects.update_or_create(
        ebook=ebook,
        user=user,
        defaults={'rating': rating, 'review_text': review_text},
    )
    _register_review_submission(user.id, ip)
    return JsonResponse(
        {
            'created': created,
            'review': {
                'id': review.id,
                'rating': review.rating,
                'review_text': review.review_text,
                'created_at': review.created_at.isoformat(),
                'updated_at': review.updated_at.isoformat(),
            },
            'ebook_rating_summary': {'average_rating': str(ebook.average_rating), 'review_count': ebook.review_count},
        }
    )


@require_GET
def ebook_reviews(request, ebook_id):
    ebook = get_object_or_404(Ebook, id=ebook_id, is_active=True)
    rows = Review.objects.filter(ebook=ebook).select_related('user').order_by('-created_at')[:200]
    return JsonResponse(
        {
            'ebook_id': ebook.id,
            'average_rating': str(ebook.average_rating),
            'review_count': ebook.review_count,
            'reviews': [
                {
                    'user_email': r.user.email,
                    'rating': r.rating,
                    'review_text': r.review_text,
                    'created_at': r.created_at.isoformat(),
                    'updated_at': r.updated_at.isoformat(),
                }
                for r in rows
            ],
        }
    )


@require_GET
def my_reviews(request):
    user = _auth_user(request)
    if not user:
        return HttpResponseForbidden('Authentication required')
    rows = Review.objects.filter(user=user).select_related('ebook').order_by('-updated_at')
    return JsonResponse(
        {'reviews': [{'ebook': r.ebook.title, 'rating': r.rating, 'review_text': r.review_text, 'updated_at': r.updated_at.isoformat()} for r in rows]}
    )


@require_POST
def delete_my_review(request, review_id):
    user = _auth_user(request)
    if not user:
        return HttpResponseForbidden('Authentication required')
    review = get_object_or_404(Review, id=review_id, user=user)
    ebook = review.ebook
    review.delete()
    ebook.refresh_rating_aggregates()
    return JsonResponse({'deleted': True})


@require_POST
def admin_delete_review(request, review_id):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    review = get_object_or_404(Review, id=review_id)
    review.delete()
    return JsonResponse({'deleted': True})


@require_GET
def review_analytics(request):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')

    most_reviewed = list(Ebook.objects.filter(is_active=True).order_by('-review_count').values('id', 'title', 'review_count')[:10])
    highest_rated = list(Ebook.objects.filter(is_active=True, review_count__gt=0).order_by('-average_rating', '-review_count').values('id', 'title', 'average_rating', 'review_count')[:10])
    recent_reviews = list(Review.objects.select_related('ebook', 'user').order_by('-created_at').values('id', 'ebook__title', 'user__email', 'rating', 'created_at')[:20])
    return JsonResponse({'most_reviewed': most_reviewed, 'highest_rated': highest_rated, 'recent_review_activity': recent_reviews})


@require_GET
def search_suggestions(request):
    term = request.GET.get('q', '').strip()
    if not term:
        return JsonResponse({'suggestions': []})
    ebooks = Ebook.objects.filter(is_active=True).filter(Q(title__icontains=term) | Q(author__icontains=term)).order_by('-download_count', '-average_rating')[:10]
    suggestions = [{'type': 'title', 'value': e.title, 'slug': e.slug} for e in ebooks]
    authors = list(Ebook.objects.filter(is_active=True, author__icontains=term).values_list('author', flat=True).distinct()[:5])
    suggestions.extend([{'type': 'author', 'value': a} for a in authors])
    return JsonResponse({'suggestions': suggestions})


@require_GET
def search_analytics(request):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    # practical aggregates via python fallback
    logs = list(SearchQueryLog.objects.values('term', 'result_count').order_by('-created_at')[:5000])
    freq = {}
    zero = {}
    for row in logs:
        t = row['term']
        freq[t] = freq.get(t, 0) + 1
        if row['result_count'] == 0:
            zero[t] = zero.get(t, 0) + 1
    most_terms = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:20]
    zero_terms = sorted(zero.items(), key=lambda x: x[1], reverse=True)[:20]
    return JsonResponse({'most_searched_terms': [{'term': t, 'count': c} for t, c in most_terms], 'zero_result_terms': [{'term': t, 'count': c} for t, c in zero_terms]})


@require_GET
def ebook_detail_by_slug(request, slug):
    ebook = get_object_or_404(Ebook.objects.select_related('category'), slug=slug, is_active=True)
    files = list(ebook.files.all())
    reviews = list(Review.objects.filter(ebook=ebook).select_related('user').order_by('-created_at')[:50])
    user = _auth_user(request)
    is_favorited = False
    user_review = None
    if user:
        is_favorited = Favorite.objects.filter(user=user, ebook=ebook).exists()
        user_review = Review.objects.filter(user=user, ebook=ebook).first()

    return render(
        request,
        'ebook_detail.html',
        {
            'ebook': ebook,
            'ebook_files': files,
            'reviews': reviews,
            'is_favorited': is_favorited,
            'user_review': user_review,
            'structured_data_json': json.dumps(
                {
                    '@context': 'https://schema.org',
                    '@type': 'Book',
                    'name': ebook.title,
                    'author': ebook.author,
                    'description': ebook.meta_description,
                    'aggregateRating': {
                        '@type': 'AggregateRating',
                        'ratingValue': str(ebook.average_rating),
                        'reviewCount': ebook.review_count,
                    },
                }
            ),
        },
    )


@require_GET
def static_page(request, page_slug):
    pages = {
        'about': {
            'title': 'About Ebooks Library',
            'meta_description': 'Learn about Ebooks Library, our mission, and how we deliver secure ebook access.',
            'heading': 'About Us',
            'body': 'Ebooks Library is a secure platform for discovering and accessing curated ebook content with code-based delivery and user-focused personalization.',
        },
        'contact': {
            'title': 'Contact Support - Ebooks Library',
            'meta_description': 'Contact Ebooks Library support for help with codes, downloads, and account issues.',
            'heading': 'Contact Support',
            'body': 'For help with account access, code redemption, or download issues, email support@ebookslibrary.example or use the support request form.',
        },
        'privacy': {
            'title': 'Privacy Policy - Ebooks Library',
            'meta_description': 'Read the Ebooks Library privacy policy for how we handle account, download, and activity data.',
            'heading': 'Privacy Policy',
            'body': 'We collect only the data needed to secure accounts, validate code usage, and provide download history, analytics, and abuse prevention controls.',
        },
        'terms': {
            'title': 'Terms of Service - Ebooks Library',
            'meta_description': 'Review the Ebooks Library terms governing code usage, ebook access, and account responsibilities.',
            'heading': 'Terms of Service',
            'body': 'Access codes are single-use unless stated otherwise. Download links are temporary, and users must comply with all applicable usage and copyright rules.',
        },
    }
    page = pages.get(page_slug)
    if not page:
        raise Http404('Page not found')
    return render(
        request,
        'static_page.html',
        {
            'page': page,
            'page_slug': page_slug,
            'structured_data_json': json.dumps(
                {
                    '@context': 'https://schema.org',
                    '@type': 'WebPage',
                    'name': page['title'],
                    'description': page['meta_description'],
                    'url': f'/{page_slug}/',
                }
            ),
        },
    )


@require_GET
def admin_dashboard(request):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')

    now = timezone.now()
    daily_start = now - timezone.timedelta(days=1)
    weekly_start = now - timezone.timedelta(days=7)

    total_ebooks = Ebook.objects.count()
    total_active_codes = AccessCode.objects.filter(is_active=True, expires_at__gt=now).count()
    used_codes = AccessCode.objects.filter(is_used=True).count()
    expired_codes = AccessCode.objects.filter(expires_at__lte=now).count()
    total_downloads = EbookDownload.objects.count()
    daily_downloads = EbookDownload.objects.filter(created_at__gte=daily_start).count()
    weekly_downloads = EbookDownload.objects.filter(created_at__gte=weekly_start).count()

    top = Ebook.objects.order_by('-download_count').first()
    top_ebooks = list(Ebook.objects.filter(is_active=True).order_by('-download_count').values('title', 'download_count')[:10])
    recent_activity = list(SecurityEventLog.objects.order_by('-created_at').values('event_type', 'severity', 'created_at')[:20])

    by_day = {}
    for row in EbookDownload.objects.filter(created_at__gte=weekly_start).values('created_at'):
        day = row['created_at'].date().isoformat()
        by_day[day] = by_day.get(day, 0) + 1

    code_status_distribution = {'active': total_active_codes, 'used': used_codes, 'expired': expired_codes}
    overview = {
        'total_ebooks': total_ebooks,
        'total_active_codes': total_active_codes,
        'used_codes': used_codes,
        'expired_codes': expired_codes,
        'downloads': {'daily': daily_downloads, 'weekly': weekly_downloads, 'all_time': total_downloads},
        'most_downloaded_ebook': top.title if top else None,
    }
    charts = {'downloads_over_time': by_day, 'top_ebooks': top_ebooks, 'code_status_distribution': code_status_distribution}

    if request.GET.get('format') == 'json':
        return JsonResponse({'overview': overview, 'charts': charts, 'recent_activity_feed': recent_activity})

    cfg = _system_setting()
    return render(
        request,
        'admin_dashboard.html',
        {
            'user_obj': user,
            'overview': overview,
            'top_ebooks': top_ebooks,
            'recent_activity': recent_activity,
            'downloads_over_time': sorted(by_day.items()),
            'code_status': code_status_distribution,
            'maintenance': cfg,
            'charts_json': json.dumps(charts),
        },
    )


@require_POST
def admin_toggle_maintenance(request):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    cfg = _system_setting()
    cfg.maintenance_mode = request.POST.get('maintenance_mode', 'false').lower() in ('1', 'true', 'yes')
    cfg.disable_downloads = request.POST.get('disable_downloads', 'false').lower() in ('1', 'true', 'yes')
    cfg.disable_code_entry = request.POST.get('disable_code_entry', 'false').lower() in ('1', 'true', 'yes')
    cfg.notification_message = request.POST.get('notification_message', '').strip()[:255]
    cfg.save()
    _log_security_event('maintenance_toggled', severity='warning', request=request, user=user, metadata={'maintenance_mode': cfg.maintenance_mode, 'disable_downloads': cfg.disable_downloads, 'disable_code_entry': cfg.disable_code_entry})
    return JsonResponse({'maintenance_mode': cfg.maintenance_mode, 'disable_downloads': cfg.disable_downloads, 'disable_code_entry': cfg.disable_code_entry, 'notification_message': cfg.notification_message})


@require_POST
def admin_trigger_backup(request):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    backup_type = request.POST.get('backup_type', 'full')[:30]
    rec = BackupRecord.objects.create(backup_type=backup_type, status='completed', location=f'backups/{timezone.now().strftime("%Y%m%d-%H%M%S")}-{backup_type}.tar.gz', triggered_by=user, completed_at=timezone.now())
    _log_security_event('backup_triggered', request=request, user=user, metadata={'backup_type': backup_type, 'record_id': rec.id})
    return JsonResponse({'backup_id': rec.id, 'status': rec.status, 'location': rec.location})


@require_POST
def admin_run_cleanup(request):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    now = timezone.now()
    expired_codes = AccessCode.objects.filter(expires_at__lte=now, is_active=True).update(is_active=False)
    retention_days = int(request.POST.get('retention_days', settings.LOG_RETENTION_DAYS))
    cutoff = now - timezone.timedelta(days=retention_days)
    pruned_security = SecurityEventLog.objects.filter(created_at__lt=cutoff).delete()[0]
    pruned_errors = SystemErrorLog.objects.filter(created_at__lt=cutoff).delete()[0]
    pruned_failed_attempts = FailedCodeAttempt.objects.filter(created_at__lt=cutoff).delete()[0]
    _log_security_event('cleanup_run', request=request, user=user, metadata={'expired_codes_deactivated': expired_codes, 'retention_days': retention_days})
    return JsonResponse({'expired_codes_deactivated': expired_codes, 'pruned_security_logs': pruned_security, 'pruned_error_logs': pruned_errors, 'pruned_failed_code_attempts': pruned_failed_attempts})


@require_GET
def admin_exports(request):
    user = _auth_user(request)
    if not user or user.role != User.Role.ADMIN:
        return HttpResponseForbidden('Admin required')
    export_type = request.GET.get('type', 'downloads')
    rows = []
    header = []
    if export_type == 'downloads':
        header = ['user_email', 'ebook_title', 'version_label', 'downloaded_at', 'code_id']
        for h in DownloadHistory.objects.select_related('user', 'ebook').order_by('-downloaded_at')[:5000]:
            rows.append([h.user.email, h.ebook.title, h.version_label, h.downloaded_at.isoformat(), h.code_id or ''])
    elif export_type == 'code_usage':
        header = ['code', 'user_email', 'used_at', 'download_completed']
        for c in CodeUsageLog.objects.select_related('code', 'user').order_by('-used_at')[:5000]:
            rows.append([c.code.code_value, c.user.email if c.user else '', c.used_at.isoformat(), str(c.download_completed)])
    else:
        header = ['event_type', 'severity', 'ip_address', 'created_at']
        for e in SecurityEventLog.objects.order_by('-created_at')[:5000]:
            rows.append([e.event_type, e.severity, e.ip_address or '', e.created_at.isoformat()])

    content = ','.join(header) + '\n' + '\n'.join([','.join([str(v).replace(',', ' ') for v in r]) for r in rows])
    response = HttpResponse(content, content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{export_type}.csv"'
    return response


@require_GET
def categories(request):
    cache_key = 'categories:list'
    data = cache.get(cache_key)
    if data is None:
        data = [{'name': c.name, 'slug': c.slug} for c in Category.objects.all().order_by('name')]
        cache.set(cache_key, data, timeout=settings.CATEGORY_CACHE_TTL_SECONDS)
    return JsonResponse({'categories': data})
