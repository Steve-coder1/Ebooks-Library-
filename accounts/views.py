from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.paginator import Paginator
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .forms import (
    LoginForm,
    PasswordResetConfirmForm,
    PasswordResetRequestForm,
    ProfileUpdateForm,
    RegisterForm,
)
from .models import AdminAuditLog, PasswordResetToken, UserSession
from library.models import DownloadHistory, Favorite, Review

from .utils import (
    clear_login_failures,
    clear_password_reset_attempts,
    generate_captcha,
    get_client_ip,
    is_login_rate_limited,
    is_password_reset_rate_limited,
    log_security_event,
    register_login_failure,
    register_password_reset_attempt,
)

User = get_user_model()


def _identifier(request, email):
    return f"{get_client_ip(request)}:{email.lower()}"


@require_http_methods(["GET", "POST"])
def register(request):
    form = RegisterForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        user.password = make_password(form.cleaned_data['password'])
        user.role = User.Role.USER
        user.save()
        messages.success(request, 'Registration successful')
        return redirect('accounts:login')
    return render(request, 'accounts/register.html', {'form': form})


@require_http_methods(["GET", "POST"])
def login_view(request):
    captcha_prompt = generate_captcha(request)
    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        identifier = _identifier(request, email)
        if is_login_rate_limited(identifier):
            log_security_event('login_rate_limited', ip_address=get_client_ip(request), metadata={'identifier': identifier})
            messages.error(request, 'Too many attempts. Please try again later.')
            return render(request, 'accounts/login.html', {'form': form, 'captcha_prompt': captcha_prompt}, status=429)
        expected_captcha = request.session.get('captcha_answer')
        if form.cleaned_data['captcha_answer'] != expected_captcha:
            register_login_failure(identifier)
            log_security_event('login_captcha_failed', ip_address=get_client_ip(request), metadata={'identifier': identifier})
            messages.error(request, 'Invalid captcha')
            return render(request, 'accounts/login.html', {'form': form, 'captcha_prompt': captcha_prompt}, status=400)
        user = User.objects.filter(email__iexact=email).first()
        if not user or not user.check_password(form.cleaned_data['password']):
            register_login_failure(identifier)
            log_security_event('login_invalid_credentials', ip_address=get_client_ip(request), metadata={'identifier': identifier})
            messages.error(request, 'Invalid credentials')
            return render(request, 'accounts/login.html', {'form': form, 'captcha_prompt': captcha_prompt}, status=400)
        clear_login_failures(identifier)
        raw_token, _ = UserSession.create_session(
            user,
            ip_address=get_client_ip(request),
            device_info=request.META.get('HTTP_USER_AGENT', ''),
        )
        response = redirect('accounts:profile')
        response.set_cookie('session_token', raw_token, secure=True, httponly=True, samesite='Lax')
        return response
    return render(request, 'accounts/login.html', {'form': form, 'captcha_prompt': captcha_prompt})


@require_http_methods(["GET", "POST"])
def admin_login(request):
    captcha_prompt = generate_captcha(request)
    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        identifier = _identifier(request, f'admin:{email}')
        if is_login_rate_limited(identifier):
            log_security_event('admin_login_rate_limited', ip_address=get_client_ip(request), metadata={'identifier': identifier})
            return render(request, 'accounts/admin_login.html', {'form': form, 'captcha_prompt': captcha_prompt}, status=429)
        user = User.objects.filter(email__iexact=email, role=User.Role.ADMIN).first()
        expected_captcha = request.session.get('captcha_answer')
        if form.cleaned_data['captcha_answer'] != expected_captcha or not user or not user.check_password(form.cleaned_data['password']):
            register_login_failure(identifier)
            return render(request, 'accounts/admin_login.html', {'form': form, 'captcha_prompt': captcha_prompt}, status=400)
        clear_login_failures(identifier)
        raw_token, _ = UserSession.create_session(
            user,
            ip_address=get_client_ip(request),
            device_info=request.META.get('HTTP_USER_AGENT', ''),
        )
        AdminAuditLog.objects.create(
            admin_user=user,
            event='admin_login',
            ip_address=get_client_ip(request),
            metadata={'2fa_ready': True},
        )
        response = redirect('accounts:profile')
        response.set_cookie('session_token', raw_token, secure=True, httponly=True, samesite='Lax')
        return response
    return render(request, 'accounts/admin_login.html', {'form': form, 'captcha_prompt': captcha_prompt})


def _require_auth(request):
    if not getattr(request, 'authenticated_session', None):
        return None
    return request.authenticated_session.user


@require_http_methods(["POST"])
def logout_view(request):
    session = getattr(request, 'authenticated_session', None)
    if session:
        user = session.user
        if user.role == User.Role.ADMIN:
            AdminAuditLog.objects.create(admin_user=user, event='admin_logout', ip_address=get_client_ip(request))
        session.delete()
    response = redirect('accounts:login')
    response.delete_cookie('session_token')
    return response


@require_http_methods(["GET", "POST"])
def request_password_reset(request):
    form = PasswordResetRequestForm(request.POST or None)
    reset_token = None
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        identifier = f"{get_client_ip(request)}:{email.lower()}"
        if is_password_reset_rate_limited(identifier):
            log_security_event('password_reset_rate_limited', ip_address=get_client_ip(request), metadata={'identifier': identifier})
            return render(request, 'accounts/password_reset_request.html', {'form': form, 'reset_token': reset_token}, status=429)
        user = User.objects.filter(email__iexact=email).first()
        register_password_reset_attempt(identifier)
        if user:
            token_obj = PasswordResetToken.issue_for_user(user)
            reset_token = token_obj.token
            clear_password_reset_attempts(identifier)
        messages.success(request, 'If the account exists, a reset token has been generated.')
    return render(request, 'accounts/password_reset_request.html', {'form': form, 'reset_token': reset_token})


@require_http_methods(["GET", "POST"])
def confirm_password_reset(request):
    form = PasswordResetConfirmForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        token_obj = get_object_or_404(PasswordResetToken, token=form.cleaned_data['token'])
        if token_obj.expires_at < timezone.now():
            token_obj.delete()
            messages.error(request, 'Token expired')
            return render(request, 'accounts/password_reset_confirm.html', {'form': form}, status=400)
        user = token_obj.user
        user.set_password(form.cleaned_data['new_password'])
        user.save(update_fields=['password'])
        token_obj.delete()
        messages.success(request, 'Password reset complete')
        return redirect('accounts:login')
    return render(request, 'accounts/password_reset_confirm.html', {'form': form})


@require_http_methods(["GET", "POST"])
def profile(request):
    user = _require_auth(request)
    if not user:
        return HttpResponseForbidden('Authentication required')
    form = ProfileUpdateForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        if not user.check_password(form.cleaned_data['current_password']):
            form.add_error('current_password', 'Wrong password')
        else:
            new_email = form.cleaned_data.get('email')
            if new_email:
                user.email = new_email.lower()
            if form.cleaned_data.get('new_password'):
                user.set_password(form.cleaned_data['new_password'])
            user.save()
            messages.success(request, 'Profile updated')
            return redirect('accounts:profile')

    history_qs = DownloadHistory.objects.filter(user=user).select_related('ebook').order_by('-downloaded_at')
    favorites_qs = Favorite.objects.filter(user=user).select_related('ebook').order_by('-created_at')
    reviews_qs = Review.objects.filter(user=user).select_related('ebook').order_by('-updated_at')

    history_page = Paginator(history_qs, 8).get_page(request.GET.get('history_page', 1))
    favorites_page = Paginator(favorites_qs, 8).get_page(request.GET.get('favorites_page', 1))
    reviews_page = Paginator(reviews_qs, 8).get_page(request.GET.get('reviews_page', 1))

    return render(
        request,
        'accounts/profile.html',
        {
            'form': form,
            'user_obj': user,
            'history_page': history_page,
            'favorites_page': favorites_page,
            'reviews_page': reviews_page,
            'active_tab': request.GET.get('tab', 'history'),
        },
    )
