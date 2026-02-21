from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import UserSession


class TokenSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw_token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip() or request.COOKIES.get('session_token')
        request.authenticated_session = None
        if raw_token:
            digest = UserSession.digest_token(raw_token)
            session = UserSession.objects.filter(session_token=digest).select_related('user').first()
            if session and session.expires_at > timezone.now():
                request.user = session.user
                request.authenticated_session = session
                session.expires_at = timezone.now() + timedelta(seconds=settings.TOKEN_SESSION_IDLE_TIMEOUT_SECONDS)
                session.save(update_fields=['expires_at'])
        response = self.get_response(request)
        return response
