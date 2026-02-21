import random

from django.conf import settings
from django.core.cache import cache


def get_client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def generate_captcha(request):
    a, b = random.randint(1, 9), random.randint(1, 9)
    request.session['captcha_answer'] = a + b
    return f'{a} + {b} = ?'


def is_login_rate_limited(identifier):
    lock_key = f'login-lock:{identifier}'
    if cache.get(lock_key):
        return True
    return False


def register_login_failure(identifier):
    attempts_key = f'login-attempts:{identifier}'
    lock_key = f'login-lock:{identifier}'
    attempts = cache.get(attempts_key, 0) + 1
    cache.set(attempts_key, attempts, timeout=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS)
    if attempts >= settings.LOGIN_RATE_LIMIT_ATTEMPTS:
        cache.set(lock_key, True, timeout=settings.LOGIN_RATE_LIMIT_LOCK_SECONDS)


def clear_login_failures(identifier):
    cache.delete(f'login-attempts:{identifier}')
    cache.delete(f'login-lock:{identifier}')



def log_security_event(event_type, *, ip_address='', metadata=None):
    try:
        from library.models import SecurityEventLog

        SecurityEventLog.objects.create(
            event_type=event_type,
            severity='warning',
            ip_address=ip_address or None,
            metadata=metadata or {},
        )
    except Exception:
        return


def is_password_reset_rate_limited(identifier):
    return bool(cache.get(f'pwreset-lock:{identifier}'))


def register_password_reset_attempt(identifier):
    attempts_key = f'pwreset-attempts:{identifier}'
    lock_key = f'pwreset-lock:{identifier}'
    attempts = cache.get(attempts_key, 0) + 1
    cache.set(attempts_key, attempts, timeout=settings.PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS)
    if attempts >= settings.PASSWORD_RESET_RATE_LIMIT_ATTEMPTS:
        cache.set(lock_key, True, timeout=settings.PASSWORD_RESET_RATE_LIMIT_LOCK_SECONDS)


def clear_password_reset_attempts(identifier):
    cache.delete(f'pwreset-attempts:{identifier}')
    cache.delete(f'pwreset-lock:{identifier}')
