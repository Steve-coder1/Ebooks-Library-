import random
from pathlib import Path

from django.conf import settings
from django.core import signing
from django.core.cache import cache


def storage_root() -> Path:
    return Path(settings.EBOOK_STORAGE_ROOT).resolve()


def safe_storage_path(stored_path: str) -> Path:
    candidate = (storage_root() / stored_path).resolve()
    if not str(candidate).startswith(str(storage_root())):
        raise ValueError('Invalid storage path')
    return candidate


def make_download_token(file_id: int, user_id: int | None):
    payload = {'file_id': file_id, 'user_id': user_id}
    return signing.TimestampSigner(salt='ebook-download').sign_object(payload)


def read_download_token(token: str, max_age_seconds: int):
    return signing.TimestampSigner(salt='ebook-download').unsign_object(token, max_age=max_age_seconds)


def make_code_session_token(session_id: int, code_id: int, ebook_id: int, user_id: int | None, usage_log_id: int):
    payload = {
        'session_id': session_id,
        'code_id': code_id,
        'ebook_id': ebook_id,
        'user_id': user_id,
        'usage_log_id': usage_log_id,
    }
    return signing.TimestampSigner(salt='code-session').sign_object(payload)


def read_code_session_token(token: str, max_age_seconds: int):
    return signing.TimestampSigner(salt='code-session').unsign_object(token, max_age=max_age_seconds)


def make_file_link_token(session_id: int, file_id: int):
    payload = {'session_id': session_id, 'file_id': file_id}
    return signing.TimestampSigner(salt='file-link').sign_object(payload)


def read_file_link_token(token: str, max_age_seconds: int):
    return signing.TimestampSigner(salt='file-link').unsign_object(token, max_age=max_age_seconds)


def _rate_key(ip: str, session_key: str):
    return f'code-rate:{ip}:{session_key}'


def register_code_failure(ip: str, session_key: str):
    key = _rate_key(ip, session_key)
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, timeout=settings.CODE_RATE_LIMIT_WINDOW_SECONDS)
    if attempts >= settings.CODE_RATE_LIMIT_ATTEMPTS:
        cache.set(f'code-lock:{ip}:{session_key}', True, timeout=settings.CODE_RATE_LIMIT_LOCK_SECONDS)
    return attempts


def clear_code_failures(ip: str, session_key: str):
    cache.delete(_rate_key(ip, session_key))
    cache.delete(f'code-lock:{ip}:{session_key}')


def is_code_locked(ip: str, session_key: str):
    return bool(cache.get(f'code-lock:{ip}:{session_key}'))


def needs_code_captcha(ip: str, session_key: str):
    attempts = cache.get(_rate_key(ip, session_key), 0)
    return attempts >= settings.CODE_CAPTCHA_TRIGGER_ATTEMPTS


def issue_code_captcha(request):
    a, b = random.randint(1, 9), random.randint(1, 9)
    request.session['code_captcha_answer'] = a + b
    return f'{a} + {b} = ?'
