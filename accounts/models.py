import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', User.Role.ADMIN)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    class Role(models.TextChoices):
        USER = 'user', 'User'
        ADMIN = 'admin', 'Admin'

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.USER)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class PasswordResetToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reset_tokens')
    token = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField()

    @classmethod
    def issue_for_user(cls, user):
        token = secrets.token_urlsafe(48)
        expires_at = timezone.now() + timedelta(seconds=settings.PASSWORD_RESET_TOKEN_TTL_SECONDS)
        return cls.objects.create(user=user, token=token, expires_at=expires_at)


class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user_sessions')
    session_token = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField()
    device_info = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    @classmethod
    def create_session(cls, user, *, ip_address='', device_info=''):
        raw_token = secrets.token_urlsafe(48)
        token_digest = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = timezone.now() + timedelta(seconds=settings.TOKEN_SESSION_IDLE_TIMEOUT_SECONDS)
        session = cls.objects.create(
            user=user,
            session_token=token_digest,
            expires_at=expires_at,
            ip_address=ip_address or None,
            device_info=device_info[:255],
        )
        return raw_token, session

    @staticmethod
    def digest_token(raw_token):
        return hashlib.sha256(raw_token.encode()).hexdigest()


class AdminAuditLog(models.Model):
    admin_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    event = models.CharField(max_length=64)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
