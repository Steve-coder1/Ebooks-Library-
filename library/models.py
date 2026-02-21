import secrets
import string
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models import Avg
from django.utils import timezone
from django.utils.text import slugify


class Category(models.Model):
    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=140, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Ebook(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    description = models.TextField(blank=True)
    author = models.CharField(max_length=255)
    category = models.ForeignKey(Category, on_delete=models.PROTECT, related_name='ebooks')
    cover_image_path = models.CharField(max_length=400, blank=True)
    summary_text = models.TextField(blank=True)
    keywords = models.CharField(max_length=500, blank=True)
    meta_title = models.CharField(max_length=255, blank=True)
    meta_description = models.CharField(max_length=320, blank=True)
    sample_preview_path = models.CharField(max_length=400, blank=True)
    is_featured = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    download_count = models.PositiveIntegerField(default=0)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0)
    review_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class EbookFile(models.Model):
    ebook = models.ForeignKey(Ebook, on_delete=models.CASCADE, related_name='files')
    file_name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500)
    file_size = models.BigIntegerField()
    version_label = models.CharField(max_length=100, default='v1.0')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.ebook_id}:{self.file_name}'


class Favorite(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='favorites')
    ebook = models.ForeignKey(Ebook, on_delete=models.CASCADE, related_name='favorited_by')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'ebook')


class EbookDownload(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    ebook_file = models.ForeignKey(EbookFile, on_delete=models.CASCADE, related_name='downloads')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class AccessCode(models.Model):
    code_value = models.CharField(max_length=64, unique=True, db_index=True)
    ebook = models.ForeignKey(Ebook, on_delete=models.CASCADE, related_name='access_codes')
    is_used = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    created_by_admin = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_codes')

    @classmethod
    def generate_unique_code(cls, length=24):
        alphabet = string.ascii_letters + string.digits
        while True:
            value = ''.join(secrets.choice(alphabet) for _ in range(length))
            if not cls.objects.filter(code_value=value).exists():
                return value

    @classmethod
    def issue(cls, ebook, created_by_admin, expiry_minutes=60):
        return cls.objects.create(
            code_value=cls.generate_unique_code(),
            ebook=ebook,
            expires_at=timezone.now() + timedelta(minutes=expiry_minutes),
            created_by_admin=created_by_admin,
        )


class CodeUsageLog(models.Model):
    code = models.ForeignKey(AccessCode, on_delete=models.CASCADE, related_name='usage_logs')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.CharField(max_length=255, blank=True)
    used_at = models.DateTimeField(auto_now_add=True)
    download_completed = models.BooleanField(default=False)


class FailedCodeAttempt(models.Model):
    code_value = models.CharField(max_length=64, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    session_key = models.CharField(max_length=64, blank=True)
    reason = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)


class DownloadSession(models.Model):
    code = models.ForeignKey(AccessCode, on_delete=models.CASCADE, related_name='download_sessions')
    ebook = models.ForeignKey(Ebook, on_delete=models.CASCADE, related_name='download_sessions')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)


class FileDownloadAttempt(models.Model):
    session = models.ForeignKey(DownloadSession, on_delete=models.CASCADE, related_name='file_attempts')
    ebook_file = models.ForeignKey(EbookFile, on_delete=models.CASCADE, related_name='download_attempts')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    attempted_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    download_completed = models.BooleanField(default=False)
    error_reason = models.CharField(max_length=255, blank=True)


class Review(models.Model):
    ebook = models.ForeignKey(Ebook, on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reviews')
    rating = models.PositiveSmallIntegerField()
    review_text = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('ebook', 'user')

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self._refresh_ebook_aggregates()

    def delete(self, *args, **kwargs):
        ebook = self.ebook
        super().delete(*args, **kwargs)
        Review.refresh_ebook_aggregates(ebook)

    @staticmethod
    def refresh_ebook_aggregates(ebook):
        agg = Review.objects.filter(ebook=ebook).aggregate(avg=Avg('rating'), count=models.Count('id'))
        ebook.average_rating = agg['avg'] or 0
        ebook.review_count = agg['count'] or 0
        ebook.save(update_fields=['average_rating', 'review_count'])

    def _refresh_ebook_aggregates(self):
        Review.refresh_ebook_aggregates(self.ebook)


class ReviewAbuseLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    ebook = models.ForeignKey(Ebook, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    reason = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)



class DownloadHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='download_history')
    ebook = models.ForeignKey(Ebook, on_delete=models.CASCADE, related_name='download_history')
    code = models.ForeignKey(AccessCode, on_delete=models.SET_NULL, null=True, blank=True, related_name='download_history')
    downloaded_at = models.DateTimeField(auto_now_add=True)
    version_label = models.CharField(max_length=100)



class Tag(models.Model):
    name = models.CharField(max_length=80, unique=True)
    slug = models.SlugField(max_length=90, unique=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)


Ebook.add_to_class('tags', models.ManyToManyField(Tag, blank=True, related_name='ebooks'))


class SearchQueryLog(models.Model):
    term = models.CharField(max_length=255, db_index=True)
    result_count = models.PositiveIntegerField(default=0)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)



class SecurityEventLog(models.Model):
    event_type = models.CharField(max_length=80)
    severity = models.CharField(max_length=20, default='info')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class SystemErrorLog(models.Model):
    source = models.CharField(max_length=80)
    message = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class BackupRecord(models.Model):
    backup_type = models.CharField(max_length=30)
    status = models.CharField(max_length=30, default='queued')
    location = models.CharField(max_length=500, blank=True)
    triggered_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)


class SystemSetting(models.Model):
    maintenance_mode = models.BooleanField(default=False)
    disable_downloads = models.BooleanField(default=False)
    disable_code_entry = models.BooleanField(default=False)
    notification_message = models.CharField(max_length=255, blank=True)
    rate_limit_config = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
