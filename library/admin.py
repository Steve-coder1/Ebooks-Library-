from django.contrib import admin

from .models import (
    AccessCode,
    Category,
    CodeUsageLog,
    DownloadHistory,
    DownloadSession,
    Ebook,
    EbookDownload,
    EbookFile,
    Tag,
    SearchQueryLog,
    SecurityEventLog,
    SystemErrorLog,
    BackupRecord,
    SystemSetting,
    FailedCodeAttempt,
    Favorite,
    FileDownloadAttempt,
    Review,
    ReviewAbuseLog,
)


class EbookFileInline(admin.TabularInline):
    model = EbookFile
    extra = 1


@admin.register(Ebook)
class EbookAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'author', 'category', 'average_rating', 'download_count', 'is_featured', 'is_active', 'updated_at')
    list_filter = ('is_featured', 'is_active', 'category')
    search_fields = ('title', 'author', 'description', 'keywords', 'meta_title', 'meta_description')
    inlines = [EbookFileInline]


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'created_at')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Favorite)
class FavoriteAdmin(admin.ModelAdmin):
    list_display = ('user', 'ebook', 'created_at')


@admin.register(EbookDownload)
class EbookDownloadAdmin(admin.ModelAdmin):
    list_display = ('ebook_file', 'user', 'ip_address', 'created_at')
    list_filter = ('created_at',)


@admin.register(AccessCode)
class AccessCodeAdmin(admin.ModelAdmin):
    list_display = ('code_value', 'ebook', 'is_used', 'is_active', 'expires_at', 'created_by_admin', 'created_at')
    list_filter = ('is_used', 'is_active', 'ebook', 'expires_at', 'created_at')
    search_fields = ('code_value', 'ebook__title')


@admin.register(CodeUsageLog)
class CodeUsageLogAdmin(admin.ModelAdmin):
    list_display = ('code', 'user', 'ip_address', 'used_at', 'download_completed')
    list_filter = ('download_completed', 'used_at', 'code__ebook')
    search_fields = ('code__code_value', 'code__ebook__title', 'ip_address')


@admin.register(FailedCodeAttempt)
class FailedCodeAttemptAdmin(admin.ModelAdmin):
    list_display = ('code_value', 'ip_address', 'session_key', 'reason', 'created_at')
    list_filter = ('reason', 'created_at')
    search_fields = ('code_value', 'ip_address', 'session_key')


@admin.register(DownloadSession)
class DownloadSessionAdmin(admin.ModelAdmin):
    list_display = ('id', 'code', 'ebook', 'user', 'ip_address', 'expires_at', 'is_active', 'created_at')
    list_filter = ('is_active', 'ebook', 'created_at', 'expires_at')


@admin.register(FileDownloadAttempt)
class FileDownloadAttemptAdmin(admin.ModelAdmin):
    list_display = ('session', 'ebook_file', 'ip_address', 'attempted_at', 'success', 'download_completed', 'error_reason')
    list_filter = ('success', 'download_completed', 'attempted_at')
    search_fields = ('ebook_file__file_name', 'ip_address', 'error_reason')


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ('id', 'ebook', 'user', 'rating', 'created_at', 'updated_at')
    list_filter = ('rating', 'created_at', 'ebook')
    search_fields = ('ebook__title', 'user__email', 'review_text')


@admin.register(ReviewAbuseLog)
class ReviewAbuseLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'ebook', 'ip_address', 'reason', 'created_at')
    list_filter = ('reason', 'created_at')
    search_fields = ('user__email', 'ebook__title', 'ip_address')


@admin.register(DownloadHistory)
class DownloadHistoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'ebook', 'code', 'version_label', 'downloaded_at')
    list_filter = ('downloaded_at', 'ebook')
    search_fields = ('user__email', 'ebook__title', 'version_label')


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug')
    search_fields = ('name', 'slug')


@admin.register(SearchQueryLog)
class SearchQueryLogAdmin(admin.ModelAdmin):
    list_display = ('term', 'result_count', 'ip_address', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('term', 'ip_address')


@admin.register(SecurityEventLog)
class SecurityEventLogAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'severity', 'ip_address', 'user', 'created_at')
    list_filter = ('severity', 'event_type', 'created_at')
    search_fields = ('event_type', 'ip_address')


@admin.register(SystemErrorLog)
class SystemErrorLogAdmin(admin.ModelAdmin):
    list_display = ('source', 'message', 'created_at')
    list_filter = ('source', 'created_at')
    search_fields = ('source', 'message')


@admin.register(BackupRecord)
class BackupRecordAdmin(admin.ModelAdmin):
    list_display = ('backup_type', 'status', 'location', 'triggered_by', 'created_at', 'completed_at')
    list_filter = ('backup_type', 'status', 'created_at')


@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ('maintenance_mode', 'disable_downloads', 'disable_code_entry', 'updated_at')
