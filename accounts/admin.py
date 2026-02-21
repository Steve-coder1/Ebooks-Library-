from django.contrib import admin

from .models import AdminAuditLog, PasswordResetToken, User, UserSession

admin.site.register(User)
admin.site.register(PasswordResetToken)
admin.site.register(UserSession)
admin.site.register(AdminAuditLog)
