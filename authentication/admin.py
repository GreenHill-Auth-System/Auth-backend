from django.contrib import admin

from .models import AllowedEmail, GoogleIdentity, UserSession


@admin.register(AllowedEmail)
class AllowedEmailAdmin(admin.ModelAdmin):
    list_display = ("email", "role", "authorized_systems", "is_active")
    list_filter = ("role", "is_active")
    search_fields = ("email",)


@admin.register(GoogleIdentity)
class GoogleIdentityAdmin(admin.ModelAdmin):
    list_display = (
        "google_email",
        "user",
        "hosted_domain",
        "email_verified",
        "updated_at",
    )
    list_filter = ("email_verified", "hosted_domain")
    search_fields = ("google_email", "google_sub", "user__username")
    readonly_fields = ("created_at", "updated_at")


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Read-mostly view of who is signed in where.

    To actually sign a browser out, use the session manager endpoints (they
    delete the underlying session row). Marking a row revoked here is
    bookkeeping only and does not invalidate a cookie on its own.
    """

    list_display = (
        "user",
        "ip_address",
        "short_user_agent",
        "created_at",
        "last_seen_at",
        "is_active",
    )
    list_filter = ("revoked_at",)
    search_fields = ("user__username", "user__email", "ip_address")
    readonly_fields = ("created_at", "last_seen_at")

    @admin.display(description="Active")
    def is_active(self, obj):
        return obj.revoked_at is None

    @admin.display(description="User agent")
    def short_user_agent(self, obj):
        return (obj.user_agent or "")[:60]