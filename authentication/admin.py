from django.contrib import admin

from .models import AllowedEmail


@admin.register(AllowedEmail)
class AllowedEmailAdmin(admin.ModelAdmin):
    list_display = ("email", "role", "authorized_systems", "is_active")
    list_filter = ("role", "is_active")
    search_fields = ("email",)