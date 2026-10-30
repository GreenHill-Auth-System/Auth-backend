from django.db import models


class AllowedEmail(models.Model):
    """
    An email address that is allowed to sign in, with the role it holds
    and the projects (systems) it may open. Managed in Django admin.
    """

    class Role(models.TextChoices):
        CEO = "CEO", "CEO"
        MANAGER = "Manager", "Manager"
        STAFF = "Staff", "Staff"

    class System(models.TextChoices):
        EID = "EID", "EID"
        PROCUREMENT = "Procurement", "Procurement (PMS)"
        INCIDENT = "Incident Service Management", "Incident Service Management (ISMP)"

    email = models.EmailField(unique=True)
    role = models.CharField(
        max_length=50,
        choices=Role.choices,
        default=Role.STAFF,
    )
    # Stored as a list of System values, e.g. ["EID", "Procurement"]
    authorized_systems = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["email"]

    def save(self, *args, **kwargs):
        self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.email} ({self.role})"
class AuthEvent(models.Model):
    EVENT_CHOICES = [
        ("login_ok", "Login succeeded"),
        ("login_fail", "Login failed"),
        ("logout", "Logout"),
    ]
    event = models.CharField(max_length=20, choices=EVENT_CHOICES)
    username = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
