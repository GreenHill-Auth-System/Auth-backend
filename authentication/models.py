from django.conf import settings
from django.db import models
from django.utils import timezone


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


class GoogleIdentity(models.Model):
    """The verified Google account behind a local user.

    Django's ``User.email`` is not unique, so it cannot on its own prove which
    Google account a person signed in with. ``google_sub`` (the OpenID Connect
    ``sub`` claim) is a stable, globally unique identifier for that Google
    account and never changes, unlike an email address.

    Keeping it here rather than adding a field to ``auth.User`` avoids a custom
    user model, which would require resetting the database.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="google_identity",
    )

    # OpenID Connect subject: stable, unique per Google account.
    google_sub = models.CharField(
        max_length=255,
        unique=True,
        help_text="Google's stable subject identifier for this account.",
    )

    # Google only asserts email ownership when this is True.
    email_verified = models.BooleanField(default=False)

    # Present for Google Workspace accounts; the verified hosted domain.
    hosted_domain = models.CharField(max_length=255, blank=True)

    # The email Google asserted at last sign-in. Kept separately from
    # User.email so a mismatch can be detected and audited.
    google_email = models.EmailField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]
        verbose_name_plural = "Google identities"

    def __str__(self):
        return f"{self.google_email or self.user_id} (sub={self.google_sub})"


class UserSession(models.Model):
    """A queryable index over Django's own session rows.

    Django already keeps one session row per signed-in browser, but it stores
    only an encoded blob: it cannot answer "which devices is this account
    signed in on, and how do I kill one of them?". This table is a thin,
    indexed pointer at those rows so the session manager can list and revoke
    them without decoding every session in the table.

    ``session_key`` mirrors ``django_session.session_key``. Revoking means
    deleting that row, which immediately invalidates the cookie the browser
    holds -- no waiting for expiry.

    Rows are *not* authoritative. If this table ever drifts, deleting the
    matching ``django_session`` row is still the thing that actually signs a
    browser out.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="auth_sessions",
    )

    session_key = models.CharField(
        max_length=64,
        unique=True,
        help_text="Mirrors the session key of the matching browser session.",
    )

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=400, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(default=timezone.now)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-last_seen_at"]
        indexes = [
            models.Index(
                fields=["user", "-last_seen_at"],
                name="auth_session_user_seen_idx",
            ),
        ]

    def __str__(self):
        return f"{self.user} @ {self.last_seen_at:%Y-%m-%d %H:%M}"

    @property
    def is_active(self):
        return self.revoked_at is None


class UserProfile(models.Model):
    """The parts of a person's profile that are not their identity.

    Name and email are *not* here. They live on ``auth.User`` and are asserted
    by Google at sign-in, so copying them into a second table would create two
    disagreeing answers to "what is my name?". The OIDC claims read
    ``auth.User`` directly, which is what makes every system show the same
    person.

    Only the avatar needs somewhere to live, because it has no home on
    ``auth.User``.

    It is stored as a data URL in a text column. That is deliberately simple:
    the alternative is a media root that has to survive a redeploy and be
    served from a second host, and this is a 2 MB avatar, not a document.
    ``MAX_AVATAR_BYTES`` bounds it so one person cannot fill the database.
    """

    # A data URL is roughly 4/3 the size of the image once base64-encoded.
    # 4 MB of text is therefore about a 3 MB image -- generous for a headshot
    # and still bounded.
    MAX_AVATAR_BYTES = 4 * 1024 * 1024

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="greenhill_profile",
    )

    avatar_data = models.TextField(
        blank=True,
        help_text=(
            "Data URL (data:image/png;base64,...) for the person's avatar. "
            "Empty means the frontend draws initials instead."
        ),
    )

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "user profile"
        verbose_name_plural = "user profiles"

    def __str__(self):
        return f"profile for {self.user}"

    @property
    def has_avatar(self):
        return bool(self.avatar_data)

    def set_avatar_data(self, value):
        """Store an avatar, refusing anything oversized or not an image.

        Validated here rather than in the view so every caller -- the API now,
        a management command or the admin later -- gets the same rules.
        """
        value = (value or "").strip()

        if not value:
            self.avatar_data = ""
            return

        if not value.startswith("data:image/"):
            raise ValueError("Avatar must be an image data URL.")

        if len(value) > self.MAX_AVATAR_BYTES:
            raise ValueError("Avatar is too large.")

        self.avatar_data = value


class UserSettings(models.Model):
    """Per-person preferences, shared by all three systems.

    These used to be written to ``localStorage`` in the auth frontend only.
    That cannot be shared: ``localStorage`` is scoped to one origin, so the
    same person's preferences on the auth app were invisible to EID, PMS and
    ISMP, and invisible again in a private window. Keeping them server-side
    is what makes "one account, three systems" true for settings as well as
    for identity.
    """

    class Appearance(models.TextChoices):
        LIGHT = "Light", "Light"
        DARK = "Dark", "Dark"
        SYSTEM = "System", "System"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="greenhill_settings",
    )

    in_app_notifications = models.BooleanField(default=True)
    email_notifications = models.BooleanField(default=True)
    browser_notifications = models.BooleanField(default=False)

    appearance = models.CharField(
        max_length=20,
        choices=Appearance.choices,
        default=Appearance.LIGHT,
    )
    time_zone = models.CharField(max_length=64, default="Africa / Kampala")
    reduce_motion = models.BooleanField(default=False)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "user settings"
        verbose_name_plural = "user settings"

    def __str__(self):
        return f"settings for {self.user}"
