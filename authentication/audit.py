from .models import AuthEvent


def log_event(request, event, username=""):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    ip = forwarded.split(",")[0].strip() or request.META.get("REMOTE_ADDR")
    AuthEvent.objects.create(
        event=event,
        username=(username or "")[:255],
        ip_address=ip or None,
    )
