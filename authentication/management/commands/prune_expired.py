"""Housekeeping: expire OAuth tokens and stale browser sessions.

Schedule this daily (Render cron job, a scheduled task, or a one-off shell)::

    python manage.py prune_expired

It runs the three cleanups that keep the auth database from growing without
bound:

* ``cleartokens`` -- deletes expired OAuth access/refresh tokens
* ``clearsessions`` -- deletes expired Django session rows
* session inventory -- marks rows revoked where the browser session is gone

Nothing here is security critical; a token that is expired is already
unusable. It is purely to stop the tables from growing forever.
"""

from django.core.management import call_command
from django.core.management.base import BaseCommand

from authentication.sessions import prune_stale_sessions


class Command(BaseCommand):
    help = "Delete expired OAuth tokens and stale session records."

    def add_arguments(self, parser):
        parser.add_argument(
            "--skip-tokens",
            action="store_true",
            help="Do not run cleartokens.",
        )
        parser.add_argument(
            "--skip-sessions",
            action="store_true",
            help="Do not run clearsessions.",
        )

    def handle(self, *args, **options):
        if not options["skip_tokens"]:
            self.stdout.write("Clearing expired OAuth tokens...")
            call_command("cleartokens", verbosity=1)

        if not options["skip_sessions"]:
            self.stdout.write("Clearing expired browser sessions...")
            call_command("clearsessions", verbosity=1)

        pruned = prune_stale_sessions()
        self.stdout.write(
            self.style.SUCCESS(
                f"Marked {pruned} stale session inventor"
                f"{'y' if pruned == 1 else 'ies'} as revoked."
            )
        )
