"""Password hashing parameters for GreenHill sign-in.

Django 6 defaults to PBKDF2-HMAC-SHA256 with 1,500,000 iterations. That is a
pure CPU loop and measured ~1.8 s per hash and ~1.9 s per verify on the
development machine, which means every single sign-in paid almost two seconds
before any database work happened. On a small cloud instance with a slower
core it is worse, and it is the largest avoidable part of "login is slow".

Argon2id is the algorithm OWASP recommends first. It is memory-hard (so it
resists GPU and ASIC cracking far better than PBKDF2 at the same wall-clock
cost) and its implementation runs in optimised native code, so we get a
*stronger* hash for roughly a tenth of the time.

Parameters below are 64 MiB of memory, 2 passes, single lane. That is well
above the OWASP Argon2id minimum (19 MiB, t=2, p=1) and it is deliberately
chosen over Django's own defaults (100 MiB, p=8) because each concurrent
sign-in reserves that much RAM: 100 MiB is risky on a small instance, and
8 lanes on a single-core box buys nothing.

Measured on the dev machine: hash ~390 ms, verify ~226 ms (PBKDF2 was ~1.9 s).

Existing passwords are untouched. `PASSWORD_HASHERS` keeps the PBKDF2 hashers
after this one, so an old `pbkdf2_sha256$...` value still verifies, and Django
silently re-hashes it with Argon2id the next time that person signs in.
"""

from django.contrib.auth.hashers import Argon2PasswordHasher


class GreenHillArgon2PasswordHasher(Argon2PasswordHasher):
    """Argon2id with memory/time parameters sized for a small instance."""

    # KiB. 65536 KiB == 64 MiB.
    memory_cost = 65536

    # Number of passes over the memory block.
    time_cost = 2

    # Lanes. One keeps usage predictable on a single-vCPU container.
    parallelism = 1
