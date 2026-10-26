from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from authentication.models import UserProfile

SUPER_ADMIN_EMAILS = ['refactory@greenhillacademy.ac.ug']

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        profile, _ = UserProfile.objects.get_or_create(user=instance)
        email = instance.email.lower()
        
        if email in [e.lower() for e in SUPER_ADMIN_EMAILS]:
            profile.is_super_admin = True
            profile.can_access_ismp = True
            profile.can_access_procurement = True
            profile.can_access_executive = True
            instance.is_superuser = True
            instance.is_staff = True
            instance.save()
        profile.save()
    else:
        instance.profile.save()