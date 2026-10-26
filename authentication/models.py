from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    is_super_admin = models.BooleanField(default=False)
    can_access_ismp = models.BooleanField(default=False)
    can_access_procurement = models.BooleanField(default=False)
    can_access_executive = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.email} Profile"
    

# Create your models here.

class ImportedCampEmail(models.Model):
    email = models.EmailField(unique=True)
    camp_name = models.CharField(max_length=100)
    imported_at = models.DateTimeField(auto_now_add=True)
    is_provisioned = models.BooleanField(default=False)

    def __str__(self):
        return self.email
