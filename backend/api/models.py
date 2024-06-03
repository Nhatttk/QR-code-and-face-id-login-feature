from django.db import models
from django.contrib.auth.models import User
from taggit.managers import TaggableManager

# from ckeditor_uploader.fields import RichTextUploadingField
from ckeditor.fields import RichTextField

from api.submodels.models_media import *

# Account ================================================================================

# # https://www.youtube.com/watch?v=Sc1KKe1Pguw
# def profile_upload_path(instance, filename):
#     return '/'.join(['folder', str(instance.phone), filename])

# PNG_TYPE_IMAGE = "PNG_TYPE_IMAGE"
# JPG_TYPE_IMAGE = "JPG_TYPE_IMAGE"
# JPEG_TYPE_IMAGE = "JPEG_TYPE_IMAGE"
# GIF_TYPE_IMAGE = "GIF_TYPE_IMAGE"
# MP4_TYPE_VIDEO = "MP4_TYPE_VIDEO"
# IMAGE_TYPE_CHOICES = [
#     (PNG_TYPE_IMAGE, 'PNG image type'),
#     (JPG_TYPE_IMAGE, 'JPG image type'),
#     (JPEG_TYPE_IMAGE, 'JPEG image type'),
#     (GIF_TYPE_IMAGE, 'GIP image type')
# ]
# VIDEO_TYPE_CHOICES = [
#     (MP4_TYPE_VIDEO, 'MP4 video type'),
# ]


class Profile(models.Model):
    user = models.OneToOneField(
        User, related_name='user_w_profile', on_delete=models.CASCADE, primary_key=True)
    address = models.CharField(max_length=100, null=True)
    birthday = models.DateField(null=True)
    gender = models.BooleanField(default=True)
    phone = models.CharField(max_length=50, null=True)
    facebook = models.URLField(null=True, blank=True)
    youtube = models.URLField(null=True, blank=True)
    twitter = models.URLField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    avatar = models.ImageField(upload_to='images/avatars/',
                               default='images/avatars/avatar_default.png', null=True, blank=True)
    is_mentor = models.BooleanField(default=False)
    is_school_admin = models.BooleanField(default=False)
    is_algorithm_mentor = models.BooleanField(default=False)
    count_change_password = models.IntegerField(default=0)
    is_sub_mentor = models.BooleanField(default=False)

    class Meta:
        ordering = ('user',)

    def __str__(self):
        return self.user.email + "(Edu Mentor: " + str(self.is_mentor) + ", Leader Support: " + str(self.is_sub_mentor) + ", Algorithm Mentor: " + str(self.is_algorithm_mentor) + ")"
        # if self.is_algorithm_mentor:
        #     return self.user.email + "(Algorithm Mentor)"
        # if self.is_school_admin:
        #     return self.user.email + "(School Admin)"
        # if self.is_mentor:
        #     return self.user.email + "(Edu Mentor)"


class SessionToken(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, primary_key=True)
    token = models.CharField(max_length=500, null=True, blank=False)
    hostname = models.CharField(max_length=100, null=True, blank=True)
    ip_address = models.CharField(max_length=100, null=True, blank=True)
    mac_address = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)


class HistoryLog(models.Model):
    user = models.ForeignKey(User, related_name='user_w_history_log',
                             on_delete=models.SET_NULL, blank=False, null=True)
    hostname = models.CharField(max_length=100, null=True, blank=True)
    ip_address = models.CharField(max_length=100, null=True, blank=True)
    mac_address = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    browser = models.CharField(max_length=100, null=True, blank=True)
    device = models.CharField(max_length=100, null=True, blank=True)

# ==============================================================================


class Setting(models.Model):
    is_lock_login = models.BooleanField(default=False)

    def __str__(self):
        return "Lock Login: " + str(self.is_lock_login)
