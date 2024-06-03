from django.db import models
from protected_media.models import ProtectedFileField, ProtectedImageField
import uuid
from django.contrib.auth.models import User


class ImageLibraryCategory(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    slug = models.SlugField(null=True, blank=False, unique=True)
    user = models.ForeignKey(User, related_name='user_w_image_library_category',
                             on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        if self.user:
            return self.name + "(" + self.user.email + ")"
        return self.name


def image_library_upload_file(instance, filename):
    if instance.image_library_category:
        subfolder = str(instance.image_library_category.slug)
    else:
        subfolder = "common"
    filename = filename.lower()
    return "images/image_library/{subfolder}/{filename}".format(subfolder=subfolder, filename=filename)


class ImageLibrary(models.Model):
    title = models.CharField(max_length=255, null=True, blank=True)
    image = models.ImageField(
        upload_to=image_library_upload_file, null=True, blank=False)
    image_library_category = models.ForeignKey(
        ImageLibraryCategory, related_name='image_library_category_w_image_library', on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        if self.title:
            return "(" + self.title + ")" + self.image.url
        return self.image.url

# ==========================================================================


class DocumentLibraryCategory(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    slug = models.SlugField(null=True, blank=False, unique=True)
    user = models.ForeignKey(User, related_name='user_w_document_library_category',
                             on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        if self.user:
            return self.name + "(" + self.user.email + ")"
        return self.name


def document_library_upload_file(instance, filename):
    if instance.document_library_category:
        subfolder = str(instance.document_library_category.slug)
    else:
        subfolder = "common"
    filename = filename.lower()
    # filename = str(uuid.uuid4()) + ".mp4"
    return "documents/document_library/{subfolder}/{filename}".format(subfolder=subfolder, filename=filename)


class DocumentLibrary(models.Model):
    title = models.CharField(max_length=255, null=True, blank=True)
    document = models.FileField(
        upload_to=document_library_upload_file, null=True, blank=False)
    document_library_category = models.ForeignKey(
        DocumentLibraryCategory, related_name='document_library_category_w_document_library', on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        if self.title:
            return self.document.url + "(" + self.title + ")"
        return self.document.url

#


class DocumentLibraryCategoryHLSVideo(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    slug = models.SlugField(null=True, blank=False, unique=True)
    user = models.ForeignKey(User, related_name='user_w_document_library_category_hls_video',
                             on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        if self.user:
            return self.name + "(" + self.user.email + ")"
        return self.name


def document_library_upload_file_hls_video(instance, file_name):
    if instance.document_library_category_hls_video:
        subfolder = str(instance.document_library_category_hls_video.slug)
    else:
        subfolder = "common"
    file_name = file_name.lower()
    folder_name = instance.folder_name.lower()
    return "documents/document_library_hls_video/{subfolder}/{folder_name}/{file_name}".format(subfolder=subfolder, folder_name=folder_name, file_name=file_name)


class DocumentLibraryHLSVideo(models.Model):
    title = models.CharField(max_length=255, null=True, blank=True)
    document = models.FileField(
        upload_to=document_library_upload_file_hls_video, null=True, blank=False)
    document_library_category_hls_video = models.ForeignKey(
        DocumentLibraryCategoryHLSVideo, related_name='document_library_category_hls_video_w_document_library_hls_video', on_delete=models.SET_NULL, blank=True, null=True)
    file_type = models.CharField(max_length=18)
    size = models.CharField(null=True, blank=True, max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    file_name = models.CharField(null=True, blank=True, max_length=255)
    folder_name = models.CharField(null=True, blank=True, max_length=255)
    parent_id = models.IntegerField(default=0, null=True, blank=True)

    def __str__(self):
        if self.title:
            return self.folder_name + ", " + self.file_name + "(" + self.title + ")"
        return self.file_name

# ==============================================================


class ImageLibraryProtectedCategory(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    slug = models.SlugField(null=True, blank=False, unique=True)

    def __str__(self):
        return self.name


def image_library_upload_file_protected(instance, filename):
    if instance.image_library_category:
        subfolder = str(instance.image_library_category.slug)
    else:
        subfolder = "common"
    filename = filename.lower()
    return "images/image_library/{subfolder}/{filename}".format(subfolder=subfolder, filename=filename)


class ImageLibraryProtected(models.Model):
    title = models.CharField(max_length=255, null=True, blank=True)
    image = ProtectedImageField(
        upload_to=image_library_upload_file_protected, null=True, blank=False)
    image_library_category = models.ForeignKey(
        ImageLibraryProtectedCategory, related_name='image_library_protected_category_w_image_library', on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        return self.image.url
