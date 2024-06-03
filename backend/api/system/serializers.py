from rest_framework import serializers
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils.text import slugify
from unidecode import unidecode
from api.models import *


class ImageLibraryCategorySerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=False)
    image_library_category_id = serializers.IntegerField(required=False)

    class Meta:
        model = ImageLibraryCategory
        fields = '__all__'

    def slug_validate(self, request):
        name = self.validated_data['name']
        slug = slugify(unidecode(name))
        filterExist = ImageLibraryCategory.objects.filter(slug=slug)
        if len(filterExist) > 0:
            return False
        return True

    def save(self, request):
        try:
            name = self.validated_data['name']
            slug = slugify(unidecode(name))
            return ImageLibraryCategory.objects.create(name=name, slug=slug, user_id=request.user.id)
        except Exception as error:
            print("ImageLibraryCategorySerializer_save_error: ", error)
            return None

    def update(self, request):
        try:
            image_library_category_id = self.validated_data['image_library_category_id']
            name = self.validated_data['name']
            slug = slugify(unidecode(name))
            category = ImageLibraryCategory.objects.get(
                pk=image_library_category_id)
            category.name = name
            category.slug = slug
            category.save()
            return category
        except Exception as error:
            print("ImageLibraryCategorySerializer_update_error: ", error)
            return None

    def delete(self, request):
        try:
            model = ImageLibraryCategory.objects.get(
                pk=self.validated_data['image_library_category_id'])
            model.delete()
            return True
        except Exception as error:
            print("ImageLibraryCategorySerializer_delete_error: ", error)
            return False


class ImageLibrarySerializer(serializers.ModelSerializer):
    image_id = serializers.IntegerField(required=False)

    class Meta:
        model = ImageLibrary
        fields = '__all__'
        extra_fields = ['image_id']

    def delete(self, request, image_id):
        try:
            model = ImageLibrary.objects.get(
                pk=image_id)
            model.delete()
            if model.image.storage.exists(model.image.name):
                model.image.storage.delete(model.image.name)
            return True
        except Exception as error:
            print("ImageLibrarySerializer_delete_error: ", error)
            return False

    def update(self, request):
        try:
            image_id = self.validated_data['image_id']
            title = self.validated_data['title']
            model = ImageLibrary.objects.get(pk=image_id)
            model.title = title
            model.save()
            return model
        except Exception as error:
            print("ImageLibrarySerializer_update_error: ", error)
            return None


class UploadImageLibrarySerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=True)
    image_library_category_id = serializers.IntegerField()

    class Meta:
        model = ImageLibrary
        fields = [
            'image', 'image_library_category_id'
        ]

# =============================


class ImageLibraryProtectedCategorySerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=False)
    image_library_category_id = serializers.IntegerField(required=False)

    class Meta:
        model = ImageLibraryProtectedCategory
        fields = '__all__'

    def slug_validate(self, request):
        name = self.validated_data['name']
        slug = slugify(unidecode(name))
        filterExist = ImageLibraryProtectedCategory.objects.filter(slug=slug)
        if len(filterExist) > 0:
            return False
        return True

    def save(self, request):
        try:
            name = self.validated_data['name']
            slug = slugify(unidecode(name))
            return ImageLibraryProtectedCategory.objects.create(name=name, slug=slug)
        except Exception as error:
            print("ImageLibraryProtectedCategorySerializer_save_error: ", error)
            return None

    def update(self, request):
        try:
            image_library_category_id = self.validated_data['image_library_category_id']
            name = self.validated_data['name']
            slug = slugify(unidecode(name))
            category = ImageLibraryCategory.objects.get(
                pk=image_library_category_id)
            category.name = name
            category.slug = slug
            category.save()
            return category
        except Exception as error:
            print("ImageLibraryCategorySerializer_update_error: ", error)
            return None

    def delete(self, request):
        try:
            model = ImageLibraryProtectedCategory.objects.get(
                pk=self.validated_data['image_library_category_id'])
            model.delete()
            return True
        except Exception as error:
            print("ImageLibraryProtectedCategorySerializer_delete_error: ", error)
            return False


class ImageLibraryProtectedSerializer(serializers.ModelSerializer):
    image_id = serializers.IntegerField(required=False)

    class Meta:
        model = ImageLibraryProtected
        fields = '__all__'
        extra_fields = ['image_id']

    def delete(self, request, image_id):
        try:
            model = ImageLibraryProtected.objects.get(
                pk=image_id)
            model.delete()
            if model.image.storage.exists(model.image.name):
                model.image.storage.delete(model.image.name)
            return True
        except Exception as error:
            print("ImageLibraryProtectedSerializer_delete_error: ", error)
            return False

    def update(self, request):
        try:
            image_id = self.validated_data['image_id']
            title = self.validated_data['title']
            model = ImageLibraryProtected.objects.get(pk=image_id)
            model.title = title
            model.save()
            return model
        except Exception as error:
            print("ImageLibraryProtectedSerializer_update_error: ", error)
            return None


class UploadImageLibraryProtectedSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=True)
    image_library_category_id = serializers.IntegerField()

    class Meta:
        model = ImageLibraryProtected
        fields = [
            'image', 'image_library_category_id'
        ]

# =============================


class DocumentLibraryCategorySerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=False)
    document_library_category_id = serializers.IntegerField(required=False)

    class Meta:
        model = DocumentLibraryCategory
        fields = '__all__'

    def slug_validate(self, request):
        name = self.validated_data['name']
        slug = slugify(unidecode(name))
        filterExist = DocumentLibraryCategory.objects.filter(slug=slug)
        if len(filterExist) > 0:
            return False
        return True

    def save(self, request):
        try:
            name = self.validated_data['name']
            slug = slugify(unidecode(name))
            return DocumentLibraryCategory.objects.create(name=name, slug=slug, user_id=request.user.id)
        except Exception as error:
            print("DocumentLibraryCategorySerializer_save_error: ", error)
            return None

    def update(self, request):
        try:
            document_library_category_id = self.validated_data['document_library_category_id']
            name = self.validated_data['name']
            slug = slugify(unidecode(name))
            category = DocumentLibraryCategory.objects.get(
                pk=document_library_category_id)
            category.name = name
            category.slug = slug
            category.save()
            return category
        except Exception as error:
            print("DocumentLibraryCategorySerializer_update_error: ", error)
            return None

    def delete(self, request):
        try:
            model = DocumentLibraryCategory.objects.get(
                pk=self.validated_data['document_library_category_id'])
            model.delete()
            return True
        except Exception as error:
            print("DocumentLibraryCategorySerializer_delete_error: ", error)
            return False


class DocumentLibrarySerializer(serializers.ModelSerializer):
    document_id = serializers.IntegerField(required=False)

    class Meta:
        model = DocumentLibrary
        fields = '__all__'
        extra_fields = ['document_id']

    def delete(self, request, document_id):
        try:
            model = DocumentLibrary.objects.get(
                pk=document_id)
            model.delete()
            if model.document.storage.exists(model.document.name):
                model.document.storage.delete(model.document.name)
            return True
        except Exception as error:
            print("DocumentLibrarySerializer_delete_error: ", error)
            return False

    def update(self, request):
        try:
            document_id = self.validated_data['document_id']
            title = self.validated_data['title']
            model = DocumentLibrary.objects.get(pk=document_id)
            model.title = title
            model.save()
            return model
        except Exception as error:
            print("DocumentLibrarySerializer_update_error: ", error)
            return None


class UploadDocumentLibrarySerializer(serializers.ModelSerializer):
    document = serializers.FileField(required=True)
    document_library_category_id = serializers.IntegerField()

    class Meta:
        model = DocumentLibrary
        fields = [
            'document', 'document_library_category_id'
        ]

# HLS VIDEO


class DocumentLibraryCategoryHLSVideoSerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=False)
    document_library_category_id = serializers.IntegerField(required=False)

    class Meta:
        model = DocumentLibraryCategoryHLSVideo
        fields = '__all__'

    def slug_validate(self, request):
        name = self.validated_data['name']
        slug = slugify(unidecode(name))
        filterExist = DocumentLibraryCategoryHLSVideo.objects.filter(slug=slug)
        if len(filterExist) > 0:
            return False
        return True

    def save(self, request):
        try:
            name = self.validated_data['name']
            slug = slugify(unidecode(name))
            return DocumentLibraryCategoryHLSVideo.objects.create(name=name, slug=slug, user_id=request.user.id)
        except Exception as error:
            print("DocumentLibraryCategoryHLSVideoSerializer_save_error: ", error)
            return None

    def update(self, request):
        try:
            document_library_category_hls_video = self.validated_data[
                'document_library_category_hls_video']
            name = self.validated_data['name']
            slug = slugify(unidecode(name))
            category = DocumentLibraryCategoryHLSVideo.objects.get(
                pk=document_library_category_hls_video)
            category.name = name
            category.slug = slug
            category.save()
            return category
        except Exception as error:
            print("DocumentLibraryCategoryHLSVideoSerializer_update_error: ", error)
            return None

    def delete(self, request):
        try:
            model = DocumentLibraryCategoryHLSVideo.objects.get(
                pk=self.validated_data['document_library_category_hls_video'])
            model.delete()
            return True
        except Exception as error:
            print("DocumentLibraryCategoryHLSVideoSerializer_delete_error: ", error)
            return False


class DocumentLibraryHLSVideoBasicSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentLibraryHLSVideo
        fields = ['document', 'file_name']


class DocumentLibraryHLSVideoSerializer(serializers.ModelSerializer):
    document_id = serializers.IntegerField(required=False)
    file_type = serializers.CharField(required=False)
    ts_children = serializers.SerializerMethodField(
        method_name="get_all_ts_children_of_m3u8")

    class Meta:
        model = DocumentLibraryHLSVideo
        fields = '__all__'
        extra_fields = ['document_id']

    def get_all_ts_children_of_m3u8(self, instance):
        queryset = DocumentLibraryHLSVideo.objects.filter(
            parent_id=instance.id, file_type="ts")
        return DocumentLibraryHLSVideoBasicSerializer(queryset,
                                                      many=True).data

    def delete(self, request, document_id):
        try:
            model = DocumentLibraryHLSVideo.objects.get(
                pk=document_id)
            parent_id = model.id
            model.delete()
            if model.document.storage.exists(model.document.name):
                model.document.storage.delete(model.document.name)
            #
            model_children = DocumentLibraryHLSVideo.objects.filter(
                parent_id=parent_id)
            for item in model_children:
                if item.document.storage.exists(item.document.name):
                    item.document.storage.delete(item.document.name)
            model_children.delete()
            return True
        except Exception as error:
            print("DocumentLibraryHLSVideoSerializer_delete_error: ", error)
            return False

    def update(self, request):
        try:
            document_id = self.validated_data['document_id']
            title = self.validated_data['title']
            model = DocumentLibraryHLSVideo.objects.get(pk=document_id)
            model.title = title
            model.save()
            return model
        except Exception as error:
            print("DocumentLibraryHLSVideoSerializer_update_error: ", error)
            return None


class UploadDocumentLibraryHLSVideoSerializer(serializers.ModelSerializer):
    files = serializers.ListField(child=serializers.FileField(required=True))
    infoFiles = serializers.ListField(
        child=serializers.CharField(required=False))
    file_type = serializers.CharField(required=False)
    document_library_category_hls_video_id = serializers.IntegerField(
        required=False)

    class Meta:
        model = DocumentLibraryHLSVideo
        fields = '__all__'
        extra_fields = [
            'files', 'infoFiles'
        ]

    def upload(self, request):
        try:
            files = self.validated_data['files']
            infoFiles = self.validated_data['infoFiles']
            count = 0
            document = None
            for item in files:
                # print("item.file: ", item)
                # print("item.info: ", infoFiles[count])
                infoItem = infoFiles[count]
                infoItem = infoItem.split(';')
                file_name = infoItem[0]
                file_type = infoItem[5]
                size = infoItem[2]
                folder_name = infoItem[6]
                document_library_category_hls_video_id = infoItem[7]
                if file_type == "m3u8":
                    document = DocumentLibraryHLSVideo.objects.create(document=item, file_name=file_name, file_type=file_type, size=size,
                                                                      folder_name=folder_name, document_library_category_hls_video_id=document_library_category_hls_video_id)
                elif file_type == "ts" and document != None:
                    parent_id = int(document.id)
                    DocumentLibraryHLSVideo.objects.create(document=item, file_name=file_name, file_type=file_type, size=size, folder_name=folder_name,
                                                           document_library_category_hls_video_id=document_library_category_hls_video_id, parent_id=parent_id)
                count += 1
            return True
        except Exception as e:
            print("Error", e)
            # exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            # fpath = os.path.split(exc_tb.tb_frame.f_code.co_filename)[0]
            # print('ERROR', exc_type, fpath, fname, 'on line', exc_tb.tb_lineno)
            return False
