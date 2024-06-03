from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.models import Q, Count
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination
from django.forms.models import model_to_dict
import re
from rest_framework.parsers import MultiPartParser, FormParser

from api.models import *
from .serializers import *
from api import status_http


class ImageLibraryMVS(viewsets.ModelViewSet):
    serializer_class = ImageLibrarySerializer
    permission_classes = [IsAuthenticated]

    @action(methods=["GET"], detail=False, url_path="image_library_get_all_images_by_category_api", url_name="image_library_get_all_images_by_category_api")
    def image_library_get_all_images_by_category_api(self, request, *args, **kwargs):
        queryset = ImageLibrary.objects.filter(
            image_library_category_id=kwargs['category_id']).order_by('-id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["DELETE"], detail=False, url_path="image_library_delete_image_api", url_name="image_library_delete_image_api")
    def image_library_delete_image_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = {}
                result = serializer.delete(request, kwargs['image_id'])
                if result:
                    data['message'] = 'Delete successfully!'
                    return Response(data, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("ImageLibraryMVS_image_library_delete_image_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["PATCH"], detail=False, url_path="image_library_update_image_api", url_name="image_library_update_image_api")
    def image_library_update_image_api(self, request, *args, **kwargs):
        try:
            print("image_library_update_image_api: ", request.data)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                model = serializer.update(request)
                if model:
                    data = {}
                    data['message'] = 'Update successfully!'
                    return Response(data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("ImageLibraryMVS_image_library_update_image_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)


class ImageLibraryCategoryMVS(viewsets.ModelViewSet):
    serializer_class = ImageLibraryCategorySerializer
    permission_classes = [IsAuthenticated]

    @action(methods=["GET"], detail=False, url_path="image_library_category_get_all_api", url_name="image_library_category_get_all_api")
    def image_library_category_get_all_api(self, request, *args, **kwargs):
        queryset = ImageLibraryCategory.objects.filter(user_id=request.user.id).order_by('id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["POST"], detail=False, url_path="add_image_library_category_api", url_name="add_image_library_category_api")
    def add_image_library_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not serializer.slug_validate(request):
                    return Response(serializer.errors, status=status_http.HTTP_ME_456_SLUG_EXIST)
                model = serializer.save(request)
                if model:
                    data = {}
                    data['image_library_category_id'] = model.id
                    data['message'] = 'Add successfully!'
                    return Response(data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("ImageLibraryCategoryMVS_add_image_library_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["PATCH"], detail=False, url_path="edit_image_library_category_api", url_name="edit_image_library_category_api")
    def edit_image_library_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not serializer.slug_validate(request):
                    return Response(serializer.errors, status=status_http.HTTP_ME_456_SLUG_EXIST)
                model = serializer.update(request)
                if model:
                    data = {}
                    data['name'] = model.name
                    data['message'] = 'Add successfully!'
                    return Response(data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("ImageLibraryCategoryMVS_edit_image_library_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["DELETE"], detail=False, url_path="delete_image_library_category_api", url_name="delete_image_library_category_api")
    def delete_image_library_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = {}
                result = serializer.delete(request)
                if result:
                    data['message'] = 'Delete successfully!'
                    return Response(data, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print(
                "ImageLibraryCategoryMVS_delete_image_library_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)


class UploadImageLibraryMVS(viewsets.ModelViewSet):
    serializer_class = UploadImageLibrarySerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    @action(methods=["POST"], detail=False, url_path="upload_image_library_for_category_api", url_name="upload_image_library_for_category_api")
    def upload_image_library_for_category_api(self, request, *args, **kwargs):
        try:
            # print("upload_image_library_for_category_api: ", request.data)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("upload_image_library_for_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

# ====================================================

class ImageLibraryProtectedMVS(viewsets.ModelViewSet):
    serializer_class = ImageLibraryProtectedSerializer
    permission_classes = [IsAuthenticated]

    @action(methods=["GET"], detail=False, url_path="image_library_protected_get_all_images_by_category_api", url_name="image_library_protected_get_all_images_by_category_api")
    def image_library_protected_get_all_images_by_category_api(self, request, *args, **kwargs):
        queryset = ImageLibraryProtected.objects.filter(
            image_library_category_id=kwargs['category_id']).order_by('-id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["DELETE"], detail=False, url_path="image_library_protected_delete_image_api", url_name="image_library_protected_delete_image_api")
    def image_library_protected_delete_image_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = {}
                result = serializer.delete(request, kwargs['image_id'])
                if result:
                    data['message'] = 'Delete successfully!'
                    return Response(data, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("ImageLibraryProtectedMVS_image_library_protected_delete_image_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["PATCH"], detail=False, url_path="image_library_protected_update_image_api", url_name="image_library_protected_update_image_api")
    def image_library_protected_update_image_api(self, request, *args, **kwargs):
        try:
            print("image_library_protected_update_image_api: ", request.data)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                model = serializer.update(request)
                if model:
                    data = {}
                    data['message'] = 'Update successfully!'
                    return Response(data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("ImageLibraryProtectedMVS_image_library_protected_update_image_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)


class ImageLibraryProtectedCategoryMVS(viewsets.ModelViewSet):
    serializer_class = ImageLibraryProtectedCategorySerializer
    permission_classes = [IsAuthenticated]

    @action(methods=["GET"], detail=False, url_path="image_library_protected_category_get_all_api", url_name="image_library_protected_category_get_all_api")
    def image_library_protected_category_get_all_api(self, request, *args, **kwargs):
        queryset = ImageLibraryProtectedCategory.objects.order_by('id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["POST"], detail=False, url_path="add_image_library_protected_category_api", url_name="add_image_library_protected_category_api")
    def add_image_library_protected_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not serializer.slug_validate(request):
                    return Response(serializer.errors, status=status_http.HTTP_ME_456_SLUG_EXIST)
                model = serializer.save(request)
                if model:
                    data = {}
                    data['image_library_category_id'] = model.id
                    data['message'] = 'Add successfully!'
                    return Response(data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("ImageLibraryProtectedCategoryMVS_add_image_library_protected_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["PATCH"], detail=False, url_path="edit_image_library_protected_category_api", url_name="edit_image_library_protected_category_api")
    def edit_image_library_protected_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not serializer.slug_validate(request):
                    return Response(serializer.errors, status=status_http.HTTP_ME_456_SLUG_EXIST)
                model = serializer.update(request)
                if model:
                    data = {}
                    data['name'] = model.name
                    data['message'] = 'Add successfully!'
                    return Response(data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("ImageLibraryProtectedCategoryMVS_edit_image_library_protected_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["DELETE"], detail=False, url_path="delete_image_library_protected_category_api", url_name="delete_image_library_protected_category_api")
    def delete_image_library_protected_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = {}
                result = serializer.delete(request)
                if result:
                    data['message'] = 'Delete successfully!'
                    return Response(data, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print(
                "ImageLibraryProtectedCategoryMVS_delete_image_library_protected_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)


class UploadImageLibraryProtectedMVS(viewsets.ModelViewSet):
    serializer_class = UploadImageLibraryProtectedSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    @action(methods=["POST"], detail=False, url_path="upload_image_library_protected_for_category_api", url_name="upload_image_library_protected_for_category_api")
    def upload_image_library_protected_for_category_api(self, request, *args, **kwargs):
        try:
            # print("upload_image_library_protected_for_category_api: ", request.data)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("upload_image_library_protected_for_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)


# ====================================================

class DocumentLibraryMVS(viewsets.ModelViewSet):
    serializer_class = DocumentLibrarySerializer
    permission_classes = [IsAuthenticated]

    @action(methods=["GET"], detail=False, url_path="document_library_get_all_documents_by_category_api", url_name="document_library_get_all_documents_by_category_api")
    def document_library_get_all_documents_by_category_api(self, request, *args, **kwargs):
        queryset = DocumentLibrary.objects.filter(
            document_library_category_id=kwargs['category_id']).order_by('-id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["DELETE"], detail=False, url_path="document_library_delete_document_api", url_name="document_library_delete_document_api")
    def document_library_delete_document_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = {}
                result = serializer.delete(request, kwargs['document_id'])
                if result:
                    data['message'] = 'Delete successfully!'
                    return Response(data, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("DocumentLibraryMVS_document_library_delete_document_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["PATCH"], detail=False, url_path="document_library_update_document_api", url_name="document_library_update_document_api")
    def document_library_update_document_api(self, request, *args, **kwargs):
        try:
            # print("document_library_update_document_api: ", request.data)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                model = serializer.update(request)
                if model:
                    data = {}
                    data['message'] = 'Update successfully!'
                    return Response(data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("DocumentLibraryMVS_document_library_update_document_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

class DocumentLibraryCategoryMVS(viewsets.ModelViewSet):
    serializer_class = DocumentLibraryCategorySerializer
    permission_classes = [IsAuthenticated]

    @action(methods=["GET"], detail=False, url_path="document_library_category_get_all_api", url_name="document_library_category_get_all_api")
    def document_library_category_get_all_api(self, request, *args, **kwargs):
        queryset = DocumentLibraryCategory.objects.filter(user_id=request.user.id).order_by('id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["POST"], detail=False, url_path="add_document_library_category_api", url_name="add_document_library_category_api")
    def add_document_library_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not serializer.slug_validate(request):
                    return Response(serializer.errors, status=status_http.HTTP_ME_456_SLUG_EXIST)
                model = serializer.save(request)
                if model:
                    data = {}
                    data['document_library_category_id'] = model.id
                    data['message'] = 'Add successfully!'
                    return Response(data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("DocumentLibraryCategoryMVS_add_document_library_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["PATCH"], detail=False, url_path="edit_document_library_category_api", url_name="edit_document_library_category_api")
    def edit_document_library_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not serializer.slug_validate(request):
                    return Response(serializer.errors, status=status_http.HTTP_ME_456_SLUG_EXIST)
                model = serializer.update(request)
                if model:
                    data = {}
                    data['name'] = model.name
                    data['message'] = 'Add successfully!'
                    return Response(data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("DocumentLibraryCategoryMVS_edit_document_library_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["DELETE"], detail=False, url_path="delete_document_library_category_api", url_name="delete_document_library_category_api")
    def delete_document_library_category_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = {}
                result = serializer.delete(request)
                if result:
                    data['message'] = 'Delete successfully!'
                    return Response(data, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print(
                "DocumentLibraryCategoryMVS_delete_document_library_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

class UploadDocumentLibraryMVS(viewsets.ModelViewSet):
    serializer_class = UploadDocumentLibrarySerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    @action(methods=["POST"], detail=False, url_path="upload_document_library_for_category_api", url_name="upload_document_library_for_category_api")
    def upload_document_library_for_category_api(self, request, *args, **kwargs):
        try:
            # print("upload_document_library_for_category_api: ", request.data)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("upload_document_library_for_category_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

# HLS VIDEO

class DocumentLibraryHLSVideoMVS(viewsets.ModelViewSet):
    serializer_class = DocumentLibraryHLSVideoSerializer
    permission_classes = [IsAuthenticated]

    @action(methods=["GET"], detail=False, url_path="document_library_hls_video_get_all_documents_by_category_api", url_name="document_library_hls_video_get_all_documents_by_category_api")
    def document_library_hls_video_get_all_documents_by_category_api(self, request, *args, **kwargs):
        queryset = DocumentLibraryHLSVideo.objects.filter(
            document_library_category_hls_video_id=kwargs['category_id']).order_by('-id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["GET"], detail=False, url_path="document_library_hls_video_get_all_documents_by_category_and_m3u8_api", url_name="document_library_hls_video_get_all_documents_by_category_and_m3u8_api")
    def document_library_hls_video_get_all_documents_by_category_and_m3u8_api(self, request, *args, **kwargs):
        queryset = DocumentLibraryHLSVideo.objects.filter(
            document_library_category_hls_video_id=kwargs['category_id'], file_type="m3u8").order_by('-id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["DELETE"], detail=False, url_path="document_library_hls_video_delete_document_api", url_name="document_library_hls_video_delete_document_api")
    def document_library_hls_video_delete_document_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = {}
                result = serializer.delete(request, kwargs['document_id'])
                if result:
                    data['message'] = 'Delete successfully!'
                    return Response(data, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("DocumentLibraryHLSVideoMVS_document_library_hls_video_delete_document_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["PATCH"], detail=False, url_path="document_library_hls_video_update_document_api", url_name="document_library_hls_video_update_document_api")
    def document_library_hls_video_update_document_api(self, request, *args, **kwargs):
        try:
            # print("document_library_hls_video_update_document_api: ", request.data)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                model = serializer.update(request)
                if model:
                    data = {}
                    data['message'] = 'Update successfully!'
                    return Response(data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("DocumentLibraryHLSVideoMVS_document_library_hls_video_update_document_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

class DocumentLibraryCategoryHLSVideoMVS(viewsets.ModelViewSet):
    serializer_class = DocumentLibraryCategoryHLSVideoSerializer
    permission_classes = [IsAuthenticated]

    @action(methods=["GET"], detail=False, url_path="document_library_category_hls_video_get_all_api", url_name="document_library_category_hls_video_get_all_api")
    def document_library_category_hls_video_get_all_api(self, request, *args, **kwargs):
        queryset = DocumentLibraryCategoryHLSVideo.objects.filter(user_id=request.user.id).order_by('id')
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["POST"], detail=False, url_path="add_document_library_category_hls_video_api", url_name="add_document_library_category_hls_video_api")
    def add_document_library_category_hls_video_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not serializer.slug_validate(request):
                    return Response(serializer.errors, status=status_http.HTTP_ME_456_SLUG_EXIST)
                model = serializer.save(request)
                if model:
                    data = {}
                    data['document_library_category_hls_video'] = model.id
                    data['message'] = 'Add successfully!'
                    return Response(data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("DocumentLibraryCategoryHLSVideoMVS_add_document_library_category_hls_video_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["PATCH"], detail=False, url_path="edit_document_library_category_hls_video_api", url_name="edit_document_library_category_hls_video_api")
    def edit_document_library_category_hls_video_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not serializer.slug_validate(request):
                    return Response(serializer.errors, status=status_http.HTTP_ME_456_SLUG_EXIST)
                model = serializer.update(request)
                if model:
                    data = {}
                    data['name'] = model.name
                    data['message'] = 'Add successfully!'
                    return Response(data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("DocumentLibraryCategoryHLSVideoMVS_edit_document_library_category_hls_video_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["DELETE"], detail=False, url_path="delete_document_library_category_hls_video_api", url_name="delete_document_library_category_hls_video_api")
    def delete_document_library_category_hls_video_api(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = {}
                result = serializer.delete(request)
                if result:
                    data['message'] = 'Delete successfully!'
                    return Response(data, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print(
                "DocumentLibraryCategoryHLSVideoMVS_delete_document_library_category_hls_video_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

class UploadDocumentLibraryHLSVideoMVS(viewsets.ModelViewSet):
    serializer_class = UploadDocumentLibraryHLSVideoSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    @action(methods=["POST"], detail=False, url_path="upload_hls_video_api", url_name="upload_hls_video_api")
    def upload_hls_video_api(self, request, *args, **kwargs):
        try:
            # user_id = _get_user_id_from_token(request)
            context = {'user_id': request.user.id}
            # print("upload_hls_video_api: ", request.data)
            serializer = self.serializer_class(data=request.data, context=context)
            if serializer.is_valid():
                serializer.upload(request)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print("upload_hls_video_api: ", error)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)

# ====================================================
class CheckLockLoginSystem(viewsets.ModelViewSet):
    permission_classes = [AllowAny]

    @action(methods=["GET"], detail=False, url_path="check_is_lock_login", url_name="check_is_lock_login")
    def check_is_lock_login(self, request, *args, **kwargs):
        try:
            setting = Setting.objects.first()
            if setting:
                return Response({'is_lock_login': setting.is_lock_login}, status=status.HTTP_200_OK)
        except Exception as e:
            print("Lock login: ", e)
        return Response({'error': 'Bad request'}, status=status.HTTP_400_BAD_REQUEST)