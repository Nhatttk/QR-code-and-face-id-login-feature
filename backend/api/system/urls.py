from django.urls import path

from .views import *

image_library_get_all_images_by_category_api = ImageLibraryMVS.as_view({
    'get': 'image_library_get_all_images_by_category_api'
})
image_library_delete_image_api = ImageLibraryMVS.as_view({
    'delete': 'image_library_delete_image_api'
})
image_library_update_image_api = ImageLibraryMVS.as_view({
    'patch': 'image_library_update_image_api'
})
#
image_library_category_get_all_api = ImageLibraryCategoryMVS.as_view({
    'get': 'image_library_category_get_all_api'
})
add_image_library_category_api = ImageLibraryCategoryMVS.as_view({
    'post': 'add_image_library_category_api'
})
edit_image_library_category_api = ImageLibraryCategoryMVS.as_view({
    'patch': 'edit_image_library_category_api'
})
delete_image_library_category_api = ImageLibraryCategoryMVS.as_view({
    'delete': 'delete_image_library_category_api'
})
upload_image_library_for_category_api = UploadImageLibraryMVS.as_view(
    {'post': 'upload_image_library_for_category_api'})

# ============================================================================

image_library_protected_get_all_images_by_category_api = ImageLibraryProtectedMVS.as_view({
    'get': 'image_library_protected_get_all_images_by_category_api'
})
image_library_protected_delete_image_api = ImageLibraryProtectedMVS.as_view({
    'delete': 'image_library_protected_delete_image_api'
})
image_library_protected_update_image_api = ImageLibraryProtectedMVS.as_view({
    'patch': 'image_library_protected_update_image_api'
})
#
image_library_protected_category_get_all_api = ImageLibraryProtectedCategoryMVS.as_view({
    'get': 'image_library_protected_category_get_all_api'
})
add_image_library_protected_category_api = ImageLibraryProtectedCategoryMVS.as_view({
    'post': 'add_image_library_protected_category_api'
})
edit_image_library_protected_category_api = ImageLibraryProtectedCategoryMVS.as_view({
    'patch': 'edit_image_library_protected_category_api'
})
delete_image_library_protected_category_api = ImageLibraryProtectedCategoryMVS.as_view({
    'delete': 'delete_image_library_protected_category_api'
})
upload_image_library_protected_for_category_api = UploadImageLibraryProtectedMVS.as_view(
    {'post': 'upload_image_library_protected_for_category_api'})

# ============================================================================


document_library_get_all_documents_by_category_api = DocumentLibraryMVS.as_view({
    'get': 'document_library_get_all_documents_by_category_api'
})
document_library_delete_document_api = DocumentLibraryMVS.as_view({
    'delete': 'document_library_delete_document_api'
})
document_library_update_document_api = DocumentLibraryMVS.as_view({
    'patch': 'document_library_update_document_api'
})
#
document_library_category_get_all_api = DocumentLibraryCategoryMVS.as_view({
    'get': 'document_library_category_get_all_api'
})
add_document_library_category_api = DocumentLibraryCategoryMVS.as_view({
    'post': 'add_document_library_category_api'
})
edit_document_library_category_api = DocumentLibraryCategoryMVS.as_view({
    'patch': 'edit_document_library_category_api'
})
delete_document_library_category_api = DocumentLibraryCategoryMVS.as_view({
    'delete': 'delete_document_library_category_api'
})
upload_document_library_for_category_api = UploadDocumentLibraryMVS.as_view(
    {'post': 'upload_document_library_for_category_api'})

# HLS VIDEO
document_library_hls_video_get_all_documents_by_category_api = DocumentLibraryHLSVideoMVS.as_view({
    'get': 'document_library_hls_video_get_all_documents_by_category_api'
})
document_library_hls_video_get_all_documents_by_category_and_m3u8_api = DocumentLibraryHLSVideoMVS.as_view({
    'get': 'document_library_hls_video_get_all_documents_by_category_and_m3u8_api'
})
document_library_hls_video_delete_document_api = DocumentLibraryHLSVideoMVS.as_view({
    'delete': 'document_library_hls_video_delete_document_api'
})
document_library_hls_video_update_document_api = DocumentLibraryHLSVideoMVS.as_view({
    'patch': 'document_library_hls_video_update_document_api'
})
#
document_library_category_hls_video_get_all_api = DocumentLibraryCategoryHLSVideoMVS.as_view({
    'get': 'document_library_category_hls_video_get_all_api'
})
add_document_library_category_hls_video_api = DocumentLibraryCategoryHLSVideoMVS.as_view({
    'post': 'add_document_library_category_hls_video_api'
})
edit_document_library_category_hls_video_api = DocumentLibraryCategoryHLSVideoMVS.as_view({
    'patch': 'edit_document_library_category_hls_video_api'
})
delete_document_library_category_hls_video_api = DocumentLibraryCategoryHLSVideoMVS.as_view({
    'delete': 'delete_document_library_category_hls_video_api'
})
#
upload_hls_video_api = UploadDocumentLibraryHLSVideoMVS.as_view({
    'post': 'upload_hls_video_api'
})
#
check_is_lock_login = CheckLockLoginSystem.as_view({
    'get': 'check_is_lock_login'
})

urlpatterns = [
    path('image_library_category_get_all_api/',
         image_library_category_get_all_api),
    path('image_library_get_all_images_by_category_api/<int:category_id>/',
         image_library_get_all_images_by_category_api),
    path('image_library_delete_image_api/<int:image_id>/',
         image_library_delete_image_api),
    path('image_library_update_image_api/',
         image_library_update_image_api),
    #
    path('add_image_library_category_api/', add_image_library_category_api),
    path('edit_image_library_category_api/', edit_image_library_category_api),
    path('delete_image_library_category_api/',
         delete_image_library_category_api),
    path('upload_image_library_for_category_api/',
         upload_image_library_for_category_api),
    # ================================================

    path('image_library_protected_category_get_all_api/',
         image_library_protected_category_get_all_api),
    path('image_library_protected_get_all_images_by_category_api/<int:category_id>/',
         image_library_protected_get_all_images_by_category_api),
    path('image_library_protected_delete_image_api/<int:image_id>/',
         image_library_protected_delete_image_api),
    path('image_library_protected_update_image_api/',
         image_library_protected_update_image_api),
    #
    path('add_image_library_protected_category_api/',
         add_image_library_protected_category_api),
    path('edit_image_library_protected_category_api/',
         edit_image_library_protected_category_api),
    path('delete_image_library_protected_category_api/',
         delete_image_library_protected_category_api),
    path('upload_image_library_protected_for_category_api/',
         upload_image_library_protected_for_category_api),
    # ================================================

    path('document_library_category_get_all_api/',
         document_library_category_get_all_api),
    path('document_library_get_all_documents_by_category_api/<int:category_id>/',
         document_library_get_all_documents_by_category_api),
    path('document_library_delete_document_api/<int:document_id>/',
         document_library_delete_document_api),
    path('document_library_update_document_api/',
         document_library_update_document_api),
    #
    path('add_document_library_category_api/',
         add_document_library_category_api),
    path('edit_document_library_category_api/',
         edit_document_library_category_api),
    path('delete_document_library_category_api/',
         delete_document_library_category_api),
    path('upload_document_library_for_category_api/',
         upload_document_library_for_category_api),

    # HLS VIDEO
    path('document_library_category_hls_video_get_all_api/',
         document_library_category_hls_video_get_all_api),
    path('document_library_hls_video_get_all_documents_by_category_api/<int:category_id>/',
         document_library_hls_video_get_all_documents_by_category_api),
    path('document_library_hls_video_get_all_documents_by_category_and_m3u8_api/<int:category_id>/',
         document_library_hls_video_get_all_documents_by_category_and_m3u8_api),
    path('document_library_hls_video_delete_document_api/<int:document_id>/',
         document_library_hls_video_delete_document_api),
    path('document_library_hls_video_update_document_api/',
         document_library_hls_video_update_document_api),
    path('add_document_library_category_hls_video_api/',
         add_document_library_category_hls_video_api),
    path('edit_document_library_category_hls_video_api/',
         edit_document_library_category_hls_video_api),
    path('delete_document_library_category_hls_video_api/',
         delete_document_library_category_hls_video_api),

    path('upload_hls_video_api/', upload_hls_video_api),

    # ================================================
    path('check_is_lock_login/', check_is_lock_login),
]
