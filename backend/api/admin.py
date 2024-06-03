from django.contrib import admin
from .models import *

admin.site.register(Profile)
admin.site.register(HistoryLog)
admin.site.register(ImageLibrary)
admin.site.register(DocumentLibrary)
#
admin.site.register(ImageLibraryProtected)


class ImageLibraryCategoryAdmin(admin.ModelAdmin):
    prepopulated_fields = {"slug": ("name",)}


admin.site.register(ImageLibraryCategory, ImageLibraryCategoryAdmin)
#


class ImageLibraryProtectedCategoryAdmin(admin.ModelAdmin):
    prepopulated_fields = {"slug": ("name",)}


admin.site.register(ImageLibraryProtectedCategory,
                    ImageLibraryProtectedCategoryAdmin)
#


class DocumentLibraryCategoryAdmin(admin.ModelAdmin):
    prepopulated_fields = {"slug": ("name",)}


admin.site.register(DocumentLibraryCategory, DocumentLibraryCategoryAdmin)

admin.site.register(Setting)

#


class DocumentLibraryCategoryHLSVideoAdmin(admin.ModelAdmin):
    prepopulated_fields = {"slug": ("name",)}


admin.site.register(DocumentLibraryCategoryHLSVideo,
                    DocumentLibraryCategoryHLSVideoAdmin)
admin.site.register(DocumentLibraryHLSVideo)
