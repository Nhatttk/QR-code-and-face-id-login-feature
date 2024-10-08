"""gescareer_schoolbycity URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
#
# from django.conf.urls import url
from django.views.generic.base import RedirectView
from django.conf.urls.static import static
from django.conf import settings

# from api.views import SecureFile
from api.views import protected_media_view, textfile_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', RedirectView.as_view(url='admin/login/')),
    path('api/', include('api.urls')),
    #
    # url(r'^protected/', include('protected_media.urls')),
    # path('/media/images/avatars/<str:file>', SecureFile, name="secure")
    path('protected-media/<str:subpath>/<str:filename>/',
         protected_media_view, name='protected-media'),
    path('textfile/<str:filename>', textfile_view, name='textfile_view'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
