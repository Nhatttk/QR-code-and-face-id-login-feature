
from django.conf.urls import include
from django.urls import path

from rest_framework import permissions

from .serializers import MyTokenObtainPairView
from .views import *

history_log_get_all_api = HistoryLogMVS.as_view(
    {'get': 'history_log_get_all_api'})
upload_avatar_user_api = UploadAvatarUserMVS.as_view(
    {'patch': 'upload_avatar_user_api'})
profile_check_exist_api = ProfileMVS.as_view(
    {'post': 'profile_check_exist_api'})
profile_add_api = ProfileMVS.as_view({'post': 'profile_add_api'})

urlpatterns = [
    # user
    path('account/get-user-profile/', get_profile_view),
    path('account/update-user-profile/', update_user_profile_view),
    path('account/change-password/', change_password_view),
    path('account/history-log-get-all/', history_log_get_all_api),
    path('account/upload-avatar-user/', upload_avatar_user_api),
    path('account/profile-check-exist/', profile_check_exist_api),
    path('account/profile-add/', profile_add_api),
    # auth
    path('auth/google/', GoogleView.as_view(), name='google'),
    path('auth/login/', MyTokenObtainPairView.as_view()),
    # #
    path('system/', include('api.system.urls'))
]
