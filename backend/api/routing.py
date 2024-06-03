from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    # We use re_path() due to limitations in URLRouter.
    re_path(r"ws/qr_code/(?P<room_name>\w+)/$", consumers.QRCodeConsumer.as_asgi()),
]