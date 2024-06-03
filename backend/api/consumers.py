# yourapp/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer, WebsocketConsumer
class QRCodeConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope["url_route"]["kwargs"]["room_name"]
        self.room_group_name = f"chat_{self.room_name}"

        # Join room group
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)

        await self.accept()
        await self.send(text_data=json.dumps({"message": 'success'}))

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

        # Optional: You can send a message to the group that a user has disconnected
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'send.message',
                'message': f'A user has disconnected.',
                'status_socket': 'disconnected'
            }
        )

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        
        status = text_data_json['status']
        print("status: ",status)
        if status == 'success':
                    sessionID = text_data_json['qr_data']
                    print("sesID: ", sessionID)
                    username = text_data_json['username']
                    await self.channel_layer.group_send(
                    self.room_group_name ,
                    {
                        'type' : 'send.message',
                        'message': f'QR code scanned successfully for user: {username}',
                        'username': username,
                        'status_socket' : 'success'
                    })
        elif  status == 'alow_login' : 
                    sessionID = text_data_json['qr_data']
                    print("sesID: ", sessionID)
                    access_token = text_data_json['accessToken']
                    await self.channel_layer.group_send(
                    self.room_group_name ,
                    {
                        'type' : 'send.message.data',
                        'message': f'Alow Login',
                        'access_token': access_token,
                        'status_socket' : 'alow_login'
                    }
                
            )
    async def send_message(self, event):
        # Nhận và gửi dữ liệu đến client cụ thể
        text_data = event["message"]
        status_socket = event["status_socket"]
        username = event["username"]
        await self.send(text_data=json.dumps({"message": text_data, "status_socket": status_socket, 'username': username}))
    
    async def send_message_data(self, event):
        # Nhận và gửi dữ liệu đến client cụ thể
        text_data = event["message"]
        access_token = event["access_token"]
        status_socket = event["status_socket"]
        await self.send(text_data=json.dumps({"message": text_data, "access_token": access_token, "status_socket": status_socket}))
