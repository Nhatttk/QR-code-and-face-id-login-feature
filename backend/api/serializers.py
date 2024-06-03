from django.contrib.auth.models import User, Group, Permission
from django.core.validators import EmailValidator
from django.db.models import fields
from django.utils.crypto import get_random_string
from requests.api import request
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
import socket
import calendar
import time
from getmac import get_mac_address as gma
from user_agents import parse
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.hashers import make_password
from datetime import timedelta, datetime

from api.models import *
# from api.submodels.models_student import StudentMe


def getOriginalRefreshToken(refresh_token):
    try:
        original_string = ""
        temp_string = refresh_token.split("@%.!")
        if len(temp_string) > 0:
            if len(str(temp_string[0])) > 0:
                return ""
            original_string = str(temp_string[1])
        return original_string
    except:
        return ""


def getUserFromRefreshToken(self, refresh_token):
    try:
        refresh_token = RefreshToken(refresh_token)
        # print("refresh_token: ", refresh_token)
        user_id = refresh_token["user_id"]
        user = User.objects.get(pk=user_id)
        return user
    except:
        return None


def getUserFromAccessToken(self, access_token):
    try:
        access_token = AccessToken(access_token)
        user_id = access_token["user_id"]
        user = User.objects.get(pk=user_id)
        return user
    except:
        return None


def _is_token_valid(self, access_token):
    try:
        access_token = AccessToken(access_token)
        user_id = access_token["user_id"]
        User.objects.get(email=self.validated_data["email"], id=user_id)
        return True
    except:
        return False


def _token_get_exp(access_token):
    try:
        access_token = AccessToken(access_token)
        return access_token["exp"]
    except Exception as error:
        print("===_token_get_exp", error)
        return None


# class ImageLibrarySeriProfileisalizer(serializers.ModelSerializer):
#     class Meta:
#         model = ImageLibrary
#         fields = '__all__'


class UploadAvatarUserSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(required=True)
    user_id = serializers.IntegerField()

    class Meta:
        model = Profile
        fields = ["avatar", "user_id"]

    def update_avatar(self, request):
        try:
            user_id = self.validated_data["user_id"]
            avatar = self.validated_data["avatar"]
            model = Profile.objects.get(pk=user_id)
            storage, path = model.avatar.storage, model.avatar.path
            model.avatar = avatar
            model.save()
            if storage.exists(path):
                if "avatar_default.png" not in path:
                    storage.delete(path)
            return model
        except Exception as error:
            print("UploadAvatarUserSerializer_update_avatar_error: ", error)
            return None


class ProfileUpdateAuthenticationSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True)

    class Meta:
        model = Profile
        fields = ["phone", "email"]
        # extra_fields = ['email']

    def check_is_exist(self, request):
        email = self.validated_data["email"]
        filterExist = Profile.objects.filter(user__email=email)
        if len(filterExist) > 0:
            return True
        return False

    def check_is_mentor(self, request):
        email = self.validated_data["email"]
        filterExist = Profile.objects.filter(user__email=email, is_mentor=True)
        if len(filterExist) > 0:
            return True
        return False

    def check_is_leader_support_course(self, request):
        email = self.validated_data["email"]
        filterExist = Profile.objects.filter(
            user__email=email, is_sub_mentor=True)
        if len(filterExist) > 0:
            return True
        return False

    def check_is_school_admin(self, request):
        email = self.validated_data["email"]
        filterExist = Profile.objects.filter(
            user__email=email, is_school_admin=True)
        if len(filterExist) > 0:
            return True
        return False

    def check_is_student(self, request):
        email = self.validated_data["email"]
        filterExist = Profile.objects.filter(
            user__email=email, is_mentor=False, is_sub_mentor=False, is_school_admin=False, is_algorithm_mentor=False)
        if len(filterExist) > 0:
            return True
        return False

    def add(self, request):
        try:
            phone = self.validated_data["phone"]
            email = self.validated_data["email"]
            first_name = request.data.get("first_name")
            last_name = request.data.get("last_name")

            user = User()
            user.username = email
            # provider random default password
            user.password = make_password(
                BaseUserManager().make_random_password())
            user.email = email
            user.first_name = first_name
            user.last_name = last_name
            user.save()

            member_group = Group.objects.get(
                name=settings.GROUP_NAME["MEMBER"])
            member_group.user_set.add(user)

            Profile.objects.create(user=user, phone=phone)

            return True
        except Exception as error:
            print("ProfileSerializer_add_error: ", error)
            return None


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            "address",
            "gender",
            "phone",
            "facebook",
            "avatar",
            "count_change_password",
            "is_sub_mentor"
        ]


class UpdateProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    profile = ProfileSerializer()

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "profile"]
        extra_kwargs = {
            "email": {"validators": [EmailValidator]},
        }

    def save(self):
        user = User.objects.get(email=self.validated_data["email"])
        user.first_name = self.validated_data["first_name"]
        user.last_name = self.validated_data["last_name"]
        user.save()
        profile = Profile.objects.get(user=user)
        profile_data = self.validated_data["profile"]
        profile.phone = profile_data["phone"]
        profile.address = profile_data["address"]
        profile.gender = profile_data["gender"]
        profile.save()
        return user


class ChangePasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        style={"input_type": "password"}, write_only=True)
    old_password = serializers.CharField(
        style={"input_type": "password"}, write_only=True
    )

    class Meta:
        model = User
        fields = ["email", "password", "old_password"]
        extra_kwargs = {
            "password": {"write_only": True},
            "old_password": {"write_only": True},
            "email": {"validators": [EmailValidator]},
        }

    def validate(self, data):
        if len(data["old_password"]) < 5:
            raise serializers.ValidationError(
                {"message": "Password must be at least 5 characters."}
            )
        if len(data["password"]) < 5:
            raise serializers.ValidationError(
                {"message": "Password must be at least 5 characters."}
            )
        return data

    def old_password_validate(self):
        user = User.objects.get(email=self.validated_data["email"])
        if not user.check_password(self.validated_data["old_password"]):
            return False
        return True

    def update(self):
        user = User.objects.get(email=self.validated_data["email"])
        password = self.validated_data["password"]
        user.set_password(password)
        user.save()
        try:
            profile = Profile.objects.get(pk=user)
            profile.count_change_password += 1
            profile.save()
        except Exception as error:
            print("ProfileSerializer_update_count_change_pass_error: ", error)
        return user


class HistoryLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = HistoryLog
        fields = "__all__"


# Authentication ================================================================


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ("name",)


class GroupSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True)

    class Meta:
        model = Group
        fields = (
            "name",
            "permissions",
        )


class ResetPasswordSerializer(serializers.ModelSerializer):
    refresh_token = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ["password", "refresh_token"]

    # def is_token_valid(self, access_token):
    #     try:
    #         access_token = AccessToken(access_token)
    #         user_id = access_token["user_id"]
    #         User.objects.get(id=user_id)
    #         return True
    #     except:
    #         return False

    def is_refresh_token_valid(self, refresh_token):
        try:
            refresh_token = getOriginalRefreshToken(refresh_token)
            refresh_token = RefreshToken(refresh_token)
            user_id = refresh_token["user_id"]
            User.objects.get(id=user_id)
            return True
        except:
            return False

    def change_password(self):
        refresh_token = self.validated_data["refresh_token"]
        password = self.validated_data["password"]
        refresh_token = getOriginalRefreshToken(refresh_token)
        user = getUserFromRefreshToken(self, refresh_token=refresh_token)
        password = self.validated_data["password"]
        user.set_password(password)
        user.save()
        try:
            profile = Profile.objects.get(pk=user)
            profile.count_change_password += 1
            profile.save()
        except Exception as error:
            print("ResetPasswordSerializer_update_count_change_pass_error: ", error)
        return user


# class ResetPasswordSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(required=True)

#     class Meta:
#         model = User
#         fields = ['email', 'password']
#         extra_kwargs = {
#             'password': {'write_only': True},
#             'email': {'validators': [EmailValidator]},
#         }

#     def validate(self, data):
#         if len(data['password']) < 5:
#             raise serializers.ValidationError(
#                 {'message': 'Password must be at least 5 characters.'})
#         return data

#     def is_token_valid(self, access_token):
#         return _is_token_valid(self, access_token)

#     def change_password(self):
#         access_token=self.validated_data['access_token']
#         password=self.validated_data['password']
#         user = getUserFromAccessToken(self, access_token=access_token)
#         password = self.validated_data['password']
#         user.set_password(password)
#         user.save()
#         return user

# def change_password(self):
#     user = User.objects.get(email=self.validated_data['email'])
#     password = self.validated_data['password']
#     user.set_password(password)
#     user.save()
#     return user


class CreateAccessTokenSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ["email"]
        extra_kwargs = {
            "email": {"validators": [EmailValidator]},
        }

    def is_account_active(self):
        try:
            user = User.objects.get(
                email=self.validated_data["email"], is_active=True)
            return True
        except:
            return False

    def is_email_exist(self):
        try:
            user = User.objects.get(email=self.validated_data["email"])
            return True
        except:
            return False

    def get_user(self):
        try:
            return User.objects.get(email=self.validated_data["email"])
        except:
            return None


class ActiveAccountSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ["email"]
        extra_kwargs = {
            "email": {"validators": [EmailValidator]},
        }

    def is_account_active(self):
        try:
            user = User.objects.get(
                email=self.validated_data["email"], is_active=True)
            return True
        except:
            return False

    def is_email_exist(self):
        try:
            user = User.objects.get(email=self.validated_data["email"])
            return True
        except:
            return False

    def save(self):
        user = User.objects.get(email=self.validated_data["email"])
        user.is_active = True
        user.save()
        return user

    def is_token_valid(self, access_token):
        return _is_token_valid(self, access_token)


class ResendActivationLinkSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ["email"]
        extra_kwargs = {
            "email": {"validators": [EmailValidator]},
        }

    def is_account_active(self):
        try:
            user = User.objects.get(
                email=self.validated_data["email"], is_active=True)
            return True
        except:
            return False

    def is_email_exist(self):
        try:
            user = User.objects.get(email=self.validated_data["email"])
            return True
        except:
            return False

    def send_mail(self):
        user = User.objects.get(email=self.validated_data["email"])
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        link_active = settings.FRONTEND_SITE_URL_ACTIVE_ACCOUNT + \
            "".join(access_token)
        message = render_to_string(
            "api/mail/resend_link_active_account.html",
            {"link_active": link_active, "email_title": settings.EMAIL_TITLE},
        )
        send = EmailMessage(
            settings.EMAIL_TITLE,
            message,
            from_email=settings.EMAIL_FROM,
            to=[self.validated_data["email"]],
        )
        send.content_subtype = "html"
        send.send()
        return True


class ForgotPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    school_domain = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ["email", "school_domain"]
        extra_kwargs = {
            "email": {"validators": [EmailValidator]},
        }

    def is_account_active(self):
        try:
            User.objects.get(
                email=self.validated_data["email"], is_active=True)
            return True
        except:
            return False

    # def is_email_exist(self):
    #     try:
    #         email = self.validated_data["email"]
    #         school_domain = self.validated_data["school_domain"]
    #         User.objects.get(email=email)
    #         checkSchoolValid = StudentMe.objects.filter(
    #             email=email, domain_school=school_domain
    #         ).count()
    #         if checkSchoolValid == 0:
    #             return False
    #         return True
    #     except:
    #         return False

    def send_mail(self):
        email = self.validated_data["email"]
        user = User.objects.get(email=email)
        refresh = RefreshToken.for_user(user)
        from_time = datetime.utcnow()
        expiration_time = timedelta(minutes=15)
        refresh.set_exp(from_time=from_time, lifetime=expiration_time)
        refresh_token = str(refresh)
        refresh_token_fake = "@%.!" + refresh_token
        # print("refresh_token: ", refresh_token_fake)
        # print("expiration_time: ", refresh)
        # link_active = settings.FRONTEND_SITE_URL_RESET_PASSWORD + \
        #     ''.join(access_token)
        message = render_to_string('api/mail/forgot_password.html',
                                   {'email_title': settings.EMAIL_TITLE, 'code': refresh_token_fake})
        send = EmailMessage(settings.EMAIL_TITLE, message,
                            from_email=settings.EMAIL_FROM, to=[self.validated_data['email']])
        send.content_subtype = 'html'
        send.send()
        #
        return True


class RegistrationSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    phone = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = [
            "email",
            "password",
            "first_name",
            "last_name",
            "phone",
        ]  # 'username',
        extra_kwargs = {
            "password": {"write_only": True},
            "email": {"validators": [EmailValidator]},
        }

    def is_email_exist(self):
        try:
            user = User.objects.get(email=self.validated_data["email"])
            return True
        except:
            return False

    def save(self):
        user = User(
            email=self.validated_data["email"],
            username=self.validated_data["email"],
            first_name=self.validated_data["first_name"],
            last_name=self.validated_data["last_name"],
        )
        password = self.validated_data["password"]

        if len(password) < 5:
            raise serializers.ValidationError(
                {"password": "Password must be at least 5 characters."}
            )

        user.set_password(password)
        user.is_active = False
        user.save()
        try:
            profile = Profile(user=user, phone=self.validated_data["phone"])
            profile.save()
            member_group = Group.objects.get(
                name=settings.GROUP_NAME["MEMBER"])
            member_group.user_set.add(user)
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            link_active = settings.FRONTEND_SITE_URL_ACTIVE_ACCOUNT + "".join(
                access_token
            )
            message = render_to_string(
                "api/mail/active_account.html",
                {"link_active": link_active, "email_title": settings.EMAIL_TITLE},
            )
            send = EmailMessage(
                settings.EMAIL_TITLE,
                message,
                from_email=settings.EMAIL_FROM,
                to=[self.validated_data["email"]],
            )
            send.content_subtype = "html"
            send.send()
            print("Sent email!")
        except:
            pass
        return user


def _current_user(self):
    request = self.context.get("request", None)
    if request:
        return request.user
    return False


def visitor_ip_address(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


class MySimpleJWTSerializer(TokenObtainPairSerializer):
    my_ip_address = "0.0.0.0"
    myRequest = None

    @classmethod
    def get_token(cls, user):
        # print("user: ", user)
        token = super().get_token(user)
        user_obj = User.objects.get(username=user)
        #
        token["email"] = user_obj.email

        access_token = str(token.access_token)
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        # ip_address = str(MySimpleJWTSerializer.my_ip_address)
        mac_address = gma()
        # print("===444", hostname)
        # print("===555", ip_address)
        # print("===666", mac_address)
        # print("===my_ip_address", MySimpleJWTSerializer.my_ip_address)

        # request = cls.context("request", None)
        # #
        sessionToken = SessionToken.objects.filter(user=user).count()
        if sessionToken == 0:
            sessionToken = SessionToken.objects.get_or_create(
                user=user,
                token=access_token,
                hostname=hostname,
                ip_address=MySimpleJWTSerializer.my_ip_address,
                mac_address=mac_address,
            )
        else:
            sessionToken = SessionToken.objects.get(user=user)
            token_temp = sessionToken.token
            mac_address_temp = sessionToken.mac_address
            ip_address_temp = sessionToken.ip_address

            #
            exp = _token_get_exp(token_temp)
            if exp is not None:
                ts_now = calendar.timegm(time.gmtime())
                # print("===3 : {exp}, {ts_now}", exp, ts_now)
                if ts_now < exp:
                    pass
                    # print("===Exp not end", exp)
                    # if ip_address_temp != MySimpleJWTSerializer.my_ip_address:
                    #     return None
                # else:
                #     print("===42", ts_now)
            else:
                SessionToken.objects.filter(user=user).update(
                    token=access_token,
                    hostname=hostname,
                    ip_address=MySimpleJWTSerializer.my_ip_address,
                    mac_address=mac_address,
                )
                # print("===Exp end")
        #
        # try:
        #     user_agent = MySimpleJWTSerializer.myRequest.user_agent
        #     browser_name = user_agent.browser.family
        #     is_pc = user_agent.is_pc
        #     is_mobile = user_agent.is_mobile
        #     is_tablet = user_agent.is_tablet
        #     device = ""
        #     if is_pc == True:
        #         device = "PC"
        #     elif is_mobile == True:
        #         device = "Mobile"
        #     elif is_tablet == True:
        #         device = "Tablet"
        #     HistoryLog.objects.create(user=user, hostname=hostname, ip_address=MySimpleJWTSerializer.my_ip_address,
        #                               mac_address=mac_address, browser=browser_name, device=device)
        # except Exception as err:
        #     print("HistoryLog: ", str(err))
        #     pass
        return token

    # def validate(self, attrs):
    #     credentials = {"username": "", "password": attrs.get("password")}
    #     # print("school_domain: ", attrs)
    #     #
    #     school_domain = ""
    #     email = ""
    #     username = attrs.get("username").strip()
    #     username_temp = username
    #     username_temp = username_temp.split(":google:email:")
    #     if len(username_temp) > 1:
    #         email = username_temp[0]
    #         school_domain = username_temp[1]
    #         checkSchoolValid = StudentMe.objects.filter(
    #             email=email, domain_school=school_domain
    #         ).count()
    #         # print("checkSchoolValid: ", email)
    #         if checkSchoolValid == 0:
    #             return super().validate(credentials)
    #     else:
    #         email = username
    #     #
    #     # user_obj = User.objects.filter(email=attrs.get("username")).first(
    #     # ) or User.objects.filter(username=attrs.get("username")).first()
    #     user_obj = (
    #         User.objects.filter(email=email).first()
    #         or User.objects.filter(username=email).first()
    #     )
    #     if user_obj:
    #         credentials["username"] = user_obj.username
    #     # request = self.context.get('request', None)
    #     # print("===validate", visitor_ip_address(request))
    #     # MySimpleJWTSerializer.myRequest = request
    #     # MySimpleJWTSerializer.my_ip_address = visitor_ip_address(request)
    #     return super().validate(credentials)


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MySimpleJWTSerializer


# ==========================================

# https://stackoverflow.com/questions/54544978/customizing-jwt-response-from-django-rest-framework-simplejwt
# class LoginGoogleSerializer(TokenObtainPairSerializer):
#     my_ip_address = "0.0.0.0"
#     myRequest = None

#     @classmethod
#     def get_token(cls, user):
#         token = super().get_token(user)
#         user_obj = User.objects.get(username=user)
#         token['email'] = user_obj.email
#         return token

#     def validate(self, attrs):
#         print("validate333: ", attrs)
#         # credentials = {
#         #     'username': '',
#         #     'password': attrs.get("password")
#         # }
#         # user_obj = User.objects.filter(email=attrs.get("username")).first(
#         # ) or User.objects.filter(username=attrs.get("username")).first()
#         # if user_obj:
#         #     credentials['username'] = user_obj.username

#         # token_google = attrs.get("token")
#         email = attrs.get("email")
#         firstName = attrs.get("givenName")
#         lastName = attrs.get("familyName")
#         avatar = attrs.get("imageUrl")

#         # create user if not exist
#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             user = User()
#             user.username = email
#             # provider random default password
#             user.password = make_password(BaseUserManager().make_random_password())
#             user.email = email
#             user.save()

#         request = self.context.get('request', None)
#         print("===validate_LoginGoogleSerializer", visitor_ip_address(request))
#         LoginGoogleSerializer.myRequest = request
#         LoginGoogleSerializer.my_ip_address = visitor_ip_address(request)
#         return user


# class LoginGoogleView(TokenObtainPairView):
#     serializer_class = LoginGoogleSerializer
