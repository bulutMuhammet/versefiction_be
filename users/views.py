# Sadece başaracağım günü bekliyorum.
# Beklemekten öte

from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenViewBase
from users.models import Profile
from users.serializers import RegisterSerializer, TokenObtainPairSerializer, \
    ForgotPasswordSerializer, \
    ResetPasswordSerializer, ProfileRegisterSerializer,  ProfileUpdateSerializer,\
    UpdateUserSerializer, \
    ChangePasswordSerializer
from users.tokens import AccountVerificationToken, PasswordResetToken, \
    password_reset_token
from rest_framework.authentication import SessionAuthentication


class TokenObtainPairView(TokenViewBase):
    serializer_class = TokenObtainPairSerializer


class CreateUserView(CreateAPIView):
    model = User.objects.all()
    serializer_class = RegisterSerializer


class UpdateUserView(APIView):
    queryset = User.objects.all()
    serializer_class = UpdateUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        first_name = request.data['first_name']
        username = request.data['username']
        email = request.data['email']

        serializer = UpdateUserSerializer(
            data={"first_name": first_name, "username": username,
                  "email": email})
        if serializer.is_valid():
            request.user.first_name = first_name
            request.user.username = username
            request.user.email = email
            request.user.save()
            return Response({"User": "Updated"}, status=status.HTTP_202_ACCEPTED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class UpdateProfileView(APIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileUpdateSerializer

    def put(self, request, *args, **kwargs):
        profile = Profile.objects.get(user=request.user)
        serializer = ProfileUpdateSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():

            serializer.save()

            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyAccountView(APIView):
    def get(self, request, *args, **kwargs):
        token = kwargs["token"]
        base64 = kwargs["base64"]
        account_verification_token = AccountVerificationToken()

        try:
            decoded_base64 = force_str(urlsafe_base64_decode(base64))
            user = User.objects.get(username=decoded_base64)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and account_verification_token.check_token(user, token):

            user.verification = True
            user.save()
            return Response({"account": "verifed"}, status=status.HTTP_202_ACCEPTED)
        else:
            return Response({"Token": "Invalid Token"},
                            status=status.HTTP_406_NOT_ACCEPTABLE)


class ForgotPasswordView(APIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        email = request.data['email']
        serializer = ForgotPasswordSerializer(data={"email": email})

        if serializer.is_valid():
            email = serializer.data.get('email')
            user = User.objects.get(email=email)

            ### Creating Reset Token
            password_reset_token = PasswordResetToken()
            token = password_reset_token.make_token(user)

            ### Username base64 encode
            base64 = urlsafe_base64_encode(force_bytes(user.username))

            hostname = request.get_host()

            verify_link = f"{hostname}/user/reset-password/{base64}/{token}"

            # message_html = render_to_string("email/api_reset_password.html", {"verify_link": verify_link,"user":user})

            ### Mail content with reset link
            message = f"Parolanı sıfırla: \n {verify_link}"

            send_mail(subject="Reset Password", message=message,
                      # html_message=message_html,
                      from_email='testmest5398@gmail.com',
                      recipient_list=[str(email)])

            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


class ResetPasswordView(APIView):
    serializer_class = ResetPasswordSerializer

    def put(self, request, *args, **kwargs):
        base64 = kwargs["base64"]
        token = kwargs["token"]
        new_password = request.data['new_password']
        serializer = ResetPasswordSerializer(data={"new_password": new_password})

        try:
            decoded_base64 = force_str(urlsafe_base64_decode(base64))
            user = User.objects.get(username=decoded_base64)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if serializer.is_valid():
            if user is not None and password_reset_token.check_token(user, token):
                user.set_password(serializer.data.get("new_password"))
                user.save()
                update_session_auth_hash(request, user)  # Important!

                return Response(status=status.HTTP_200_OK)
            else:
                return Response({"token": "This token has expired or wrong token. "},
                                status=status.HTTP_408_REQUEST_TIMEOUT)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdatePassword(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    def get_object(self):
        return self.request.user

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        data = {
            "old_password": request.data["old_password"],
            "new_password": request.data["new_password"]
        }

        serializer = ChangePasswordSerializer(data=data)

        if serializer.is_valid():
            old_password = serializer.data.get("old_password")
            if not self.object.check_password(old_password):
                return Response({"old_password": "Wrong password"},
                                status=status.HTTP_400_BAD_REQUEST)

            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response(status=status.HTTP_204_NO_CONTENT)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

