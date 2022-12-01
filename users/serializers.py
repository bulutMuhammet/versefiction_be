import re
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User, update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import serializers, exceptions
from rest_framework.generics import RetrieveAPIView
from rest_framework.serializers import Serializer
from rest_framework_simplejwt.serializers import PasswordField
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from users.models import Profile
from users.tokens import AccountVerificationToken


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id',  'username', 'email', 'password')

    def validate(self, attr):
        validate_password(attr["password"])

        return attr

    def validate_email(self, email):
        email = email.lower()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('Bu epostayı kullanan bir kullanıcı zaten mevcut.')
        return email

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data["username"],
            email=validated_data["email"]
        )
        user.set_password(validated_data["password"])
        user.save()
        send_verify_mail(user=user)


        return user

class UpdateUserSerializer(serializers.ModelSerializer):


    class Meta:
        model = User
        fields = ('first_name', 'username', 'email')


    def validate_email(self, email):
        email = email.lower()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('Bu epostayı kullanan bir kullanıcı zaten mevcut.')
        return email



class TokenObtainSerializer(serializers.Serializer):
    username_field = get_user_model().USERNAME_FIELD

    default_error_messages = {
        'no_active_account': _('No active account found with the given credentials')
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields[self.username_field] = serializers.CharField()
        self.fields['password'] = PasswordField()

    def validate(self, attrs):
        username = attrs[self.username_field]

        if re.match(r"[^@]+@[^@]+\.[^@]+", username):
            users = User.objects.filter(email__iexact=username)
            if len(users) > 0 and len(users) == 1:
                attrs[self.username_field] = users.first().username

        authenticate_kwargs = {
            self.username_field: attrs[self.username_field],
            'password': attrs['password'],
        }
        try:
            authenticate_kwargs['request'] = self.context['request']
        except KeyError:
            pass

        self.user = authenticate(**authenticate_kwargs)

        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )



        return {}

    @classmethod
    def get_token(cls, user):
        raise NotImplementedError('Must implement `get_token` method for `TokenObtainSerializer` subclasses')


class TokenObtainPairSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        ver = VerifiedUser.objects.filter(user=self.user)
        if ver.exists():
            return data
        else:
            raise serializers.ValidationError('Henüz hesabını onaylamadın.')


class CustomJWTSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        credentials = {
            'username': '',
            'password': attrs.get("password")
        }

        # This is answering the original question, but do whatever you need here.
        # For example in my case I had to check a different model that stores more user info
        # But in the end, you should obtain the username to continue.
        user_obj = User.objects.filter(email=attrs.get("username")).first() or User.objects.filter(username=attrs.get("username")).first()
        if user_obj:
            credentials['username'] = user_obj.username

        return super().validate(credentials)

class ForgotPasswordSerializer(Serializer):
    email = serializers.EmailField(required=True)

    class Meta:
        fields = ('email',)

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError('This email address is not registered.')

class ResetPasswordSerializer(Serializer):
    new_password = serializers.CharField(required=True)

    class Meta:
        fields = ("new_password",)

    def validate_new_password(self, value):
        validate_password(value)
        return value

class ProfileRegisterSerializer(serializers.ModelSerializer):
    GENDER       = (('e', 'Erkek'), ('k', 'Kadın'), ('d', 'Diğer'))
    gender = serializers.ChoiceField(required=True, choices=GENDER)

    class Meta:
        model = Profile
        fields = ('gender','country','birth_date','bio')

class ProfileUpdateSerializer(serializers.ModelSerializer,RetrieveAPIView):
    GENDER = (('e', 'Erkek'), ('k', 'Kadın'), ('d', 'Diğer'))
    gender = serializers.ChoiceField(required=True, choices=GENDER)
    class Meta:
        model=Profile
        fields = ('gender','country','birth_date','bio')

class ChangePasswordSerializer(Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    class Meta:
        fields = ("old_password", "new_password",)

    def validate_new_password(self, value):
        validate_password(value)
        return value

def send_verify_mail(user):
    ### Creating  Token
    account_verification_token = AccountVerificationToken()
    token = account_verification_token.make_token(user)

    ### Username base64 encode
    base64 = urlsafe_base64_encode(force_bytes(user.username))


    hostname = "http://127.0.0.1:8000"


    ### Mail content with verification link
    verify_link = f"{hostname}/user/verify-account/{base64}/{token}"
    # message_html = render_to_string("email/api_confirm_account.html", {"verify_link": verify_link,"email":user.email,'user':user})
    message = render_to_string("email/verify.txt", {"verify_link": verify_link})

    send_mail(subject="Verify your account", message=message, #html_message=message_html,
              from_email='testmest5398@gmail.com',
              recipient_list=[str(user.email)], fail_silently=False)