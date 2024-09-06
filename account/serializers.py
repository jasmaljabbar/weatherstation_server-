from rest_framework import serializers
from rest_framework_simplejwt.tokens import Token
from .models import UserData
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed




class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserData
        fields = ['id', 'email', 'first_name','last_name', 'password', 'is_verified', 'otp',]
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = UserData.objects.create_user(**validated_data)
        return user

class OtpSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)


class LoginSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)

        user = self.user

        # Bypass the is_verified check for superusers (admins)
        if not user.is_verified and not user.is_superuser:
            raise AuthenticationFailed('Account is not verified.')

        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        data['first_name'] = user.first_name
        data['email'] = user.email
        data['is_staff'] = user.is_staff
        data['is_admin'] = user.is_superuser

        return data

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['first_name'] = user.first_name
        token['email'] = user.email
        token['is_staff'] = user.is_staff
        token['is_admin'] = user.is_superuser
        return token

class GoogleUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserData
        fields = ['id', 'email', 'first_name', 'last_name', 'password', 'is_verified']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = UserData.objects.create_user(**validated_data)
        user.is_verified = True  # Google users are pre-verified
        user.save()
        return user