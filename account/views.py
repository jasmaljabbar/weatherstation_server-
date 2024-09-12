from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import UserSerializer,LoginSerializer,GoogleUserSerializer
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from .utils import generate_otp,send_otp_email
from django.conf import settings
from rest_framework.decorators import permission_classes
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.contrib.auth.models import User
from google.oauth2 import id_token
from google.auth.transport import requests
from django.db.models import Q
from rest_framework.permissions import AllowAny
from datetime import timedelta
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from .models import UserData
from rest_framework_simplejwt.views import TokenObtainPairView
import environ
from pathlib import Path

env = environ.Env(DEBUG=(bool, False))


@permission_classes([AllowAny])
class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer
    

@permission_classes([AllowAny])
class VerifyOTP(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp_entered = request.data.get('otp')

        try:
            user = UserData.objects.get(email=email, otp=otp_entered)
            print('email:',email, 'otp:',otp_entered)
            if user.otp_time:
                current_time = timezone.now()
                otp_time = user.otp_time

                # Check if the OTP is within 1 minutes
                if current_time - otp_time > timedelta(minutes=1):
                    return Response({'detail': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

            user.is_verified = True
            user.otp = None
            user.otp_time = None
            user.save()


            return Response({'message': 'Email verified successfully.'}, 
                              status=status.HTTP_200_OK)
        except UserData.DoesNotExist:
            return Response({'detail': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)



@permission_classes([IsAuthenticated])
class UserIndivualView(RetrieveUpdateDestroyAPIView):
    serializer_class = UserSerializer
    queryset = UserData.objects.all()


@permission_classes([AllowAny])
class RegisterView(APIView):
     
     def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            otp = generate_otp()
            user.otp = otp
            user.otp_time = timezone.now()
            print(otp)
            user.save()

            send_otp_email(user.email, otp)

            return Response({'message': 'User registered successfully. OTP sent to your email.'}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@permission_classes([AllowAny])    
class ResendOtpView(APIView):
    def post(self, request):
        email = request.data.get('email')

        try:
            user = UserData.objects.get(email=email)

            otp = generate_otp()
            user.otp = otp
            user.otp_time = timezone.now()
            print(otp)
            user.save()

            send_otp_email(user.email, otp)

            return Response({'message': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)
        except UserData.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    

class HomeView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user
        user_info = {
            "username": user.name,
            "email": user.email,
        }
        content = {"user": user_info}
        return Response(content)





class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get("refreshToken")
            if refresh_token:
                RefreshToken(refresh_token).blacklist()
                return Response(status=status.HTTP_205_RESET_CONTENT)
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class GoogleAuthentication(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        credential = request.data.get('credential')
        
        if not credential:
            return Response({'error': 'No credential provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            CLIENT_ID =env('CLIENT_ID')
            id_info = id_token.verify_oauth2_token(credential, requests.Request(), CLIENT_ID)

            
            # Extract user details
            email = id_info.get('email')
            first_name = id_info.get('given_name')
            last_name = id_info.get('family_name')
            google_user_id = id_info.get('sub')

            # Check if user already exists
            try:
                user = UserData.objects.get(email=email)
                if not user.is_active:
                    return Response({'message': 'User is blocked'}, status=status.HTTP_403_FORBIDDEN)
            except UserData.DoesNotExist:
                # If user doesn't exist, create a new one
                default_password = get_random_string(32)  # Generate random password
                user_data = {
                    'email': email,
                    'first_name': first_name,
                    'last_name': last_name,
                    'password': default_password,
                    'is_verified': True,  
                }
                serializer = GoogleUserSerializer(data=user_data)
                if serializer.is_valid():
                    user = serializer.save()
                else:
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            # Generate JWT tokens for the user
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            user_info = {
                'first_name': user.first_name,
                'email': user.email,
                'is_staff': user.is_staff,
                'is_admin': user.is_superuser
            }

            return Response({
                'refresh': str(refresh),
                'access': access_token,
                'user': user_info
            }, status=status.HTTP_200_OK)
        
        except ValueError as e:
            # If the token is invalid
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

# account/views.py
from django.http import JsonResponse

def test_view(request):
    return JsonResponse({'message': 'This is a test endpoint.'})
