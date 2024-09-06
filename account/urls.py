from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import( RegisterView, HomeView, LogoutView, LoginView,
                    VerifyOTP,ResendOtpView,UserIndivualView,GoogleAuthentication,test_view,)

urlpatterns = [
    path('api/login/', LoginView.as_view(), name='api-login'),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/register/", RegisterView.as_view(), name="sign_up"),
    path('api/validate-otp', VerifyOTP.as_view(), name='validate_otp'),
    path('api/resend-otp', ResendOtpView.as_view(), name='resend_otp'),
    path("api/home/", HomeView.as_view(), name="home"),
    path("google/", GoogleAuthentication.as_view(), name='googleAuthentication'),
    path("api/logout/", LogoutView.as_view(), name="logout"),
    path("api/userindivual/<int:pk>/", UserIndivualView.as_view(),name='token_refersh'),
    path('test-endpoint/', test_view, name='test_view'),

]
