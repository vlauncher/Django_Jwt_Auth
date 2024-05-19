from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('verify/<str:uidb64>/<str:token>/', EmailVerificationAPIView.as_view(), name='email-verify'),
    path('login/', LoginAPIView.as_view(), name='login'),
     path('password-reset/', PasswordResetRequestAPIView.as_view(), name='password-reset'),
    path('password-reset/<str:uidb64>/<str:token>/', PasswordResetAPIView.as_view(), name='password-reset-confirm'),
    path('change-password/', PasswordChangeAPIView.as_view(), name='change-password'),
    path('profile/', ProfileRetrieveUpdateAPIView.as_view(), name='agent-profile'),
    path('token-refresh/', TokenRefreshView.as_view(), name='token-refresh'),
]