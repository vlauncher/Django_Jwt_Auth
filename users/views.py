from rest_framework.permissions import IsAuthenticated
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import *
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError
from .models import User,Profile
from .tokens import account_activation_token

class RegisterAPIView(generics.GenericAPIView):
    serializer_class = RegistrationSerializer
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        msg = {}
        
        if User.objects.filter(email=serializer.validated_data['email']).exists():
            msg['email'] = 'User with this email already exists.'
        
        if User.objects.filter(username=serializer.validated_data['username']).exists():
            msg['username'] = 'Username is already taken.'
        
        if msg:
            return Response({'msg': msg}, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save()

        # Send verification email
        self.send_verification_email(user)

        return Response(
            {"msg": "Registration successful. Please check your email to verify your account."},
            status=status.HTTP_201_CREATED
        )
    def send_verification_email(self, user):
        current_site = get_current_site(self.request)
        mail_subject = "Activate your account"
        message = render_to_string(
            "email_verification.html",
            {
                "user": user,
                "domain": current_site.domain,
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "token": account_activation_token.make_token(user),
            },
        )
        email = EmailMessage(mail_subject, message, to=[user.email])
        email.content_subtype = "html"
        email.send()


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        user_serializer = UserSerializer(user)
        user_data = user_serializer.data
        refresh = RefreshToken.for_user(user)
        return Response({"msg":"Login Success",'refresh': str(refresh),
            'access': str(refresh.access_token),}, status=status.HTTP_200_OK)


class EmailVerificationAPIView(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer
    permission_classes = (permissions.AllowAny,)

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            if not user.is_active:
                user.is_active = True
                user.save()
                self.send_verification_email(user)
                return Response(
                    {"msg": "Email verification successful. You can now login."},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"msg": "Email has already been verified."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                {"msg": "Invalid verification link."},
                status=status.HTTP_400_BAD_REQUEST
            )
    def send_verification_email(self, user):
        current_site = get_current_site(self.request)
        mail_subject = "Email Confirmation"
        message = render_to_string(
            "email_confirmation.html",
            {
                "user": user,
                "domain": current_site.domain,
            },
        )
        email = EmailMessage(mail_subject, message, to=[user.email])
        email.content_subtype = "html"
        email.send()





class PasswordResetRequestAPIView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        self.send_password_reset_email(user)
        return Response(
            {"msg": "An email with password reset instructions has been sent to your email address."},
            status=status.HTTP_200_OK
        )

    def send_password_reset_email(self, user):
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_url = reverse('password-reset-confirm', kwargs={'uidb64': uid, 'token': token})
        reset_url = self.request.build_absolute_uri(reset_url)
        print(reset_url)
        mail_subject = "Password Reset"
        message = render_to_string(
            "password_reset_email.html",
            {
                "user": user,
                "reset_url": reset_url,
            },
        )
        email = EmailMessage(mail_subject, message, to=[user.email])
        email.content_subtype = "html"
        email.send()




class PasswordResetAPIView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data['password']
        confirm_password = serializer.validated_data['confirm_password']
        uidb64 = self.kwargs['uidb64']
        token = self.kwargs['token']
        user = self.get_user(uidb64)
        if user is not None and default_token_generator.check_token(user, token):
            if password == confirm_password:
                user.set_password(password)
                user.save()
                self.send_password_reset_confirmation_email(user)
                return Response(
                    {"msg": "Password reset successful. An email confirmation has been sent."},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"msg": "Passwords do not match."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                {"msg": "Invalid password reset link."},
                status=status.HTTP_400_BAD_REQUEST
            )

    def get_user(self, uidb64):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        return user

    def send_password_reset_confirmation_email(self, user):
        mail_subject = "Password Reset Confirmation"
        message = render_to_string("password_reset_confirmation_email.html", {"user": user})
        email = EmailMessage(mail_subject, message, to=[user.email])
        email.content_subtype = "html"
        email.send()

class PasswordChangeAPIView(generics.GenericAPIView):
    serializer_class = PasswordChangeSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user

        new_password = serializer.validated_data['new_password']
        user.set_password(new_password)
        user.save()

        # Send password change confirmation email
        self.send_password_change_confirmation_email(user)

        return Response(
            {"msg": "Password change successful. Please check your email for the confirmation."},
            status=status.HTTP_200_OK
        )

    def send_password_change_confirmation_email(self, user):
        mail_subject = "Password change confirmation"
        message = "Your password has been changed successfully."
        email = EmailMessage(mail_subject, message, to=[user.email])
        email.send()



class ProfileRetrieveUpdateAPIView(generics.RetrieveUpdateAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user.profile

class TokenRefreshView(APIView):
    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh = serializer.validated_data['refresh']
        try:
            token = RefreshToken(refresh)
            access = str(token.access_token)
            return Response({'access': access})
        except Exception as e:
            raise ValidationError(str(e))