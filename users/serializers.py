from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from users.models import Profile

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'password', 'is_admin', 'is_active', 'is_agent', 'username']
        extra_kwargs = {'password': {'write_only': True}}


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'password', 'username']

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username']
        )
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            if user is None:
                raise serializers.ValidationError({"msg":'Wrong Email or password.'})
        else:
            raise serializers.ValidationError({"msg":'Must include "email" and "password".'})

        attrs['user'] = user
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, data):
        token = data.get('token')

        if token:
            try:
                user = User.objects.get(activation_token=token)
                user.is_active = True
                user.activation_token = None
                user.save()
                data['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid verification token.")
        else:
            raise serializers.ValidationError("Token is required.")

        return data


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        email = data.get('email')

        if email:
            try:
                user = User.objects.get(email=email)
                data['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError("User not found.")
        else:
            raise serializers.ValidationError("Email is required.")

        return data


class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128)
    confirm_password = serializers.CharField(max_length=128)


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    new_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if current_password and new_password:
            if user.check_password(current_password):
                user.set_password(new_password)
                user.save()
            else:
                raise serializers.ValidationError("Incorrect current password.")
        else:
            raise serializers.ValidationError("Current password and new password are required.")

        return data
class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['id', 'bio', 'phone_number', 'profile_picture']