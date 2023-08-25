from rest_framework import serializers
from account.models import User
from rest_framework.exceptions import ValidationError
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from account.utils.email import send_password_reset_email

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs={
            'password': {'write_only': True}
        }
    
    # validate password and confirm password with registration
    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("password and confirm password doesn't match")
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name']

class UserChangePasswordSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['password','password2']
    

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("password and confirm password doesn't match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
          user1 = User.objects.get(email=email)
          uid = urlsafe_base64_encode(force_bytes(user1.id))
          token = default_token_generator.make_token(user1)
          link = 'http://localhost:8000/api/user/reset/'+uid+'/'+token
          send_password_reset_email(user1,link)
          return attrs
        else:
            raise  ValidationError("you are not a registered user")
        
class UserPasswordResetSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['password','password2']
    

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')
        if password != password2:
            raise serializers.ValidationError("password and confirm password doesn't match")
        pk = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=pk)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise ValidationError('Token is not valid or expired')
        user.set_password(password)
        user.save()
        return attrs