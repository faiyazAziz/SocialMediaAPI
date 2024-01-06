from rest_framework import serializers
from .models import User,Post
from django.utils.encoding import  smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.conf import settings
import datetime
from django.utils import timezone
from drf_extra_fields.fields import Base64ImageField
# from .utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    # we are writing because we need confirm password field in our registration Request
    password2 = serializers.CharField(style={'input_type':'password'})

    class Meta:
        model = User
        fields = ['email','name','password','password2','tc']
        extra_kwargs = {
            'password':{'write_only':True}
        }

    def validate(self,attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password!=password2:
            raise serializers.ValidationError('password and confirm password not matched')
        return attrs

    def create(self,validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=200)
    class Meta:
        model = User
        fields = ['email','password']


class UserProfileSerializer(serializers.ModelSerializer):
    following = serializers.PrimaryKeyRelatedField(many=True,read_only=True)
    follower = serializers.PrimaryKeyRelatedField(many=True,read_only=True)
    class Meta:
        model = User
        fields = ['id','email','name','bio','profilePic','following','follower']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style=
                {'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255, style=
                {'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password','password2']

    def validate(self,attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password!=password2:
            raise serializers.ValidationError("password and Confirm Password does not match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self,attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            body = 'Click the Link to Reset Your Password ' + link

            subject = "Reset Your Password"
            message = body
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [email,]
            # to_email:user.email
            # Util.send_email(data)
            send_mail(subject,message,email_from,recipient_list)

            # subject = 'welcome to GFG world'
            # message = f'Hi {email}, thank you for registering in geeksforgeeks.'
            # email_from = settings.EMAIL_HOST_USER
            # recipient_list = [email,]
            # send_mail(subject, message, email_from, recipient_list)
            return attrs
        else:
            raise serializers.ValidationError("You are not a registered")


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style=
    {'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style=
    {'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("password and Confirm Password does not match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError("token is not Valid or Expired")


class PostSerializer(serializers.ModelSerializer):
    user = UserProfileSerializer()
    time = serializers.SerializerMethodField()
    class Meta:
        model = Post
        fields = ['id','user','description','media','time_added','time']

    def get_time(self,obj):
        up_time = obj.time_added
        cu_time = timezone.now()
        time_diff = cu_time - up_time
        time_diff = time_diff.total_seconds()
        ans = ''
        if round(time_diff/31536000) != 0 :
            ans = str(round(time_diff/31536000)) + ' year ago'
        elif round(time_diff/86400) != 0:
            ans = str(round(time_diff/86400)) + ' day ago'
        elif round(time_diff/3600) != 0:
            ans = str(round(time_diff / 3600)) + ' hours ag'
        elif round(time_diff/60) != 0:
            ans = str(round(time_diff/60)) + ' min ago'
        else :
            ans = str(round(time_diff)) + ' sec ago'
        return ans

class AddPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = ['id','description','media','time_added']

