from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,\
    UserChangePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer,\
    PostSerializer,AddPostSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser,FormParser
from .models import Post,User
from django.core.paginator import Paginator
from  rest_framework import filters


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


# Create your views here.
class UserRegistrationView(APIView):
    def post(self,request,format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({"message":"registration successful","token":token},status=status.HTTP_201_CREATED)
        return Response(serializer.errors)


class UserLoginView(APIView):
    def post(self,request,format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email,password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response(token,status=status.HTTP_200_OK)
            else:
                return Response({"errors":{'non_field_errors':['email or password is not valid']}},
                                status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request,format=None):
        serializer = UserProfileSerializer(request.user)
        # if serializer.is_valid():
        return Response(serializer.data,status=status.HTTP_200_OK)
        # return Response({"message":"user Profile"},status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request,format=None):
        serializer = UserChangePasswordSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"message":"password changed successfully"},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(APIView):
    def post(self,request,format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message":"password reset link sent.Please check your email"},status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
    def post(self,request,uid,token,format=None):
        serializer = UserPasswordResetSerializer(data=request.data,
                                                 context={'uid':uid,'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({"message":"password rest successfully"})


class PostView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        user = request.user
        following_users = user.following.all()
        posts = Post.objects.filter(user__in=following_users) | Post.objects.filter(user=user)
        posts = posts.order_by('-id')
        # posts = Post.objects.all()
        page = request.query_params.get('page',default=1)
        print(page)
        paginator = Paginator(posts,per_page=5)
        try:
            posts = paginator.page(number=page)
        except:
            posts = []
        serializer = PostSerializer(posts,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)


class AddPostView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser,FormParser]
    def post(self,request,format=None):
        serializer = AddPostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response(serializer.errors)

class SearchUserView(APIView):
    def get(self,request,format=None):
        users = User.objects.all()
        search = request.query_params.get('search')
        if search:
            users = users.filter(name__contains=search)
        serializer = UserProfileSerializer(users,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

class ProfileView(APIView):
    def get(self,request,pk,format=None):
        user = User.objects.get(id=pk)
        serializer = UserProfileSerializer(user)
        return Response(serializer.data,status=status.HTTP_200_OK)


class FollowView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request,pk,format=None):
        user = request.user
        flu = User.objects.get(id=pk)
        user.following.add(flu)
        user.save()
        serializer = UserProfileSerializer(flu)
        return Response(serializer.data)

    def delete(self, request, pk, format=None):
        user = request.user
        flu = User.objects.get(id=pk)
        user.following.remove(flu)
        user.save()
        serializer = UserProfileSerializer(flu)
        return Response(serializer.data)
