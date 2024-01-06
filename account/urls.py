from django.urls import path
from account.views import UserRegistrationView,UserLoginView,UserProfileView,UserChangePasswordView,\
    SendPasswordResetEmailView,UserPasswordResetView,PostView,AddPostView,SearchUserView,ProfileView,FollowView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("register/",UserRegistrationView.as_view(),name='register'),
    path("login/", UserLoginView.as_view(), name='login'),
    path("profile/",UserProfileView.as_view(),name='profile'),
    path("change-password/",UserChangePasswordView.as_view(),name='change-password'),
    path("send-reset-password-email/",SendPasswordResetEmailView.as_view(),name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/',UserPasswordResetView.as_view(),name="reset-password"),
    path('token/refresh/',TokenRefreshView.as_view(),name="refresh-token"),
    path('posts/',PostView.as_view(),name='post'),
    path('add-post/',AddPostView.as_view(),name='add-post'),
    path('users/',SearchUserView.as_view()),
    path('user/<int:pk>', ProfileView.as_view()),
    path('follow/<int:pk>',FollowView.as_view()),

]