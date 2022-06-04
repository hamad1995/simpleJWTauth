from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

from . import views

urlpatterns = [
    # register
    path('register/', views.RegisterView.as_view(), name='auth_register'),
    # login
    path('login/', TokenObtainPairView.as_view(), name='login'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # change password
    path('change_password/<int:id>/', views.ChangePasswordView.as_view(),
         name='auth_change_password'),
    # logout
    path('logout/', views.LogoutView.as_view(), name='auth_logout'),
    # get users
    path('get_users/', views.UserList.as_view(), name='get_users'),
    # get one user
    path('current_user/', views.CurrentUserView.as_view(), name='get_user'),
    # update user info
    path('update_profile/<int:id>/', views.UpdateProfileView.as_view(),
         name='auth_update_profile'),
    # del user (not working!)
    path('del_user/<int:id>/', views.DelUser.as_view(), name='del_user'),
    
]
