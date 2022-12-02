from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from users import views
from users.serializers import CustomJWTSerializer

urlpatterns = [
    path('register/', views.CreateUserView.as_view()),
    path('update/', views.UpdateUserView.as_view()),

    path('profile/', views.UpdateProfileView.as_view()),
    path('token/', TokenObtainPairView.as_view(serializer_class=CustomJWTSerializer),
         name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify-account/<str:base64>/<str:token>', views.VerifyAccountView().as_view(),
         name="verify-account"),

    path('forgot-password', views.ForgotPasswordView().as_view(),
         name="forgot-password"),
    path('reset-password/<str:base64>/<str:token>', views.ResetPasswordView().as_view(),
         name="reset-password"),
    path('change-password', views.UpdatePassword.as_view(), name="change-password"),

]
