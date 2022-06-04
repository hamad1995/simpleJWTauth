from django.contrib.auth import authenticate
from django.http import JsonResponse
from account.serializer import RegistrationSerializer, ChangePasswordSerializer, UpdateUserSerializer, UserPropertiesSerializer, LogoutSerializer, DeleteSerializer
from django.contrib.auth.models import User

#######
from rest_framework import status
from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
# from rest_framework.decorators import api_view, authentication_classes, permission_classes

# Register
# Response: https://gist.github.com/mitchtabian/c13c41fa0f51b304d7638b7bac7cb694
# Url: https://<your-domain>/api/User/register


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer

# LOGIN
# Response: https://gist.github.com/mitchtabian/8e1bde81b3be342853ddfcc45ec0df8a
# URL: http://127.0.0.1:8000/api/User/login


class ObtainAuthTokenView(APIView):

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        context = {}

        email = request.POST.get('username')
        password = request.POST.get('password')
        User = authenticate(email=email, password=password)
        if User:
            try:
                token = Token.objects.get(user=User)
            except Token.DoesNotExist:
                token = Token.objects.create(user=User)
            context['response'] = 'Successfully authenticated.'
            context['id'] = User.id
            context['email'] = email.lower()
            context['token'] = token.key
        else:
            context['response'] = 'Error'
            context['error_message'] = 'Invalid credentials'

        return Response(context)


class ChangePasswordView(generics.UpdateAPIView):

    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer


class UpdateProfileView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = UpdateUserSerializer
    lookup_field = 'id'


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = [IsAuthenticated, ]

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


# class LogoutAllView(APIView):
#     permission_classes = (IsAuthenticated,)

#     def post(self, request):
#         tokens = OutstandingToken.objects.filter(user_id=request.user.id)
#         for token in tokens:
#             t, _ = BlacklistedToken.objects.get_or_create(token=token)

#         return Response(status=status.HTTP_205_RESET_CONTENT)


class UserList(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserPropertiesSerializer
    # permission_classes = [IsAdminUser]


class CurrentUserView(APIView):
    def get(self, request):
        serializer = UserPropertiesSerializer(request.user)
        return Response(serializer.data)



class DelUser(generics.DestroyAPIView):
    queryset = User.objects.all()
    serializer_class = DeleteSerializer
    lookup_field = 'id'


