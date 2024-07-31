from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth import logout
from .serializers import UserSerializer
from .models import CustomUser

class UserRegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]  # Allow any user to access this view

class UserLoginView(generics.GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]  # Allow any user to access this view

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        if not (username or email) or not password:
            return Response({'error': 'Username or email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        user = None
        if email:
            user = CustomUser.objects.filter(email=email).first()
        else:
            user = CustomUser.objects.filter(username=username).first()

        if user and user.password == password:  # Direct comparison for plain text password
            # Generate token
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

class UserLogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            # Delete the user's token
            token = Token.objects.filter(user=user).first()
            if token:
                token.delete()
            # Perform logout
            logout(request)
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
