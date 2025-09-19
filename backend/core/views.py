from django.shortcuts import render
from rest_framework import generics, permissions, views, response, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token

from .serializers import RegistrationSerializer


class RegisterView(generics.CreateAPIView):
	"""Create a new user account."""
	serializer_class = RegistrationSerializer
	permission_classes = [permissions.AllowAny]


class ObtainTokenView(ObtainAuthToken):
	"""Return a token for valid credentials."""
	def post(self, request, *args, **kwargs):
		resp = super().post(request, *args, **kwargs)
		# super returns {'token': '...'}
		return response.Response(resp.data)


class LogoutView(views.APIView):
	permission_classes = [permissions.IsAuthenticated]

	def post(self, request, *args, **kwargs):
		# delete user's token(s)
		try:
			Token.objects.filter(user=request.user).delete()
		except Exception:
			pass
		return response.Response({'detail': 'Logged out'}, status=status.HTTP_200_OK)

