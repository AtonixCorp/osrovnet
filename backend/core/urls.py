from django.urls import path
from . import views

urlpatterns = [
    # Registration endpoint used by frontend
    path('api/auth/register/', views.RegisterView.as_view(), name='api-auth-register'),
    path('api/auth/token/', views.ObtainTokenView.as_view(), name='api-auth-token'),
    path('api/auth/logout/', views.LogoutView.as_view(), name='api-auth-logout'),
    # keep placeholder for future core urls
]