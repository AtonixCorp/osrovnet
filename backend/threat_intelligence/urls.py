from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'threat-feeds', views.ThreatFeedViewSet)
router.register(r'iocs', views.IndicatorOfCompromiseViewSet)
router.register(r'threat-actors', views.ThreatActorViewSet)
router.register(r'threat-matches', views.ThreatMatchViewSet)
router.register(r'threat-hunts', views.ThreatHuntViewSet)

# Define URL patterns
urlpatterns = [
    # Include router URLs
    path('api/threat-intel/', include(router.urls)),
    
    # Custom API endpoints
    path('api/threat-intel/dashboard/', views.ThreatIntelligenceDashboardView.as_view(), name='threat-intel-dashboard'),
    path('api/threat-intel/ioc-management/', views.IOCManagementView.as_view(), name='ioc-management'),
]