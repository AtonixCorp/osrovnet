from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'targets', views.NetworkTargetViewSet)
router.register(r'scans', views.NetworkScanViewSet)
router.register(r'hosts', views.DiscoveredHostViewSet)
router.register(r'vulnerabilities', views.VulnerabilityViewSet)
router.register(r'traffic', views.NetworkTrafficViewSet)
router.register(r'alerts', views.NetworkAlertViewSet)

# Define URL patterns
urlpatterns = [
    # Include router URLs
    path('api/', include(router.urls)),
    
    # Custom API endpoints
    path('api/dashboard/statistics/', views.DashboardStatisticsView.as_view(), name='dashboard-statistics'),
    path('api/dashboard/overview/', views.NetworkOverviewView.as_view(), name='network-overview'),
    path('api/quick-scan/', views.QuickScanView.as_view(), name='quick-scan'),
]