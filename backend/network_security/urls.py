from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from . import advanced_views

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'targets', views.NetworkTargetViewSet)
router.register(r'scans', views.NetworkScanViewSet)
router.register(r'hosts', views.DiscoveredHostViewSet)
router.register(r'vulnerabilities', views.VulnerabilityViewSet)
router.register(r'traffic', views.NetworkTrafficViewSet)
router.register(r'alerts', views.NetworkAlertViewSet)

# Advanced features routers
router.register(r'topologies', advanced_views.NetworkTopologyViewSet)
router.register(r'nodes', advanced_views.NetworkNodeViewSet)
router.register(r'ids-rules', advanced_views.IntrusionDetectionRuleViewSet)
router.register(r'traffic-patterns', advanced_views.TrafficPatternViewSet)

# Define URL patterns
urlpatterns = [
    # Include router URLs
    path('api/', include(router.urls)),
    
    # Basic API endpoints
    path('api/dashboard/statistics/', views.DashboardStatisticsView.as_view(), name='dashboard-statistics'),
    path('api/dashboard/overview/', views.NetworkOverviewView.as_view(), name='network-overview'),
    path('api/quick-scan/', views.QuickScanView.as_view(), name='quick-scan'),
    
    # Advanced API endpoints
    path('api/ids/dashboard/', advanced_views.IntrusionDetectionDashboardView.as_view(), name='ids-dashboard'),
    path('api/ids/control/', advanced_views.IDSControlView.as_view(), name='ids-control'),
    path('api/advanced-scan/', advanced_views.AdvancedScanView.as_view(), name='advanced-scan'),
    path('api/analytics/', advanced_views.NetworkAnalyticsView.as_view(), name='network-analytics'),
]