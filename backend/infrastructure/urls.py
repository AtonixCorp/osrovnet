"""
Infrastructure Resilience API URLs
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'components', views.InfrastructureComponentViewSet)
router.register(r'metrics', views.HealthMetricViewSet)
router.register(r'alerts', views.SystemAlertViewSet)
router.register(r'backup-jobs', views.BackupJobViewSet)
router.register(r'backup-executions', views.BackupExecutionViewSet)
router.register(r'performance-metrics', views.PerformanceMetricViewSet)
router.register(r'dr-plans', views.DisasterRecoveryPlanViewSet)
router.register(r'dr-tests', views.DisasterRecoveryTestViewSet)
router.register(r'maintenance', views.MaintenanceWindowViewSet)

urlpatterns = [
    path('api/infrastructure/', include(router.urls)),
    path('api/infrastructure/overview/', views.system_overview, name='system-overview'),
]