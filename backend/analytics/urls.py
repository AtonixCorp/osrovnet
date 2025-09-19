from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import MetricViewSet, EventViewSet, ReportDefinitionViewSet, ScheduledReportViewSet

router = DefaultRouter()
router.register(r'metrics', MetricViewSet, basename='metric')
router.register(r'events', EventViewSet, basename='event')
router.register(r'reports', ReportDefinitionViewSet)
router.register(r'scheduled-reports', ScheduledReportViewSet)

urlpatterns = [
    path('analytics/', include(router.urls)),
]
