from rest_framework import routers
from . import views

router = routers.DefaultRouter()
router.register(r'models', views.AnomalyModelViewSet, basename='anomalymodel')
router.register(r'training', views.TrainingViewSet, basename='training')
router.register(r'behavior', views.BehavioralViewSet, basename='behavior')

urlpatterns = router.urls
