from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import HuntJobViewSet, AttackSimulationViewSet, TamperProofLogViewSet

router = DefaultRouter()
router.register(r'hunts', HuntJobViewSet)
router.register(r'simulations', AttackSimulationViewSet)
router.register(r'tamper-logs', TamperProofLogViewSet)

urlpatterns = [
    path('advanced/', include(router.urls)),
]
