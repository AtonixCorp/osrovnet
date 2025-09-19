from django.urls import path
from . import views

urlpatterns = [
    path('api/quantum-inspired/techniques/', views.TechniqueListView.as_view(), name='qi-techniques'),
    path('api/quantum-inspired/run/', views.RunSimulationView.as_view(), name='qi-run'),
]
