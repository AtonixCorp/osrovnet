from django.urls import path
from . import views

urlpatterns = [
    path('api/postquantum/algorithms/', views.AlgorithmListView.as_view(), name='pqc-algorithms'),
    path('api/postquantum/generate/', views.GenerateKeyView.as_view(), name='pqc-generate'),
]
