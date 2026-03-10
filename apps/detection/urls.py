from django.urls import path
from . import views

urlpatterns = [
    path('analyze/', views.detect_threat, name='detect_threat'),
]