from django.urls import path
from . import views

urlpatterns = [
    path('reason/', views.analyze_threat_details, name='reason_threat'),
]