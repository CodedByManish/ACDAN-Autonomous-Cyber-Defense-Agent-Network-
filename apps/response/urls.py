from django.urls import path
from . import views

urlpatterns = [
    path('execute/', views.decide_response, name='execute_response'),
]