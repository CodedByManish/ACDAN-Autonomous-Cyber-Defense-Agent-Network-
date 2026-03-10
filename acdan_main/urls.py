from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/detection/', include('apps.detection.urls')),
    path('api/reasoning/', include('apps.reasoning.urls')),
    path('api/response/', include('apps.response.urls')),
]