from django.contrib import admin
from django.urls import path
from ninja import NinjaAPI
from apps.detection.api import router as detection_router
# from apps.reasoning.api import router as reasoning_router # Uncomment as you build
# from apps.response.api import router as response_router   # Uncomment as you build

# Initialize Ninja API
api = NinjaAPI(
    title="ACDAN API",
    version="1.0.0",
    description="Autonomous Cyber Defense Agent Network API"
)

# Add Routers
api.add_router("/detection", detection_router)
# api.add_router("/reasoning", reasoning_router)
# api.add_router("/response", response_router)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', api.urls), 
]