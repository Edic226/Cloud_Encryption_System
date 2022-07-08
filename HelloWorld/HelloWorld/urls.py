from django.urls import path, include
from django.contrib import admin

from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index),
    path('user/', include('user_system.urls')),
    path('encry/', include('encry_system.urls')),
]
