"""
URL configuration for console project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path
from .auth_endpoint import views as AuthViews

urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", AuthViews.login_handler, name="login"),
    path("logout/", AuthViews.logout_handler, name="logout"),
    path("token/refresh", AuthViews.refresh_access_token_handler, name="token-refresh"),
    path("public_key", AuthViews.get_public_key_handler, name="public-key"),
    path("token/access", AuthViews.validate_access_token_handler, name="token-access"),
]
