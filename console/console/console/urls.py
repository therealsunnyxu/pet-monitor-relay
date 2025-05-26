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
    # Left the default Django frontend in just in case
    path("admin/", admin.site.urls),

    # Auth
    path("auth/login", AuthViews.login_handler, name="login"),
    path("auth/logout", AuthViews.logout_handler, name="logout"),

    # Tokens for APIs that depend on this one for auth
    path("auth/public_key", AuthViews.get_public_key_handler, name="public-key"),
    path("token/refresh", AuthViews.refresh_access_token_handler, name="token-refresh"),
    path("token/csrf", AuthViews.csrf_token_handler, name="token-csrf"),
    path("token/access", AuthViews.validate_access_token_handler, name="token-access"),

    # Email and password reset routes
    path("auth/login/forgot-password",AuthViews.forgot_password_request_handler, name="forgot-password-request"),
    path("auth/account/password",AuthViews.change_password_request_handler, name="change-password-request"),
    path("auth/account/email",AuthViews.change_email_request_handler, name="change-email-request"),
    path("auth/login/forgot-password/code",AuthViews.forgot_password_code_handler, name="forgot-password-code"),
    path("auth/login/forgot-password/change",AuthViews.forgot_password_change_handler, name="forgot-password-change"),
    path("auth/account/password/code",AuthViews.change_email_code_handler, name="change-email-code"),
    path("auth/account/email/code",AuthViews.change_password_code_handler, name="change-password-code"),
]
