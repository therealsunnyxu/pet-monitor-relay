import pytest
import django
import sys
from django.conf import settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory
from .. import settings as DefaultSettings

try:
    settings.configure(DefaultSettings)
    django.setup()
except Exception as e:
    print(e, file=sys.stderr)
@pytest.fixture(autouse=True)
def override_auth_backend():
    settings.AUTHENTICATION_BACKENDS = ["jwt_auth.backends.JWTBackend"]

@pytest.fixture(autouse=True)
def override_email_backend():
    settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

@pytest.fixture(autouse=True)
def session():
    factory = RequestFactory()
    request = factory.get("/")
    middleware = SessionMiddleware(get_response=lambda _: None)
    middleware.process_request(request)
    request.session.save()
    return request