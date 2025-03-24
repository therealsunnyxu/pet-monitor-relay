import pytest
from django.contrib.auth import get_user_model, authenticate
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory
from django.conf import settings


@pytest.fixture(autouse=True)
def override_auth_backend(settings):
    settings.AUTHENTICATION_BACKENDS = ["jwt_auth.backends.JWTBackend"]


@pytest.mark.parametrize(
    "useUsername,usePassword,valid",
    [
        (False, False, False),
        (False, True, False),
        (True, False, False),
        (True, True, True),
    ],
)
@pytest.mark.django_db
def test_jwt_backend_no_session(useUsername, usePassword, valid):
    User = get_user_model()
    username = "testuser"
    password = "testpass"
    user = User.objects.create_user(username=username, password=password)
    factory = RequestFactory()
    request = factory.get("/")
    middleware = SessionMiddleware()
    middleware.process_request(request)
    request.session.save()
    if not useUsername:
        username = ""
    if not usePassword:
        password = ""
    authed_user = authenticate(request, username=username, password=password)
    assert (authed_user is None) is not valid

    if authed_user is None:
        user.delete()
        return

    assert request.session.get("refresh_token") is not None
    assert request.session.get("access_token") is not None
    if authed_user is not None:
        authed_user.delete()
