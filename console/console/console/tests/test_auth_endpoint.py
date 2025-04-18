import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory
from django.urls import reverse
from django.http.response import HttpResponse
from django.conf import settings


@pytest.fixture(autouse=True)
def override_auth_backend(settings):
    settings.AUTHENTICATION_BACKENDS = ["jwt_auth.backends.JWTBackend"]


@pytest.mark.django_db
def test_get_public_key(client):
    url: str = reverse("public-key")
    res: HttpResponse = client.get(url)
    assert res.status_code == 200
    assert res.headers.get("Content-Type") == "application/x-pem-file"


@pytest.mark.django_db
def test_logout_with_no_user(client):
    url: str = reverse("logout")
    res: HttpResponse = client.post(url)
    assert res.status_code == 200


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
def test_login(client, useUsername, usePassword, valid):
    url: str = reverse("login")

    User = get_user_model()
    username = "testuser"
    password = "testpass"
    user = User.objects.create_user(username=username, password=password)
    factory = RequestFactory()
    request = factory.get("/")
    middleware = SessionMiddleware(get_response=lambda x: None)
    middleware.process_request(request)
    request.session.save()

    assert user is not None
    if not useUsername:
        username = ""
    if not usePassword:
        password = ""

    res: HttpResponse = client.post(
        url,
        data={"username": username, "password": password},
    )
    assert (res.status_code == 200) is valid
