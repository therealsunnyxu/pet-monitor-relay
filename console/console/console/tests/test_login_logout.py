import pytest
import secrets
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.core import mail
from django.test import RequestFactory
from django.urls import reverse
from django.http.response import HttpResponse
from django.conf import settings
from .helper_functions import create_fake_user

User = get_user_model()
LOGIN_URL = reverse("login")
LOGOUT_URL = reverse("logout")
PUBLIC_KEY_URL = reverse("public-key")

@pytest.mark.django_db
def test_get_public_key(client, session):
    res: HttpResponse = client.get(PUBLIC_KEY_URL)
    
    assert res.status_code == 200
    assert res.headers.get("Content-Type") == "application/x-pem-file", "Content type is not a PEM file"


@pytest.mark.django_db
def test_logout_with_no_user(client, session):
    res: HttpResponse = client.post(LOGOUT_URL)
    
    assert res.status_code == 200, "User did not get logged out"

test_username = "testuser"
test_password = "testpass"
@pytest.mark.parametrize(
    "username,password,valid",
    [
        ("", "", False),
        ("", test_password, False),
        (test_username, "", False),
        (test_username, test_password, True),
    ],
)
@pytest.mark.django_db
def test_login(client, session, username: str, password: str, valid: bool):
    user = create_fake_user(username, password)

    assert user is not None, "User creation failed"
    if not username:
        username = ""
    if not password:
        password = ""

    res: HttpResponse = client.post(
        LOGIN_URL,
        data={"username": username, "password": password},
    )
    
    assert (res.status_code == 200) is valid, "User did not get logged in"
    if res.status_code == 200:
        client.force_login(user)

    res: HttpResponse = client.post(
        LOGOUT_URL
    )
    
    assert not hasattr(session, "user"), "User did not get logged out"
