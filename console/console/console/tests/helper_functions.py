import pytest
import secrets
from bs4 import BeautifulSoup as Soup
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http.response import HttpResponse
from django.core.mail import EmailMessage
User = get_user_model()

@pytest.mark.django_db
def create_fake_user(username=None, password=None, email=None):
    if username is None or len(username) < 1:
        username = secrets.token_hex(8)

    if password is None or len(password) < 1:
        password = secrets.token_hex(8)
        
    return User.objects.create_user(username=username, password=password, email=email)

@pytest.mark.django_db
def login(client, session, url: str, username: str, password: str, email: str = None):
    user = create_fake_user(username, password, email)

    res: HttpResponse = client.post(
        url,
        data={"username": username, "password": password}
    )
    client.force_login(user)

    return user

@pytest.mark.django_db
def logout(client, session, url: str):
    res: HttpResponse = client.post(url)
    client.logout()

def get_reset_code(email_obj: EmailMessage) -> int:
    email_html = Soup(email_obj.body, features="html.parser")
    reset_code = int(email_html.find(id = "reset-code").text)
    return reset_code