import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.urls import reverse
from django.http.response import HttpResponse
from .helper_functions import create_fake_user, login, logout, get_reset_code
from ..auth_endpoint import models

User = get_user_model()
LOGIN_URL = reverse("login")
LOGOUT_URL = reverse("logout")
FORGOT_PASSWORD_REQUEST_URL = reverse("forgot-password-request")
FORGOT_PASSWORD_CODE_URL = reverse("forgot-password-code")
FORGOT_PASSWORD_CHANGE_URL = reverse("forgot-password-change")

TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass"
NEW_PASSWORD = "testpass123"
TEST_EMAIL =  "testemail@fakemail.com"

FAKE_CODE = 42069

@pytest.mark.parametrize("email,valid",
    [
        ("", False), # no email in field
        ("fake@fakemail.com", False), # email of an unregistered user
        (TEST_EMAIL, True) # the user's actual email
    ])
@pytest.mark.django_db
def test_forgot_password_goes_into_db(client, session, email: str, valid: bool):
    user = create_fake_user(TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL)

    res: HttpResponse = client.post(
        FORGOT_PASSWORD_REQUEST_URL,
        data={"email": email}
    )

    has_cookie = "reset_pw_uuid" in res.cookies.keys()

    assert (has_cookie) is valid, f"Expected HTTP only cookie: {valid}, got {has_cookie}"

    assert (len(mail.outbox) >= 1) is valid, f"Verification code sent: expected {valid}, got {len(mail.outbox) >= 1}"
    actual_reset_request = None
    try:
        actual_reset_request = models.ForgotPasswordRequest.objects.get(user=user)
    except Exception:
        actual_reset_request = None
    assert (actual_reset_request is not None) is valid, f"Email request in database: expected {valid}, got {actual_reset_request is not None}"
    
@pytest.mark.django_db
def test_forgot_password_code(client, session):
    user = create_fake_user(TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL)

    res: HttpResponse = client.post(
        FORGOT_PASSWORD_REQUEST_URL,
        data={"email": TEST_EMAIL}
    )

    email_obj = mail.outbox[0]
    reset_code = get_reset_code(email_obj)

    res = client.post(
        FORGOT_PASSWORD_CODE_URL,
        data={"code": ""}
    )

    assert (res.status_code == 200) is False, f"Code should have been rejected for: {str(res.content)}"

    res = client.post(
        FORGOT_PASSWORD_CODE_URL,
        data={"code": FAKE_CODE}
    )

    assert (res.status_code == 200) is False, f"Code should have been rejected for: {str(res.content)}"

    res = client.post(
        FORGOT_PASSWORD_CODE_URL,
        data={"code": reset_code}
    )

    assert (res.status_code == 200) is True, f"Code should not have been rejected for: {str(res.content)}"

@pytest.mark.django_db
def test_forgot_password_change_cancellation(client, session):
    user = create_fake_user(TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL)

    res: HttpResponse = client.post(
        FORGOT_PASSWORD_REQUEST_URL,
        data={"email": TEST_EMAIL}
    )

    reset_pw_uuid = res.cookies.get("reset_pw_uuid")

    email_obj = mail.outbox[0]
    reset_code = get_reset_code(email_obj)

    res = client.post(
        FORGOT_PASSWORD_CODE_URL,
        data={"code": reset_code}
    )

    res = client.post(
        FORGOT_PASSWORD_CHANGE_URL,
        data={"cancelled": "1"}
    )
    assert (res.status_code == 200) is True, f"Forgot password cancellation should not have been rejected for: {str(res.content)}"

    res = client.post(
        FORGOT_PASSWORD_CHANGE_URL,
        data={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD}
    )
    assert (res.status_code == 200) is False, f"Cancelled request should not have gone through: {str(res.content)}"

@pytest.mark.django_db
def test_forgot_password_change(client, session):
    user = create_fake_user(TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL)

    res: HttpResponse = client.post(
        FORGOT_PASSWORD_REQUEST_URL,
        data={"email": TEST_EMAIL}
    )

    reset_pw_uuid = res.cookies.get("reset_pw_uuid")

    email_obj = mail.outbox[0]
    reset_code = get_reset_code(email_obj)

    res = client.post(
        FORGOT_PASSWORD_CODE_URL,
        data={"code": reset_code}
    )

    res = client.post(
        FORGOT_PASSWORD_CHANGE_URL,
        data={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD}
    )

    user = User.objects.get_by_natural_key(TEST_USERNAME)
    assert (res.status_code == 200) is True, f"Request should not have been rejected for: {str(res.content)}"
    assert user.check_password(TEST_PASSWORD) == False, f"User's password is still {TEST_PASSWORD}"
    assert user.check_password(NEW_PASSWORD) == True, f"User's password isn't {NEW_PASSWORD}"


