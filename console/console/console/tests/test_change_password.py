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
CHANGE_PASSWORD_REQUEST_URL = reverse("change-password-request")
CHANGE_PASSWORD_CODE_URL = reverse("change-password-code")

TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass"
NEW_PASSWORD = "testpass123"
TEST_EMAIL =  "testemail@fakemail.com"

@pytest.mark.django_db
def test_change_password_refuses_when_not_logged_in(client, session):
    create_fake_user(TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL)

    res: HttpResponse = client.post(
        CHANGE_PASSWORD_REQUEST_URL,
        data={"old_password": TEST_PASSWORD, "new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD}
    )

    assert (res.status_code == 200) is False, "User should not be able to change password if not logged in"

@pytest.mark.django_db
def test_change_password_refuses_when_no_email(client, session):
    login(client, session, LOGIN_URL, TEST_USERNAME, TEST_PASSWORD, "")
    
    res: HttpResponse = client.post(
        CHANGE_PASSWORD_REQUEST_URL,
        data={"old_password": TEST_PASSWORD, "new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD}
    )

    assert (res.status_code == 401) is True, "User is supposed to ask an admin to change their password (and set an email) if they have no email"


@pytest.mark.parametrize("old_password,new_password,confirm_new_password,valid",
    [
        ("", "", "", False), 
        ("", TEST_PASSWORD, "", False),  # no confirm
        ("", "", TEST_PASSWORD, False),  # confirm but no new password
        ("", TEST_PASSWORD, NEW_PASSWORD, False),  # confirm does not match
        ("", NEW_PASSWORD, TEST_PASSWORD, False),  # confirm does not match
        ("", TEST_PASSWORD, TEST_PASSWORD, False), 
        (TEST_PASSWORD, "", "", False), 
        (TEST_PASSWORD, TEST_PASSWORD, "", False),  # no confirm
        (TEST_PASSWORD, "", TEST_PASSWORD, False),  # confirm but no new password
        (TEST_PASSWORD, TEST_PASSWORD, NEW_PASSWORD, False),  # confirm does not match
        (TEST_PASSWORD, NEW_PASSWORD, TEST_PASSWORD, False),  # confirm does not match
        (TEST_PASSWORD, TEST_PASSWORD, TEST_PASSWORD, False),  # same password as old one
        (TEST_PASSWORD, NEW_PASSWORD, NEW_PASSWORD, True) # good password
    ])
@pytest.mark.django_db
def test_change_password_request_goes_into_db(client, session, old_password: str, new_password: str, confirm_new_password: str, valid: bool):
    user = login(client, session, LOGIN_URL, TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL)
    
    res: HttpResponse = client.post(
        CHANGE_PASSWORD_REQUEST_URL,
        data={"old_password": old_password, "new_password": new_password, "confirm_new_password": confirm_new_password}
    )

    assert (res.status_code == 200) is valid, f"Change password expected {valid}, got {res.status_code}"
    assert (len(mail.outbox) >= 1) is valid, f"Verification code sent: expected {valid}, got {len(mail.outbox) >= 1}"
    actual_reset_request = None
    try:
        actual_reset_request = models.PasswordChangeRequest.objects.get(user=user)
    except Exception:
        actual_reset_request = None
    assert (actual_reset_request is not None) is valid, f"Email request in database: expected {valid}, got {actual_reset_request is not None}"
    logout(client, session, LOGOUT_URL)

@pytest.mark.django_db
def test_password_change_code_refuses_if_not_logged_in(client, session):
    user = login(client, session, LOGIN_URL, TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL)

    res: HttpResponse = client.post(
        CHANGE_PASSWORD_REQUEST_URL,
        data={"old_password": TEST_PASSWORD, "new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD}
    )
    
    
    email_obj = mail.outbox[0]
    reset_code = get_reset_code(email_obj)
    actual_reset_request = models.PasswordChangeRequest.objects.get(user=user)
    actual_code = actual_reset_request.code
    assert (reset_code > 0), "No reset code in email"
    assert (reset_code == actual_code), f"Database code {actual_code} does not match email code {reset_code}"

    logout(client, session, LOGOUT_URL)
    actual_reset_request = models.PasswordChangeRequest.objects.get(user=user)
    print(actual_reset_request.email_sent_at, actual_reset_request.expires_at)

    assert (actual_reset_request.is_expired()), "Database did not properly force-expire request when logged out"
    res = client.post(
        CHANGE_PASSWORD_CODE_URL,
        data={"code": reset_code}
    )

    assert (res.status_code == 200) is False, "Code should not be accepted if logged out"

@pytest.mark.django_db
def test_password_change_code(client, session):
    user = login(client, session, LOGIN_URL, TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL)

    res: HttpResponse = client.post(
        CHANGE_PASSWORD_REQUEST_URL,
        data={"old_password": TEST_PASSWORD, "new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD}
    )
    
    actual_reset_request = models.PasswordChangeRequest.objects.get(user=user)
    assert actual_reset_request.new_password == NEW_PASSWORD, f"Reset request expected to have {NEW_PASSWORD}, instead got {actual_reset_request.new_password}"

    email_obj = mail.outbox[0]
    reset_code = get_reset_code(email_obj)
    
    res = client.post(
        CHANGE_PASSWORD_CODE_URL,
        data={"code": reset_code}
    )

    # get the reference to the user again because the old one is actually a copy
    user = User.objects.get_by_natural_key(TEST_USERNAME)
    assert (res.status_code == 200) is True, f"Code should not have been rejected for: {str(res.content)}"
    assert user.check_password(TEST_PASSWORD) == False, f"User's password is still {TEST_PASSWORD}"
    assert user.check_password(NEW_PASSWORD) == True, f"User's password isn't {NEW_PASSWORD}"