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
CHANGE_EMAIL_REQUEST_URL = reverse("change-email-request")
CHANGE_EMAIL_CODE_URL = reverse("change-email-code")

GOOD_EMAIL = "goodemail@fakemail.com"
BETTER_EMAIL = "betteremail@fakemail.com"
BAD_EMAIL = "bademail"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass"

CHANGE_EMAIL_REQUEST_PARAMS = "old_email,new_email,password,valid"
change_email_request_combos = []
for old_email in [GOOD_EMAIL, BAD_EMAIL, ""]:
    for new_email in [BETTER_EMAIL, BAD_EMAIL, ""]:
        for password in [TEST_PASSWORD, ""]:
            temp_test_case = (
                old_email, 
                new_email, 
                password, 
                old_email == GOOD_EMAIL and new_email == BETTER_EMAIL and password == TEST_PASSWORD
            )
            change_email_request_combos.append(temp_test_case)

@pytest.mark.django_db
def test_change_email_refuses_when_not_logged_in(client, session):
    create_fake_user(TEST_USERNAME, TEST_PASSWORD, GOOD_EMAIL)

    res: HttpResponse = client.post(
        CHANGE_EMAIL_REQUEST_URL,
        data={"old_email": GOOD_EMAIL, "new_email": BETTER_EMAIL, "password": TEST_PASSWORD},
    )

    assert (res.status_code == 200) is False, "User should not be able to change email if not logged in"

@pytest.mark.django_db
def test_change_email_refuses_when_no_email(client, session):
    blank_email = ""
    user = login(client, session, LOGIN_URL,  TEST_USERNAME, TEST_PASSWORD, blank_email)

    res: HttpResponse = client.post(
        CHANGE_EMAIL_REQUEST_URL,
        data={"old_email": blank_email, "new_email": blank_email, "password": TEST_PASSWORD},
    )
    
    assert (res.status_code == 200) is False, "Blank emails should not trigger email reset"

    res: HttpResponse = client.post(
        CHANGE_EMAIL_REQUEST_URL,
        data={"old_email": blank_email, "new_email": BETTER_EMAIL, "password": TEST_PASSWORD},
    )
    
    assert (res.status_code == 200) is False, "Change email request should not process if user doesn't have an email\n(this is for future routes or for admins to change)"

@pytest.mark.parametrize(CHANGE_EMAIL_REQUEST_PARAMS, change_email_request_combos)
@pytest.mark.django_db
def test_change_email_request_goes_into_db(client, session, old_email: str, new_email: str, password: str, valid: bool):
    user = login(client, session, LOGIN_URL, TEST_USERNAME, TEST_PASSWORD, old_email)

    res = client.post(
        CHANGE_EMAIL_REQUEST_URL,
        data={"old_email": old_email, "new_email": new_email, "password": password}
    )
    assert (res.status_code == 200) is valid, f"Email request expected {valid}, got {res.status_code == 200}"

    assert (len(mail.outbox) >= 1) is valid, f"Verification code sent: expected {valid}, got {len(mail.outbox) >= 1}"

    actual_reset_request = None
    try:
        actual_reset_request = models.EmailChangeRequest.objects.get(user=user)
    except Exception:
        actual_reset_request = None
    assert (actual_reset_request is not None) is valid, f"Email request in database: expected {valid}, got {actual_reset_request is not None}"
    logout(client, session, LOGOUT_URL)

@pytest.mark.django_db
def test_email_change_code_refuses_if_not_logged_in(client, session):
    user = login(client, session, LOGIN_URL, TEST_USERNAME, TEST_PASSWORD, GOOD_EMAIL)

    res = client.post(
        CHANGE_EMAIL_REQUEST_URL,
        data={"old_email": GOOD_EMAIL, "new_email": BETTER_EMAIL, "password": TEST_PASSWORD}
    )
    
    
    email_obj = mail.outbox[0]
    reset_code = get_reset_code(email_obj)
    actual_reset_request = models.EmailChangeRequest.objects.get(user=user)
    actual_code = actual_reset_request.code
    assert (reset_code > 0), "No reset code in email"
    assert (reset_code == actual_code), f"Database code {actual_code} does not match email code {reset_code}"

    logout(client, session, LOGOUT_URL)
    actual_reset_request = models.EmailChangeRequest.objects.get(user=user)
    print(actual_reset_request.email_sent_at, actual_reset_request.expires_at)

    assert (actual_reset_request.is_expired()), "Database did not properly force-expire request when logged out"
    res = client.post(
        CHANGE_EMAIL_CODE_URL,
        data={"code": reset_code}
    )

    assert (res.status_code == 200) is False, "Code should not be accepted if logged out"

@pytest.mark.django_db
def test_email_change_code(client, session):
    user = login(client, session, LOGIN_URL, TEST_USERNAME, TEST_PASSWORD, GOOD_EMAIL)

    res = client.post(
        CHANGE_EMAIL_REQUEST_URL,
        data={"old_email": GOOD_EMAIL, "new_email": BETTER_EMAIL, "password": TEST_PASSWORD}
    )
    
    actual_reset_request = models.EmailChangeRequest.objects.get(user=user)
    assert actual_reset_request.new_email == BETTER_EMAIL, f"Reset request expected to have {BETTER_EMAIL}, instead got {actual_reset_request.new_email}"

    email_obj = mail.outbox[0]
    reset_code = get_reset_code(email_obj)
    
    res = client.post(
        CHANGE_EMAIL_CODE_URL,
        data={"code": reset_code}
    )

    # get the reference to the user again because the old one is actually a copy
    user = User.objects.get_by_natural_key(TEST_USERNAME)
    assert (res.status_code == 200) is True, f"Code should not have been rejected for: {str(res.content)}"
    assert user.email != GOOD_EMAIL and user.email == BETTER_EMAIL, f"Email should have changed from {GOOD_EMAIL} to {BETTER_EMAIL}, instead got changed to {user.email}"

