import secrets
import sys
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import AnonymousUser
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.middleware.csrf import get_token
from django.template.loader import render_to_string
from django.views.decorators.http import require_http_methods as method
from . import forms, models
from jwt_auth.backends import JWTBackend

auth_backend = JWTBackend()
UserModel = get_user_model()

@method(["POST"])
def login_handler(request: HttpRequest):
    form = forms.LoginForm(request.POST)
    user: AbstractBaseUser = None
    if not form.is_valid():
        user = authenticate(
            request,
            username=None,
            password=None,
            remember_me=form.cleaned_data.get("remember_me"),
        )
    else:
        user = authenticate(
            request,
            username=form.cleaned_data.get("username"),
            password=form.cleaned_data.get("password"),
            remember_me=form.cleaned_data.get("remember_me")
        )

    if user is None:
        return HttpResponse(content="Incorrect username or password", status=401)

    return HttpResponse(content="Successfully logged in", status=200)


@method(["POST"])
def logout_handler(request: HttpRequest):
    # Remove the tokens
    if request.session.get("refresh_token"):
        del request.session["refresh_token"]
    if request.session.get("access_token"):
        del request.session["access_token"]

    # Stop email and password change requests by making them all expire
    # This means the user has to make the requests again when they log back in
    # just in case someone somehow makes unauthorized API calls to reset emails and passwords
    # using something like Postman or cURL
    try:
        if hasattr(request, "user") and request.user.id is not None:
            user = request.user
            password_requests = models.PasswordChangeRequest.objects.filter(user=user)
            email_requests = models.EmailChangeRequest.objects.filter(user=user)
            if password_requests and hasattr(password_requests, "count"):
                for obj in password_requests:
                    obj.expires_at = timedelta(seconds=0)
                    obj.email_sent_at = datetime(1970, 1, 1, 0, 0, tzinfo=timezone.utc)

                models.PasswordChangeRequest.objects.bulk_update(password_requests, ["expires_at", "email_sent_at"])
            if email_requests and hasattr(email_requests, "count"):
                for obj in email_requests:
                    obj.expires_at = timedelta(seconds=0)
                    obj.email_sent_at = datetime(1970, 1, 1, 0, 0, tzinfo=timezone.utc)

                models.EmailChangeRequest.objects.bulk_update(email_requests, ["expires_at", "email_sent_at"])
    except Exception as e:
        print("Could not nullify reset requests because", e)
        pass

    # Flush out everything in the session just in case deleting didn't work
    request.session.flush()
    return HttpResponse(content="Logged out", status=200)


@method(["POST"])
def refresh_access_token_handler(request: HttpRequest):
    is_access_token_refreshed = auth_backend.refresh_access_token(request)
    if not is_access_token_refreshed:
        return HttpResponse(content="Invalid or no refresh token", status=401)

    return HttpResponse(content="Successfully refreshed token", status=200)


@method(["GET"])
def get_public_key_handler(request: HttpRequest):
    data: bytes = auth_backend.get_public_key()

    res = HttpResponse(content=str(data), status=200)
    res.headers["Content-Type"] = "application/x-pem-file"

    return res

@method(["GET"])
def validate_access_token_handler(request: HttpRequest):
    is_access_token_valid = auth_backend.validate_access_token(request)
    if not is_access_token_valid:
        return HttpResponse(content="Invalid or no access token", status=401)

    return HttpResponse(content="Access token is valid", status=200)

@method(["GET"])
def csrf_token_handler(request: HttpRequest):
    res = HttpResponse(content="CSRF cookie set", status=200)
    res.set_cookie("csrftoken", get_token(request))

    return res

def generate_reset_code(length: int = settings.RESET_CODE_LENGTH) -> int:
    return secrets.randbelow(10 ** length)

def is_access_token_valid(request: HttpRequest):
    return auth_backend.validate_access_token(request)

# Reset request handlers #

def send_code_email(user: AbstractBaseUser, field_name: str, reset_code: int | str):
    """Sends a reset email to a user

    Args:
        user (AbstractBaseUser): An existing user
        field_name (str): The field that needs to be reset (email, password, etc.)
        reset_code (int | str): An n-digit code
    """
    user.email_user(
        f"Pet Cam: {field_name} Reset Code", 
        render_to_string("emails/reset_code_email.html.j2", 
            context={
                "field_name": field_name.lower(), 
                "reset_code": reset_code
            }), 
        settings.EMAIL_HOST_USER
    )

@method(["POST"])
def forgot_password_request_handler(request: HttpRequest):
    form = forms.ForgotPasswordRequestForm(request.POST)
    
    if not form.is_valid():
        return HttpResponse(content="Email field is invalid", status=400)
    
    # Allow user to make request by putting in their email
    # It will send only if the inputted email belongs to a user
    request_email = form.cleaned_data.get("email")
    res = HttpResponse(status=200)
    user: AbstractBaseUser = None
    try:
        user = UserModel.objects.get(email=request_email)
    except Exception:
        return res
    if user:
        reset_code = generate_reset_code()
        field_name = "Password"
        forgot_password_request = models.ForgotPasswordRequest.objects.create(user=user, code=reset_code)
        send_code_email(user, field_name, reset_code)

        # unique session so that only the device that requested the reset is the one that fulfills it
        request_uuid = forgot_password_request.uuid
        res.set_cookie(key="reset_pw_uuid", value=request_uuid, httponly=True, samesite="Lax",expires=datetime.now(timezone.utc) + timedelta(days=1))

    # Send a 200 regardless of whether or not the email actually exists in the system
    # to prevent brute force email scanning
    # Rely on front-end to give a vague message
    return res

@method(["POST"])
def change_password_request_handler(request: HttpRequest):
    form = forms.PasswordChangeRequestForm(request.POST)
    
    if not form.is_valid():
        return HttpResponse(content="All fields must be completed", status=400)
    
    # Don't allow user to submit change request if they're not logged in
    user: AbstractBaseUser = request.user
    if not user:
        return HttpResponse("Current session is invalid", status=400)
    
    if not is_access_token_valid(request):
        return HttpResponse(content="Invalid or no access token", status=401)

    if len(str(user.email)) < 1:
        return HttpResponse(content="Unable to change password because you have no email. Please ask an administrator", status=401)
    new_password = form.cleaned_data.get("new_password")
    confirm = form.cleaned_data.get("confirm_new_password")
    if new_password != confirm:
        return HttpResponse(content="Confirm new password must match new password", status=400)
    is_new_same_as_old = user.check_password(new_password)
    if is_new_same_as_old:
        return HttpResponse(content="New password cannot be same as old password", status=400)
    reset_code = generate_reset_code()
    field_name = "Password"
    models.PasswordChangeRequest.objects.create(user=user, code=reset_code, new_password=new_password)
    send_code_email(user, field_name, reset_code)

    return HttpResponse(status=200)

@method(["POST"])
def change_email_request_handler(request: HttpRequest):
    form = forms.EmailChangeRequestForm(request.POST)

    if not form.is_valid():
        return HttpResponse(content="All fields must be completed", status=400)

    # Don't allow user to submit change request if they're not logged in
    user: AbstractBaseUser = request.user
    if type(user) is AnonymousUser:
        return HttpResponse("User must be logged in", status=401)
    if user.id is None:
        return HttpResponse("Current session is invalid", status=400)
    
    if not is_access_token_valid(request):
        return HttpResponse(content="Invalid or no access token", status=401)
    
    old_email = user.email
    new_email = form.cleaned_data.get("new_email")
    if old_email == new_email:
        return HttpResponse(content="New email is identical to old email", status=400)
    reset_code = generate_reset_code()
    field_name = "Email"
    models.EmailChangeRequest.objects.create(user=user, code=reset_code, new_email=new_email)
    send_code_email(user, field_name, reset_code)

    return HttpResponse(status=200)

@method(["POST"])
def forgot_password_code_handler(request: HttpRequest):
    form = forms.VerificationCodeForm(request.POST)
    
    if not form.is_valid():
        return HttpResponse(content=f"Field must contain a valid code", status=400)
    
    reset_pw_uuid = request.COOKIES.get("reset_pw_uuid")
    if not reset_pw_uuid:
        return HttpResponse(content="No active password reset request", status=400)
    
    forgot_password_request = models.ForgotPasswordRequest.objects.get(uuid=reset_pw_uuid)
    if not forgot_password_request:
        return HttpResponse(content="Invalid password reset request", status=400)
    
    forgot_password_code = forgot_password_request.code
    submitted_code = form.cleaned_data.get("code")
    if forgot_password_code != submitted_code:
        return HttpResponse(content="Incorrect code", status=400)
    
    if forgot_password_request.is_expired():
        return HttpResponse(content="Code expired", status=400)

    if forgot_password_request.is_fulfilled():
        return HttpResponse(content="Code already used", status=400)
    
    forgot_password_request.request_fulfilled_at = datetime.now(timezone.utc)
    # make a part two to allow the user to reset their password given that their original request is now valid
    # they still have their reset password cookie
    models.ForgotPasswordChangeRequest.objects.create(original_request=forgot_password_request,expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    return HttpResponse(content="Code accepted", status=200)

@method(["POST"])
def forgot_password_change_handler(request: HttpRequest):
    form = forms.ForgotPasswordChangeForm(request.POST)

    if form.data.get("cancelled") is not None:
        res = HttpResponse(content="Successfully cancelled request", status=200)
        res.set_cookie("reset_pw_uuid", "", expires="0", httponly=True)
        return res
    
    reset_pw_uuid = request.COOKIES.get("reset_pw_uuid")
    if not reset_pw_uuid:
        return HttpResponse(content="No active password reset request", status=400)

    original_request = models.ForgotPasswordRequest.objects.get(uuid=reset_pw_uuid)
    if not original_request:
        return HttpResponse(content="Invalid password reset request", status=400)
        
    if not form.is_valid():
        return HttpResponse(content="All fields must be completed", status=400)
    
    child_request = models.ForgotPasswordChangeRequest.objects.get(original_request=original_request)

    if child_request.is_cancelled():
        return HttpResponse(content="Cannot process a cancelled request", status=400)
    
    if child_request.is_expired():
        return HttpResponse(content="Request expired", status=400)
    
    if child_request.is_fulfilled():
        return HttpResponse(content="Request already fulfilled", status=400)

    new_password = form.cleaned_data.get("new_password")
    confirm_new_password = form.cleaned_data.get("confirm_new_password")
    if new_password != confirm_new_password:
        return HttpResponse(content="New password must match confirm new password", status=400)
    
    user: AbstractBaseUser = original_request.user
    if not user:
        return HttpResponse(content="Invalid user", status=500)
    
    user.set_password(new_password)
    user.save()
    child_request.request_fulfilled_at = datetime.now(timezone.utc)
    
    return HttpResponse(status=200)

@method(["POST"])
def change_email_code_handler(request: HttpRequest):
    form = forms.VerificationCodeForm(request.POST)

    if not form.is_valid():
        return HttpResponse(content=f"Field must contain a valid code", status=400)
    
    # Don't allow user to submit change request if they're not logged in
    user: AbstractBaseUser = request.user
    if not user:
        return HttpResponse("Current session is invalid", status=400)
    
    if not is_access_token_valid(request):
        return HttpResponse(content="Invalid or no access token", status=401)
    
    change_email_request = models.EmailChangeRequest.objects.filter(user=user).latest("email_sent_at")
    if change_email_request.code != form.cleaned_data.get("code"):
        return HttpResponse("Incorrect code", status=400)
    
    if change_email_request.is_expired():
        return HttpResponse(content="Code expired", status=400)
    
    if change_email_request.is_fulfilled():
        return HttpResponse(content="Code already used", status=400)
    
    user.email = change_email_request.new_email
    user.save()
    change_email_request.request_fulfilled_at = datetime.now(timezone.utc)
    return HttpResponse(content="Successfully changed email", status=200)

@method(["POST"])
def change_password_code_handler(request: HttpRequest):
    form = forms.VerificationCodeForm(request.POST)
    
    if not form.is_valid():
        return HttpResponse(content=f"Field must contain a valid code", status=400)
    
    # Don't allow user to submit change request if they're not logged in
    user: AbstractBaseUser = request.user
    if not user:
        return HttpResponse("Current session is invalid", status=400)
    
    if not is_access_token_valid(request):
        return HttpResponse(content="Invalid or no access token", status=401)
    
    change_password_request = models.PasswordChangeRequest.objects.filter(user=user).latest("email_sent_at")
    if change_password_request.code != form.cleaned_data.get("code"):
        return HttpResponse("Incorrect code", status=400)
    
    if change_password_request.is_expired():
        return HttpResponse(content="Code expired", status=400)
    
    if change_password_request.is_fulfilled():
        return HttpResponse(content="Code already used", status=400)
    
    user.set_password(change_password_request.new_password)
    user.save()
    change_password_request.request_fulfilled_at = datetime.now(timezone.utc)
    return HttpResponse(content="Successfully changed password", status=200)