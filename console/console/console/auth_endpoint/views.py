from django.contrib.auth import authenticate
from django.contrib.auth.base_user import AbstractBaseUser
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.views.decorators.http import require_http_methods as method
import json
from .forms import LoginForm
from jwt_auth.backends import JWTBackend

auth_backend = JWTBackend()


@method(["POST"])
def login_handler(request: HttpRequest):
    form: LoginForm = LoginForm(request.POST)
    if not form.is_valid():
        return HttpResponse(content="Incorrect username or password", status=401)

    user: AbstractBaseUser = authenticate(
        request,
        username=form.cleaned_data.get("username"),
        password=form.cleaned_data.get("password"),
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