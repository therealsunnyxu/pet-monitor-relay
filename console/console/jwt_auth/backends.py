from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth import get_user_model
from django.http.request import HttpRequest
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from uuid import uuid4 as uuid
from .config import (
    PUBLIC_KEY_LOC,
    PRIVATE_KEY_LOC,
    ACCESS_TOKEN_LIFETIME,
    REFRESH_TOKEN_DEFAULT_LIFETIME,
    REFRESH_TOKEN_EXTENDED_LIFETIME,
)
from datetime import datetime, timedelta
import json
import os
import sys
import traceback

UserModel = get_user_model()


class JWTBackend(ModelBackend):
    """
    Modifies Django's default authentication to use JWTs instead of passwords
    """

    def __init__(self):
        self._key: JWK = JWK()
        if os.path.exists(PUBLIC_KEY_LOC) and os.path.exists(PRIVATE_KEY_LOC):
            try:
                """
                Import the data from the private key file.
                No need to import the public key because it comes from
                the private key in the first place
                """
                with open(PRIVATE_KEY_LOC, "rb") as file:
                    data = file.read()
                    self._key.import_from_pem(data=data, password=None)
            except IOError as e:
                print(e)

        # This if statement will be skipped if the previous one is successful
        if not (os.path.exists(PUBLIC_KEY_LOC) and os.path.exists(PRIVATE_KEY_LOC)):
            # Create a new public-private pair
            self._key = JWK.generate(kty="RSA")

            try:
                # Write the public and private keys to file for persistence
                # if the service goes down for some reason.
                with open(PUBLIC_KEY_LOC, "wb") as file:
                    public_pem: bytes = self._key.export_to_pem(password=False)
                    file.write(public_pem)
                with open(PRIVATE_KEY_LOC, "wb") as file:
                    private_pem: bytes = self._key.export_to_pem(
                        private_key=True, password=None
                    )
                    file.write(private_pem)
            except IOError as e:
                print(e)

    def authenticate(
        self, request: HttpRequest, username: str = None, password: str = None, **kwargs
    ) -> AbstractBaseUser:
        """Authenticates the user using either a username and password or an access token in their session

        Args:
            request (HttpRequest): The user's request
            username (str): The user's name (default None)
            password (str): The user's password (default None)
            **kwargs (dict[str, Any]): Extra parameters
                remember_me (bool): Whether the refresh token should be "remembered" for an extended period of time

        Returns:
            AbstractBaseUser: The user model that the Django service currently uses
        """
        if (password is None and username is None) or (len(password) < 1 and len(username) < 1):
            # Automatically assume the user is logged in, since by default,
            # Django's DB-backed session give the user a cookie containing
            # their session ID, which is HTTP only.
            if not request.session.get("access_token"):
                # Assume that the user should refresh the token
                # Don't do it automatically
                return None
            try:
                user = self._authenticate_with_token(request.session["access_token"])
            except Exception:
                return None
            if not user:
                return None
            return user

        # Password guaranteed to not be None
        # This stage is now dependent on the username field existing.
        try:
            # Check if the user exists in the first place using a temp variable
            _ = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            # Don't allow making accounts
            return None

        # Call the superclass' authenticate method for login
        user = super().authenticate(request, username, password)
        if not user:
            return None

        # User confirmed to not be none
        # Check if the kwargs has a Remember Me field
        temp_remember_me = False
        if kwargs.get("remember_me") and (kwargs["remember_me"] == "on" or kwargs["remember_me"] == True):
            temp_remember_me = True
        self._store_tokens_on_login(request, user, temp_remember_me)
        return user

    def get_username_from_access_token(self, request: HttpRequest):
        if not self.validate_access_token(request):
            return None
        
        access_token = request.session.get("access_token")
        user: AbstractBaseUser = self._authenticate_with_token(access_token)
        if not user:
            return None
        return user.get_username()


    def _authenticate_with_token(self, token: str | bytes):
        """Returns a user object if the passed in access token is valid

        Args:
            request (HttpRequest): The user's request

        Raises:
            ValueError: Refresh token is missing NotBefore (nbf) or Expiration (exp)
            ValueError: Refresh token NotBefore (nbf) is before current time
            ValueError: Refresh token expired

        Returns:
            AbstractBaseUser: The user model that the Django service currently uses
        """
        try:
            access_token: JWT = JWT()
            try:
                access_token.deserialize(token, self._key)
            except Exception as e:
                raise e
            claims: dict | str = access_token.claims
            if type(claims) == str:
                # Assume that the claims are somehow encoded in JSON
                claims = json.loads(claims)
            if not (claims.get("nbf") and claims.get("exp")):
                raise ValueError(
                    "Missing NotBefore (nbf) or Expiration (exp) in refresh token."
                )

            nbf = datetime.fromtimestamp(float(claims["nbf"]))
            exp = datetime.fromtimestamp(float(claims["exp"]))

            if datetime.now() < nbf:
                raise ValueError(f"Cannot refresh until {nbf}.")

            if datetime.now() > exp:
                raise ValueError(f"Refresh token expired at {exp}.")

            user = UserModel._default_manager.get_by_natural_key(
                claims.get("username")
            )
            return user
        except Exception as e:
            print(e, file=sys.stderr)
            return None

    def _store_tokens_on_login(
        self, request: HttpRequest, user: AbstractBaseUser, remember_me: bool = False
    ):
        access_token = self._make_token(user, ACCESS_TOKEN_LIFETIME)
        refresh_lifetime = REFRESH_TOKEN_DEFAULT_LIFETIME
        if remember_me:
            refresh_lifetime = REFRESH_TOKEN_EXTENDED_LIFETIME
        refresh_token = self._make_token(user, refresh_lifetime)

        access_data = access_token.serialize()
        refresh_data = refresh_token.serialize()
        request.session["access_token"] = access_data
        request.session["refresh_token"] = refresh_data
        request.session.set_expiry(timedelta(seconds=refresh_lifetime))
        request.session.save()
    def _make_token(
        self,
        user: AbstractBaseUser,
        lifetime: timedelta | int | float,
    ):
        """Generates a JWT object.
        No additional information is added in the claims other than the default
        because this makes the assumption that the token will be stored
        in Django's DB-backed session.

        Args:
            user (AbstractBaseUser): The user object
            lifetime (timedelta | int | float): Time, either as timedelta or a number of seconds

        Raises:
            ValueError: Lifetime of token is a negative value

        Returns:
            JWT: A JWT with a UUID for a jti, along with nbf and exp fields
        """
        try:
            if type(lifetime) != timedelta:
                if lifetime < 0:
                    raise ValueError("Lifetime of token cannot be negative.")

                lifetime = timedelta(seconds=lifetime)

            token: JWT = JWT(
                header={"alg": "RS256"},
                claims={"username": user.get_username()},
                default_claims={
                    "nbf": datetime.now().timestamp(),
                    "exp": (datetime.now() + lifetime).timestamp(),
                    "jti": uuid(),
                },
            )

            token.make_signed_token(self._key)
            return token
        except Exception as e:
            print(e)
            return None

    def refresh_access_token(self, request: HttpRequest) -> bool:
        """Refreshes the user's access token using only the session in the request.
        Assumes that the session is DB-backed.

        Args:
            request (HttpRequest): The user's request

        Raises:
            ValueError: Refresh token is missing NotBefore (nbf) or Expiration (exp)
            ValueError: Refresh token NotBefore (nbf) is before current time
            ValueError: Refresh token expired

        Returns:
            bool: If the access token was refreshed or not.
        """
        try:
            refresh_data: str = request.session.get("refresh_token")
            refresh_token: JWT = JWT()
            refresh_token.deserialize(refresh_data, self._key)
            claims: dict | str = refresh_token.claims
            if type(claims) == str:
                # Assume that the claims are somehow encoded in JSON
                claims = json.loads(claims)
            if type(claims) == dict and not (claims.get("nbf") and claims.get("exp")):
                raise ValueError(
                    "Missing NotBefore (nbf) or Expiration (exp) in refresh token."
                )

            nbf = datetime.fromtimestamp(float(claims["nbf"]))
            exp = datetime.fromtimestamp(float(claims["exp"]))

            if datetime.now() < nbf:
                raise ValueError(f"Cannot refresh until {nbf}.")

            if datetime.now() > exp:
                raise ValueError(f"Refresh token expired at {exp}.")

            user = UserModel._default_manager.get_by_natural_key(
                claims.get("username")
            )

            access_token: JWT = self._make_token(user, ACCESS_TOKEN_LIFETIME)
            access_data = access_token.serialize()
            request.session["access_token"] = access_data
            request.session.save()
            return True
        except Exception as e:
            pass # print(e, traceback.format_exc(), file=sys.stderr)
            
        return False

    def get_public_key(self) -> bytes:
        return self._key.export_to_pem(password=False)
    
    def validate_access_token(self, request: HttpRequest) -> bool:
        try:
            access_data: str = request.session.get("access_token")
            access_token: JWT = JWT()
            access_token.deserialize(access_data, self._key)
            claims: dict | str = access_token.claims
            if type(claims) == str:
                # Assume that the claims are somehow encoded in JSON
                claims = json.loads(claims)
            if not (claims.get("nbf") and claims.get("exp")):
                raise ValueError(
                    "Missing NotBefore (nbf) or Expiration (exp) in access token."
                )

            nbf = datetime.fromtimestamp(float(claims["nbf"]))
            exp = datetime.fromtimestamp(float(claims["exp"]))

            if datetime.now() < nbf:
                raise ValueError(f"Cannot access until {nbf}.")

            if datetime.now() > exp:
                raise ValueError(f"access token expired at {exp}.")
            
            user = UserModel._default_manager.get_by_natural_key(
                claims.get("username")
            )

            if user is None:
                return False
        
            return True
        except Exception as e:
            print(e, file=sys.stderr)
        return False

