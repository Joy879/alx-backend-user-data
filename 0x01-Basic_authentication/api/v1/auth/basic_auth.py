#!/usr/bin/env python3
""" Module of basic authentication
"""


from models.user import User
from typing import TypeVar
from api.v1.auth.auth import Auth
import base64


class BasicAuth(Auth):
    """
        Basic authentication Class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
            returns the Base64 part of the Authorization
            header for a Basic Authentication
        """
        if (authorization_header is None
                or type(authorization_header) is not str
                or authorization_header.split(" ")[0] != 'Basic'):
            return None
        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """
            returns the decoded value of a Base64 string
        """
        if (base64_authorization_header is None
                or type(base64_authorization_header) is not str):
            return None
        try:
            return (base64.b64decode(base64_authorization_header)
                    .decode('utf-8'))
        except Exception:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> (str, str):
        """
            returns the user credentials
        """
        if (decoded_base64_authorization_header is None
                or type(decoded_base64_authorization_header) is not str
                or ":" not in decoded_base64_authorization_header):
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(":", 1))

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """
            returns the User instance based on his email and password.
        """
        if (user_email is None or type(user_email) is not str
                or user_pwd is None or type(user_pwd) is not str):
            return None
        user = User()
        res = user.search(attributes={"email": user_email})
        if res:
            if not res[0].is_valid_password(user_pwd):
                return None
            return res[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
            retrieves the User instance for a request
        """
        auth_header = self.authorization_header(request)
        if auth_header:
            base64_auth = self.extract_base64_authorization_header(auth_header)
            decoded_auth = self.decode_base64_authorization_header(base64_auth)
            creds = self.extract_user_credentials(decoded_auth)
            return self.user_object_from_credentials(creds[0], creds[1])
