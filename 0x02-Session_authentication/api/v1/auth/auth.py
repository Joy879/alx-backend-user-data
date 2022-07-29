#!/usr/bin/env python3
""" Module of authentication
"""


from typing import List, TypeVar
from flask import request
import re


class Auth:
    """
        Authentication Class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
            Checks if authentication is required
        """
        if path is None or excluded_paths is None:
            return True
        for ex_path in excluded_paths:
            if "*" in ex_path:
                if re.search(ex_path.replace("*", ".*"), path):
                    return False
            else:
                if re.search(path, ex_path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """
            Return Authorization header if it exists
        """
        return (None
                if request is None or 'Authorization' not in request.headers
                else request.headers['Authorization']
                )

    def current_user(self, request=None) -> TypeVar('User'):
        """
            Undetirmined
        """
        return None
