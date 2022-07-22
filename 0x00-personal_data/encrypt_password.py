#!/usr/bin/env python3
"""
Implement a hash_password function that expects one string argument
name password and returns a salted, hashed password, which is a byte string.
Then validate if password is same as hashed password.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Returns salted, hashed password which is a byte string
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validate that the provided password matches the hashed password.
    """
    if bcrypt.checkpw(password.encode(), hashed_password):
        return True
    else:
        return False
