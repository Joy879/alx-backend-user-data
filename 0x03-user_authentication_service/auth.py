#!/usr/bin/env python3
""" Auth """
from bcrypt import hashpw, gensalt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import bcrypt
import uuid


def _hash_password(password: str) -> str:
    """ encrypt password """
    return hashpw(password.encode('utf-8'), gensalt())


def _generate_uuid() -> str:
    """ Generate a string representation of a new UUID """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ create a new user """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)

            return user

        else:
            raise ValueError(f'User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """ checks if the password is correct """
        try:
            user = self._db.find_user_by(email=email)
            if user:
                return bcrypt.checkpw(password.encode(), user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """ generate new session ID """
        try:
            user = self._db.find_user_by(email=email)
            if user:
                id = _generate_uuid()
                self._db.update_user(user.id, session_id=id)
                return id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> str:
        """ returns user """
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception as e:
            return None

    def destroy_session(self, user_id: int) -> None:
        """ remove session id that is passed as argument """
        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """ generate new token """
        if not email:
            return None
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except Exception as e:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """ update the user password """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            new_password = _hash_password(password)
            self._db.update_user(user.id, hashed_password=new_password,
                                 reset_token=None)
            return None
        except Exception as e:
            raise ValueError
