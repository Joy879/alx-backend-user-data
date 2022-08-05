#!/usr/bin/env python3
""" App """
import flask
from auth import Auth


app = flask.Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def hello() -> str:
    """ return welcome message """
    msg = {"message": "Bienvenue"}
    return flask.jsonify(msg)


@app.route('/users', methods=['POST'])
def register() -> str:
    """ Add a new user to the db """
    try:
        email = flask.request.form['email']
        password = flask.request.form['password']
    except KeyError:
        flask.abort(400)

    try:
        AUTH.register_user(email, password)
    except ValueError:
        return flask.jsonify({"message": "email already registered"}), 400

    msg = {"email": email, "message": "user created"}
    return flask.jsonify(msg)


@app.route('/sessions', methods=['POST'])
def login() -> str:
    """ Login the user """
    form_data = flask.request.form

    if "email" not in form_data:
        return flask.jsonify({"message": "email required"}), 400
    elif "password" not in form_data:
        return flask.jsonify({"message": "password required"}), 400
    else:

        email = flask.request.form.get("email")
        pswd = flask.request.form.get("password")

        if AUTH.valid_login(email, pswd) is False:
            flask.abort(401)
        else:
            session_id = AUTH.create_session(email)
            response = flask.jsonify({
                "email": email,
                "message": "logged in"
                })
            response.set_cookie('session_id', session_id)

            return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def log_out() -> None:
    """Logout
    """
    session_id = flask.request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        flask.abort(403)
    AUTH.destroy_session(user.id)
    return flask.redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """response to the GET /profile"""
    session_id = flask.request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return flask.jsonify({"email": user.email}), 200
    else:
        flask.abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """generate a token """
    try:
        email = flask.request.form['email']
    except KeyError:
        flask.abort(403)

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        flask.abort(403)

    msg = {"email": email, "reset_token": reset_token}

    return flask.jsonify(msg), 200


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """ update password
    """
    try:
        email = flask.request.form['email']
        reset_token = flask.request.form['reset_token']
        new_password = flask.request.form['new_password']
    except KeyError:
        flask.abort(400)

    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        flask.abort(403)

    msg = {"email": email, "message": "Password updated"}
    return flask.jsonify(msg), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
