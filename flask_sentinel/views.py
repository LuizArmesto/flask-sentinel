# -*- coding: utf-8 -*-
"""
    flask-sentinel.views
    ~~~~~~~~~~~~~~~~~~~~

    :copyright: (c) 2015 by Nicola Iarocci.
    :license: BSD, see LICENSE for more details.
"""
from flask import render_template, request, redirect, url_for
from flask.ext.login import login_required, login_user, logout_user

from .core import oauth
from .data import Storage
from .basicauth import requires_basicauth
from .utils import get_redirect_target, redirect_back


def errors(*args, **kwargs):
    error =request.args.get('error')
    error_description =request.args.get('error_description')
    return render_template('errors.html',
        error=error, error_description=error_description)


@login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client = Storage.get_client(kwargs.get('client_id'))
        return render_template('oauthorize.html', client=client, **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@oauth.token_handler
def access_token(*args, **kwargs):
    """ This endpoint is for exchanging/refreshing an access token.

    Returns a dictionary or None as the extra credentials for creating the
    token response.

    :param *args: Variable length argument list.
    :param **kwargs: Arbitrary keyword arguments.
    """
    return None


@requires_basicauth
def management():
    """ This endpoint is for vieweing and adding users and clients. """
    if request.method == 'POST':
        action = request.form['action']
        if action == 'add_user':
            Storage.save_user(request.form['username'],
                              request.form['password'])
        elif action == 'delete_user':
            Storage.delete_user(request.form['username'])
        elif action == 'add_client':
            Storage.generate_client(request.form['name'],
                                    request.form['description'],
                                    request.form['redirect_uris'].split( ))
        elif action == 'delete_client':
            Storage.delete_client(request.form['client_id'])
        elif action == 'delete_token':
            Storage.delete_token(access_token=request.form['access_token'])
        elif action == 'delete_grant':
            Storage.delete_grant(request.form['grant_id'])
    return render_template('management.html',
                           users=Storage.all_users(),
                           clients=Storage.all_clients(),
                           tokens=Storage.all_tokens(),
                           grants=Storage.all_grants(),)


def login():
    next = get_redirect_target()
    if request.method == 'GET':
        return render_template('login.html', next=next)

    username = request.form['username']
    password = request.form['hashpw']
    user = Storage.get_user(username, password)
    if user:
        login_user(user)
        return redirect_back('index')
    return 'Bad login'

def logout():
    logout_user()
    return 'Logged out'
