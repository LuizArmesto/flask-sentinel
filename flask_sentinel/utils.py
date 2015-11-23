# -*- coding: utf-8 -*-
"""
    flask-sentinel.utils
    ~~~~~~~~~~~~~~~~~~~~

    :copyright: (c) 2015 by Nicola Iarocci.
    :license: BSD, see LICENSE for more details.
"""

from urlparse import urlparse, urljoin
from flask import request, url_for, redirect


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def get_redirect_target():
    for target in request.values.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target


def redirect_back(endpoint, **values):
    target = request.form['next']
    if not target or not is_safe_url(target):
        target = url_for(endpoint, **values)
    return redirect(target)


class Config(object):
    def __init__(self, app):
        self.prefix = 'SENTINEL'
        self.app = app

        app.config.setdefault(self._key('MONGO_DBNAME'), 'oauth')
        app.config.setdefault(self._key('ROUTE_PREFIX'), '/oauth')
        app.config.setdefault(self._key('TOKEN_URL'), '/token')
        app.config.setdefault(self._key('ERRORS_URL'), '/errors')
        app.config.setdefault(self._key('AUTHORIZE_URL'), '/authorize')
        app.config.setdefault(self._key('MANAGEMENT_URL'), '/management')
        app.config.setdefault(self._key('LOGIN_URL'), '/login')
        app.config.setdefault(self._key('LOGOUT_URL'), '/logout')
        app.config.setdefault(self._key('REDIS_URL'),
                              'redis://localhost:6379/0')

    def url_rule_for(self, _key):
        return '%s%s' % (self.value('ROUTE_PREFIX'), self.value(_key))

    def value(self, key):
        return self.app.config[self._key(key)]

    def _key(self, _key):
        return '%s_%s' % (self.prefix, _key)
