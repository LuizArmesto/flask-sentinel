# -*- coding: utf-8 -*-
"""
    flask-sentinel
    ~~~~~~~~~~~~~~

    :copyright: (c) 2015 by Nicola Iarocci.
    :license: BSD, see LICENSE for more details.
"""
from flask import Blueprint

from . import views
from .core import oauth, mongo, redis, login_manager
from .utils import Config
from .validator import MyRequestValidator
from .data import Storage
from redis.connection import ConnectionPool


class GrantType(object):
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        config = Config(app)
        self.config_redis(app, config)
        self.config_mongo(app, config)
        self.config_urls(app, config)
        self.config_login_manager(app, config)
        self.register_blueprint(app)
        oauth.init_app(app)
        oauth._validator = MyRequestValidator()

    def config_redis(self, app, config):
        redis.connection_pool = ConnectionPool.from_url(
            config.value('REDIS_URL'))

    def config_mongo(self, app, config):
        mongo.init_app(app, config_prefix='SENTINEL_MONGO')
        self.mongo = mongo

    def config_urls(self, app, config):
        if config.value('MANAGEMENT_URL') is not False:
            app.add_url_rule(
                config.url_rule_for('MANAGEMENT_URL'),
                view_func=views.management,
                methods=['POST', 'GET']
            )

    def config_login_manager(self, app, config):
        login_manager.init_app(app)
        login_manager.user_loader(
            lambda username: Storage.get_user(username, None))
        login_manager.login_view = 'login'
        self.login_manager = login_manager

    def register_blueprint(self, app):
        module = Blueprint('flask-sentinel', __name__,
                           template_folder='templates')
        app.register_blueprint(module)
        return module


class ResourceOwnerPasswordCredentials(GrantType):
    def config_urls(self, app, config):
        super(ResourceOwnerPasswordCredentials, self).config_urls(app, config)
        if config.value('TOKEN_URL') is not False:
            app.add_url_rule(
                config.url_rule_for('TOKEN_URL'),
                view_func=views.access_token,
                methods=['POST']
            )

class AuthorizationCode(GrantType):
    def config_urls(self, app, config):
        super(AuthorizationCode, self).config_urls(app, config)
        if config.value('TOKEN_URL') is not False:
            app.add_url_rule(
                config.url_rule_for('TOKEN_URL'),
                view_func=views.access_token,
                methods=['POST']
            )

        if config.value('AUTHORIZE_URL') is not False:
            app.add_url_rule(
                config.url_rule_for('AUTHORIZE_URL'),
                view_func=views.authorize,
                methods=['GET', 'POST']
            )

        if config.value('ERRORS_URL') is not False:
            app.add_url_rule(
                config.url_rule_for('ERRORS_URL'),
                view_func=views.errors,
                methods=['GET']
            )

        if config.value('LOGIN_URL') is not False:
            app.add_url_rule(
                config.url_rule_for('LOGIN_URL'),
                view_func=views.login,
                methods=['GET', 'POST']
            )

        if config.value('LOGOUT_URL') is not False:
            app.add_url_rule(
                config.url_rule_for('LOGOUT_URL'),
                view_func=views.logout,
                methods=['GET', 'POST']
            )
