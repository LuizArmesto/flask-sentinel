# -*- coding: utf-8 -*-
"""
    flask-sentinel.data
    ~~~~~~~~~~~~~~~~~~~

    :copyright: (c) 2015 by Nicola Iarocci.
    :license: BSD, see LICENSE for more details.
"""
import inspect
from collections import namedtuple
from datetime import datetime, timedelta
from bson.objectid import ObjectId

import bcrypt
from werkzeug.security import gen_salt

from flask.ext.login import current_user

from .core import mongo, redis
from .models import Client, User, Token, Grant


# TODO use SONManipulator instead of custom de/serializers perhaps?

# map collection _id (primary key) to class property.
idFieldsMap = namedtuple('idFields', 'cls, collection')
id = idFieldsMap(cls='id', collection='_id')


def _from_json(json, cls, as_list=False):
    """ Serializes a JSON stream to a list of objects, or a single objects
        if only a document is contained in the string.

    :param json: JSON dictionary or list.
    :parm cls: target class. Only properties matching json
               keys will be set to the corresponding json values.
    """
    if json is None:
        return None

    if not isinstance(json, list):
        json = [json]

    objs = []
    for json_item in json:
        obj = cls()

        properties, json_keys = set(_properties(obj)), set(json_item.keys())
        for property in set.intersection(properties, json_keys):
            try:
                setattr(obj, property, json_item[property])
            except AttributeError:
                # Probably a readonly property.
                pass

        if id.collection in json_item and json_item[id.collection] is not None:
            setattr(obj, id.cls, json_item[id.collection])

        objs.append(obj)

    return objs if as_list else (objs.pop() if len(objs) else None)


def _to_json(obj):
    """ Deserializes an object to a JSON stream.

    :param obj: object to be serialized to JSON.
    """

    json = {}
    for prop in _properties(obj):
        json[prop] = getattr(obj, prop)

    objid = getattr(obj, id.cls)
    if objid is not None:
        json[id.collection] = objid

    return json


def _properties(obj, include_id=False):
    """ Returns a list of object properties.

    :param obj: object to be inspected.
    :param include_id: True if db.cls (usually 'id') is to be included.
    """
    a = [
        name for (name, value) in inspect.getmembers(
            obj.__class__, lambda p: isinstance(p, property)
        ) if name != id.cls or include_id
    ]
    return a


class Storage(object):

    @staticmethod
    def get_client(client_id):
        """ Loads a client from mongodb and returns it as a Client or None.
        """
        json = mongo.db.clients.find_one({'client_id': client_id})
        return _from_json(json, Client)

    @staticmethod
    def get_user(username, password, *args, **kwargs):
        """ Loads a user from mongodb and returns it as a User or None.
        """
        user = mongo.db.users.find_one({'username': username})
        if user and password:
            encoded_pw = password.encode('utf-8')
            user_hash = user['hashpw'].encode('utf-8')
            user = mongo.db.users.find_one({
                'username': username,
                'hashpw': bcrypt.hashpw(encoded_pw, user_hash)
            })
        return _from_json(user, User)

    @staticmethod
    def get_token(access_token=None, refresh_token=None):
        """ Loads a token from mongob and returns it as a Token or None.
        """
        if not (access_token or refresh_token):
            return None

        if access_token:
            field, value = 'access_token', access_token
        elif refresh_token:
            field, value = 'refresh_token', refresh_token

        json = mongo.db.tokens.find_one({field: value})
        token = _from_json(json, Token)
        if token is None:
            return None

        json = mongo.db.users.find_one({id.collection: token.user_id})
        token.user = _from_json(json, User)

        return token

    @staticmethod
    def get_grant(client_id, code):
        """ Loads a grant from mongodb and returns it as a Grant or None.
        """
        json = mongo.db.grants.find_one({'client_id': client_id, 'code': code})
        grant = _from_json(json, Grant)

        json = mongo.db.users.find_one({id.collection: grant.user_id})
        grant.user = _from_json(json, User)

        return grant

    @staticmethod
    def save_grant(client_id, code, request, *args, **kwargs):
        user_id = current_user.id
        # decide the expires time yourself
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = Grant(
            client_id=client_id,
            user_id=user_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scopes=request.scopes,
            expires=expires
        )

        grant.id = mongo.db.grants.insert(_to_json(grant))
        return grant

    @staticmethod
    def save_token(token, request, *args, **kwargs):
        client_id = request.client.client_id
        user = request.user or current_user
        user_id = user.id

        # Make sure there is only one grant token for every (client, user)
        # mongo.db.tokens.remove({'client_id': client_id, 'user_id': user_id})

        expires_in = token.get('expires_in')
        expires = datetime.utcnow() + timedelta(seconds=expires_in)

        token = Token(
            client_id=request.client.client_id,
            user_id=user_id,
            token_type=token['token_type'],
            access_token=token['access_token'],
            refresh_token=token.get('refresh_token', None),
            expires=expires,
        )

        # Add the access token to the Redis cache and set it to
        # expire at the appropriate time.
        redis.setex(token.access_token, expires_in, user_id)

        spec = {'user_id': user_id, 'client_id': client_id}

        # Replace token if it exists already, insert otherwise.
        mongo.db.tokens.update(spec, _to_json(token), upsert=True)

    @staticmethod
    def generate_client(name=None, description=None, redirect_uris=None):
        client = Client()
        client.client_id = gen_salt(40)
        client.client_secret = gen_salt(40)
        client.client_type = "public"
        client.name = name
        client.description = description
        client.redirect_uris = redirect_uris
        mongo.db.clients.insert(_to_json(client))
        return client

    @staticmethod
    def save_user(username, password):
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        user = User(username=username, hashpw=hash)
        user.id = mongo.db.users.insert(_to_json(user))
        return user

    @staticmethod
    def delete_user(username):
        user = mongo.db.users.find_one({'username': username})
        user = _from_json(user, User)
        mongo.db.tokens.delete_many({'user_id': user.id})
        mongo.db.users.delete_one({'_id': user.id})
        return user

    @staticmethod
    def delete_client(client_id):
        client = mongo.db.clients.find_one({'client_id': client_id})
        client = _from_json(client, Client)
        mongo.db.tokens.delete_many({'client_id': client.id})
        mongo.db.clients.delete_one({'_id': client.id})
        return client

    @staticmethod
    def delete_token(access_token=None, refresh_token=None):
        """ Loads a token from mongob and returns it as a Token or None.
        """
        if not (access_token or refresh_token):
            return None

        if access_token:
            field, value = 'access_token', access_token
        elif refresh_token:
            field, value = 'refresh_token', refresh_token

        json = mongo.db.tokens.find_one({field: value})
        token = _from_json(json, Token)
        if token is None:
            return None

        mongo.db.tokens.delete_one({'_id': token.id})

        return token

    @staticmethod
    def delete_grant(grant_id):
        mongo.db.grants.delete_one({'_id': ObjectId(grant_id)})

    @staticmethod
    def all_users():
        json = list(mongo.db.users.find())
        return _from_json(json, User, as_list=True)

    @staticmethod
    def all_clients():
        json = list(mongo.db.clients.find())
        return _from_json(json, Client, as_list=True)

    @staticmethod
    def all_tokens():
        json = list(mongo.db.tokens.find())
        return _from_json(json, Token, as_list=True)

    @staticmethod
    def all_grants():
        json = list(mongo.db.grants.find())
        return _from_json(json, Grant, as_list=True)
