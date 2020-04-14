import requests
import jwt
import json
import logging
from urllib.parse import urljoin
from functools import wraps
from flask import request, current_app, Response
from enum import Enum

from flask_keycloak.utils import val_or_raise, get_response_or_raise, SCOPES
from flask_keycloak.authorization import Authorization

from flask_keycloak.utils import KeycloakError

URL_TOKEN = "realms/{realm_name}/protocol/openid-connect/token"
URL_INTROSPECT = f"{URL_TOKEN}/introspect"

logger = logging.getLogger(__name__)


class AuthManager:

    def __init__(self, app=None, config={}, mode='online',
            authz=False, authz_config_file=None
        ):
        """
        A flask extension for enabling keycloak based authentication and
        authorization on a Flask API

        :param app: Flask app
        :param config: A dictionary containing keycloak server configurations
        :param mode: Mode of operation. Can be 'online' or  'offline'
        :param authz: If True, access control verification on resources
                will be is enabled
        :param authz_config_file: Path to the file containing authz settings
                exported from Keycloak
        """
        self.config = config
        self.mode = mode
        self.authz_config_file = authz_config_file
        self.authz = authz
        self._authorization = None
        self._session = requests.session()

        if app is not None:
            self.app = app
            self.init_app(app)

    def init_app(self, app):
        self._validate()
        app.config['KEYCLOAK_SERVER_URL'] = self.config.get('server_url')
        app.config['KEYCLOAK_REALM_NAME'] = self.config.get('realm_name')
        app.config['KEYCLOAK_CLIENT_ID'] = self.config.get('client_id')
        app.config['KEYCLOAK_CLIENT_SECRET'] = self.config.get('client_secret')
        app.config['KEYCLOAK_JWT_KEY'] = self.config.get('jwt_key')
        app.config['KEYCLOAK_AUTHZ_CONFIG_FILE'] = self.authz_config_file

        if self.authz and self.mode == 'offline':
            self._authorization = Authorization(
                config_file=self.authz_config_file
            )

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['keycloak-adapter'] = self

    def _validate(self):
        """
        Validate intialization parmaters and config values
        """
        val_or_raise(self.config, 'server_url')
        val_or_raise(self.config, 'realm_name')
        val_or_raise(self.config, 'client_id')

        if self.mode not in ['online', 'offline']:
            raise ValueError("Invalid mode. Can be 'online' or 'offline'")

        if self.mode == 'online':
            val_or_raise(self.config, 'client_secret',
                'client_secret is required in online mode')
        else:
            val_or_raise(self.config, 'jwt_key',
                'jwt_key is required in offline mode')
            if self.authz and not self.authz_config_file:
                raise ValueError('authz_config_file has to be specified in offline mode')

    def urljoin(self, url):
        return urljoin(self.config['server_url'], url)

    def introspect(self, token):
        """
        Introspect the access token using token introspection uri of keycloak
        """
        url = self.urljoin(URL_INTROSPECT.format(
            realm_name=self.config['realm_name'])
        )
        data = {
            'token': token,
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret']
        }
        response = self._session.post(url, data=data)
        token_info = get_response_or_raise(response)
        if not token_info['active']:
            logger.debug('Token is Inactive')
            raise KeycloakError('Token is inactive')
        return token_info

    def decode_token(self, token):
        """
        Decode the access token locally using the JWT key
        """
        return jwt.decode(
            token, self.config['jwt_key'], audience=self.config['client_id']
        )

    def authenticate(self, token):
        """
        Verifies and stores the token information in the context
        """
        token_info = self.introspect(token) if (
            self.mode == 'online') else self.decode_token(token)
        return token_info

    def authorize(self, token, resource, scope):
        """
        Verifies policies and permissions on the requested resource by comparing
        against the roles claim in the token
        """
        decision = False
        if self.mode == 'online':
            # Request to the token url with response mode as decision
            url = self.urljoin(URL_TOKEN.format(
                realm_name=self.config['realm_name'])
            )
            data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
                'audience': self.config['client_id'],
                'permission': f'{resource}#{scope}',
                'response_mode': 'decision'
            }
            headers = {'Authorization': f'Bearer {token}'}
            response = self._session.post(url, data=data, headers=headers)
            try:
                decision = get_response_or_raise(response)['result']
            except:
                logger.exception('Exception in authorization checks')
                decision = False
        else:
            # verify the permissions locally with the help of authz config file
            client_id = self.config['client_id']
            # Get client roles from the token
            user_roles = token['resource_access'].get(client_id, {}).get('roles', [])
            # Modifying the roles to match the ones stored in config
            user_roles = [f'{client_id}/{ur}' for ur in user_roles]
            decision = self._authorization.evaluate_permissions(
                user_roles=user_roles,
                resource=resource,
                scope=scope
            )

        return decision

    def _get_token_from_headers(self):
        token = None
        if 'Authorization' in request.headers and (
                request.headers['Authorization'].startswith('Bearer ')):
            token = request.headers['Authorization'].split(None,1)[1].strip()
        return token

    def _verify_auth(self):
        """
        Verify the access token and check the access control permissions
        for the logged in user
        """
        endpoint, method = request.endpoint, request.method
        logger.debug(f'Endpoint={endpoint}, method={method}')
        token = self._get_token_from_headers()

        if not token:
            logger.debug('Unable to retireve access token from the headers')
            return False, Response(json.dumps({
                    "error": "AuthenticationError",
                    "error_description": "Access token is missing"
                }
            ), status=401)
        # Verify the JWT access token
        try:
            token_info = self.authenticate(token)
        except Exception as e:
            logger.exception('Exception in token verification')
            return False, Response(json.dumps({
                    "error": "AuthenticationError",
                    "error_description": "Invalid or expired access token"
                }
            ), status=401)

        if self.authz:
            # Verify the permissions
            token = token if self.mode == 'online' else token_info
            scope = SCOPES[method]
            valid = self.authorize(token, resource=endpoint, scope=scope)
            if not valid:
                return False, Response(json.dumps({
                    "error": "Unauthorized",
                    "error_description": "User does not have the permission" \
                        f" to access {endpoint}:{method}"
                    }
                ), status=403)

        return True, '{}'


def auth_required(func):
    """
    To be used as a decorator for the view fucntions
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_app.config.get('AUTH') is not False:
            try:
                adapter = current_app.extensions['keycloak-adapter']
            except KeyError:
                raise RuntimeError("You must initialize a KeycloakAuthManager "
                       "application before using this method")

            valid, response = adapter._verify_auth()
            if not valid:
                return response

        return func(*args, **kwargs)

    return wrapper
