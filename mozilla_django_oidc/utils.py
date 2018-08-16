import json
import requests

from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
try:
    from urllib.request import parse_http_list, parse_keqv_list
except ImportError:
    # python < 3
    from urllib2 import parse_http_list, parse_keqv_list

from django import VERSION
from django.conf import settings
from django.utils import six
from django.utils.encoding import force_bytes, smart_bytes, smart_text
from josepy.b64 import b64decode
from josepy.jwk import JWK
from josepy.jws import JWS, Header


def parse_www_authenticate_header(header):
    """
    Convert a WWW-Authentication header into a dict that can be used
    in a JSON response.
    """
    items = parse_http_list(header)
    return parse_keqv_list(items)


def import_from_settings(attr, *args):
    """
    Load an attribute from the django settings.

    :raises:
        ImproperlyConfigured
    """
    try:
        if args:
            return getattr(settings, attr, args[0])
        return getattr(settings, attr)
    except AttributeError:
        raise ImproperlyConfigured('Setting {0} not found'.format(attr))


def absolutify(request, path):
    """Return the absolute URL of a path."""
    return request.build_absolute_uri(path)


# Computed once, reused in every request
_less_than_django_1_10 = VERSION < (1, 10)


def is_authenticated(user):
    """return True if the user is authenticated.

    This is necessary because in Django 1.10 the `user.is_authenticated`
    stopped being a method and is now a property.
    Actually `user.is_authenticated()` actually works, thanks to a backwards
    compat trick in Django. But in Django 2.0 it will cease to work
    as a callable method.
    """
    if _less_than_django_1_10:
        return user.is_authenticated()
    return user.is_authenticated


def verify_jws(payload, key):
    """Verify the given JWS payload with the given key and return the payload"""
    jws = JWS.from_compact(payload)

    try:
        alg = jws.signature.combined.alg.name
    except KeyError:
        msg = 'No alg value found in header'
        raise SuspiciousOperation(msg)

    OIDC_RP_SIGN_ALGO = import_from_settings('OIDC_RP_SIGN_ALGO', 'HS256')
    if alg != OIDC_RP_SIGN_ALGO:
        msg = "The provider algorithm {!r} does not match the client's " \
              "OIDC_RP_SIGN_ALGO.".format(alg)
        raise SuspiciousOperation(msg)

    if isinstance(key, six.string_types):
        # Use smart_bytes here since the key string comes from settings.
        jwk = JWK.load(smart_bytes(key))
    else:
        # The key is a json returned from the IDP JWKS endpoint.
        jwk = JWK.from_json(key)

    if not jws.verify(jwk):
        msg = 'JWS token verification failed.'
        raise SuspiciousOperation(msg)

    return jws.payload


def retrieve_matching_jwk(token):
    """Get the signing key by exploring the JWKS endpoint of the OP."""
    OIDC_OP_JWKS_ENDPOINT = import_from_settings('OIDC_OP_JWKS_ENDPOINT', None)
    response_jwks = requests.get(
        OIDC_OP_JWKS_ENDPOINT,
        verify=import_from_settings('OIDC_VERIFY_SSL', True)
    )
    response_jwks.raise_for_status()
    jwks = response_jwks.json()

    # Compute the current header from the given token to find a match
    jws = JWS.from_compact(token)
    json_header = jws.signature.protected
    header = Header.json_loads(json_header)

    key = None
    for jwk in jwks['keys']:
        if 'alg' in jwk and jwk['alg'] != smart_text(header.alg):
            raise SuspiciousOperation('alg values do not match.')
        if jwk['kid'] == smart_text(header.kid):
            key = jwk
    if key is None:
        raise SuspiciousOperation('Could not find a valid JWKS.')
    return key


def get_payload_data(token, key):
    """Helper method to get the payload of the JWT token."""
    if import_from_settings('OIDC_ALLOW_UNSECURED_JWT', False):
        header, payload_data, signature = token.split(b'.')
        header = json.loads(smart_text(b64decode(header)))

        # If config allows unsecured JWTs check the header and return the decoded payload
        if 'alg' in header and header['alg'] == 'none':
            return b64decode(payload_data)

    # By default fallback to verify JWT signatures
    return verify_jws(token, key)


def verify_logout_token(token, **kwargs):
    """Validate the token signature and return its contents as dictionary."""
    OIDC_OP_JWKS_ENDPOINT = import_from_settings('OIDC_OP_JWKS_ENDPOINT', None)
    OIDC_RP_CLIENT_ID = import_from_settings('OIDC_RP_CLIENT_ID')
    OIDC_RP_CLIENT_SECRET = import_from_settings('OIDC_RP_CLIENT_SECRET')
    OIDC_RP_SIGN_ALGO = import_from_settings('OIDC_RP_SIGN_ALGO', 'HS256')
    OIDC_RP_IDP_SIGN_KEY = import_from_settings('OIDC_RP_IDP_SIGN_KEY', None)

    if (OIDC_RP_SIGN_ALGO.startswith('RS') and
        (OIDC_RP_IDP_SIGN_KEY is None and OIDC_OP_JWKS_ENDPOINT is None)):
        msg = '{} alg requires OIDC_RP_IDP_SIGN_KEY or OIDC_OP_JWKS_ENDPOINT to be configured.'
        raise ImproperlyConfigured(msg.format(OIDC_RP_SIGN_ALGO))

    token = force_bytes(token)
    if OIDC_RP_SIGN_ALGO.startswith('RS'):
        if OIDC_RP_IDP_SIGN_KEY is not None:
            key = OIDC_RP_IDP_SIGN_KEY
        else:
            key = retrieve_matching_jwk(token)
    else:
        key = OIDC_RP_CLIENT_SECRET

    payload_data = get_payload_data(token, key)
    # The 'token' will always be a byte string since it's
    # the result of base64.urlsafe_b64decode().
    # The payload is always the result of base64.urlsafe_b64decode().
    # In Python 3 and 2, that's always a byte string.
    # In Python3.6, the json.loads() function can accept a byte string
    # as it will automagically decode it to a unicode string before
    # deserializing https://bugs.python.org/issue17909
    payload = json.loads(payload_data.decode('utf-8'))

    msg = 'Payload data incorrect.'
    aud = payload.get('aud')
    if not aud or (OIDC_RP_CLIENT_ID != aud):
        raise SuspiciousOperation(msg)
    if not payload.get('sid'):
        raise SuspiciousOperation(msg)
    return payload
