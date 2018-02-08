import json
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django import VERSION
from django.conf import settings
from django.utils.encoding import force_bytes, smart_bytes
from josepy.jwk import JWK
from josepy.jws import JWS


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
    jwk = JWK.load(key)
    if not jws.verify(jwk):
        msg = 'JWS token verification failed.'
        raise SuspiciousOperation(msg)

    try:
        alg = jws.signature.combined.alg.name
        if alg != import_from_settings('OIDC_RP_SIGN_ALGO', None):
            msg = 'The specified alg value is not allowed'
            raise SuspiciousOperation(msg)
    except KeyError:
        msg = 'No alg value found in header'
        raise SuspiciousOperation(msg)

    return jws.payload


def verify_logout_token(token, **kwargs):
    """Validate the token signature and return its contents as dictionary."""
    OIDC_RP_CLIENT_ID = import_from_settings('OIDC_RP_CLIENT_ID')
    OIDC_RP_CLIENT_SECRET = import_from_settings('OIDC_RP_CLIENT_SECRET')
    OIDC_RP_SIGN_ALGO = import_from_settings('OIDC_RP_SIGN_ALGO', 'HS256')
    OIDC_RP_IDP_SIGN_KEY = import_from_settings('OIDC_RP_IDP_SIGN_KEY', None)

    if OIDC_RP_SIGN_ALGO.startswith('RS'):
        key = OIDC_RP_IDP_SIGN_KEY
    else:
        key = OIDC_RP_CLIENT_SECRET

    # Verify the token
    verified_token = verify_jws(
        force_bytes(token),
        # Use smart_bytes here since the key string comes from settings.
        smart_bytes(key),
    )
    # The 'verified_token' will always be a byte string since it's
    # the result of base64.urlsafe_b64decode().
    # The payload is always the result of base64.urlsafe_b64decode().
    # In Python 3 and 2, that's always a byte string.
    # In Python3.6, the json.loads() function can accept a byte string
    # as it will automagically decode it to a unicode string before
    # deserializing https://bugs.python.org/issue17909
    token_dic = json.loads(verified_token.decode('utf-8'))

    msg = 'JWT verification failed.'
    aud = token_dic.get('aud')
    if not aud or (OIDC_RP_CLIENT_ID != aud):
        raise SuspiciousOperation(msg)
    if not token_dic.get('sid'):
        raise SuspiciousOperation(msg)
    return token_dic
