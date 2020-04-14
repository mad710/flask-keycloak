import json

def consensus(items):
    return (items.count(True) - items.count(False)) > 0


DECISION_STRATEGY_METHODS = {
    'AFFIRMATIVE': any,
    'UNANIMOUS': all,
    'CONSENSUS': consensus
}

LOGICS = {
    'POSITIVE': True,
    'NEGATIVE': False
}

SCOPES = {
    'GET': 'view',
    'POST': 'add',
    'PUT': 'modify',
    'DELETE': 'delete'
}

def val_or_raise(indict, key, msg=None):
    if not key in indict:
        errstr = msg or f'Config {key} is required'
        raise KeyError(errstr)


def load_config(filepath):
    with open(filepath, 'r') as fo:
        return json.load(fo)


def get_response_or_raise(response, exc=None, msg=''):
    if not response.status_code == 200:
        exc = exc or KeycloakError
        raise exc(msg)
    return json.loads(response.content)


class KeycloakError(Exception):
    pass
