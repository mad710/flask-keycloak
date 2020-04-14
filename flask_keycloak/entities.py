
class Resource:
    def __init__(self, name, type, uris, scopes):
        self.name = name
        self.type = type
        self.uris = uris
        self.scopes = scopes


class Scope:
    def __init__(self, name, display_name):
        self.name = name
        self.display_name = display_name

    def __repr__(self):
        return self.name


class Policy:
    def __init__(self, name, type, logic, roles, decision_strategy):
        self.name = name
        self.type = type
        self.logic = logic
        self.roles = roles
        self.decision_strategy = decision_strategy

    def __repr__(self):
        return self.name


class Role:
    def __init__(self, name, required):
        self.name = name
        self.required = required

    def __repr__(self):
        return self.name


class Permission:
    def __init__(self, name, type, logic, resources,
            scopes, policies, decision_strategy
        ):
        self.name = name
        self.type = type
        self.logic = logic
        self.resources = resources
        self.scopes = scopes
        self.policies = policies
        self.decision_strategy = decision_strategy
