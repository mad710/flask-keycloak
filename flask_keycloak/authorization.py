import json
import logging

from .entities import (
    Resource,
    Policy,
    Permission,
    Role
)

from flask_keycloak.utils import load_config
from flask_keycloak.utils import (
    DECISION_STRATEGY_METHODS,
    LOGICS
)

logger = logging.getLogger(__name__)


class Authorization:

    def __init__(self, config_file):
        """
        Class responsible for parsing keycloak authorization settings, storing them
        and taking authorization decisions

        :param config_file: Path to the file containing Keycloak authorization settings
        """
        self._config_file = config_file
        self._authz_config = load_config(self._config_file)
        self._prepare_entities()

    def _prepare_entities(self):
        """
        Prepare resources, scopes, policies and permissions by parsing the authz_config
        """
        self.enforcement_mode = self._authz_config['policyEnforcementMode']
        self.decision_stratergy = self._authz_config['decisionStrategy']
        self.resources = {}
        self.scopes = []
        self.policies = {}
        self.permissions = {}

        for scp in self._authz_config['scopes']:
            self.scopes.append(scp['name'])

        for res in self._authz_config['resources']:
            scopes = [scp['name'] for scp in res.get('scopes', [])]
            resource = Resource(
                name=res['name'],
                type=res.get('type'),
                uris=res['uris'],
                scopes=scopes
            )
            self.resources[resource.name] = resource

        for pol in self._authz_config['policies']:
            if pol['type'] == 'role':
                # A policy
                roles = set([
                    Role(role['id'], role['required']
                    ) for role in json.loads(pol['config']['roles'])
                ])
                policy = Policy(
                    name=pol['name'],
                    type=pol['type'],
                    logic=pol['logic'],
                    decision_strategy=pol['decisionStrategy'],
                    roles=roles
                )
                self.policies[policy.name] = policy

        for perm in self._authz_config['policies']:
            if perm['type'] in ('scope', 'resource'):
                # A permission
                scopes = json.loads(perm['config'].get('scopes', '[]'))
                resources = json.loads(perm['config'].get('resources', '[]'))
                policies = set([
                    pn for pn in json.loads(
                        perm['config']['applyPolicies']) if pn in self.policies
                ])

                permission = Permission(
                    name=perm['name'],
                    type=perm['type'],
                    logic=perm['logic'],
                    decision_strategy=perm['decisionStrategy'],
                    resources=resources,
                    scopes=scopes,
                    policies=policies
                )
                self.permissions[permission.name] = permission

    def evaluate_policy(self, policy_name, user_roles):
        """
        Evaluates a single policy against the user roles and returns the outcome

        :param polciy_name <str>: Name of the policy to be evaluated
        :param user_roles <list>: A list of roles in the access token

        :rtype: bool
        """
        policy = self.policies[policy_name]
        required_roles = set([str(role) for role in policy.roles if role.required])
        all_roles = set([str(role) for role in policy.roles])

        # https://github.com/keycloak/keycloak-documentation/blob/master/\
        # authorization_services/topics/policy-role-policy-required-role.adoc

        if required_roles.issubset(user_roles) and (
            all_roles.intersection(user_roles)
        ):
            return LOGICS[policy.logic]
        else:
            return not(LOGICS[policy.logic])

    def evaluate_permission(self, permission_name, user_policies, resource, scope):
        """
        Evaluates a single permission against the user policies and returns
        the outcome

        :param polciy_name <str>: Name of the permission to be evaluated
        :param user_policies <list>: A list of policies the user has passed

        :rtype: bool
        """
        decision = False
        permission = self.permissions[permission_name]

        # Get appropriate function for the decsion strategy of this permission
        # Ref: https://github.com/keycloak/keycloak-documentation/blob/master/\
        # authorization_services/topics/permission-decision-strategy.adoc
        permission_dsm = DECISION_STRATEGY_METHODS[permission.decision_strategy]

        if permission.type == 'scope':
            if permission.resources and not resource in permission.resources:
                decision = False
            else:
                if scope in permission.scopes:
                    if permission_dsm(
                        pn in user_policies for pn in permission.policies
                    ):
                        decision = True
        elif permission.type == 'resource':
            if resource in permission.resources:
                if permission_dsm(
                    pn in user_policies for pn in permission.policies
                ):
                    decision = True

        logger.debug(f'Permission {permission} is evaluated to {decision}')
        return decision

    def evaluate_permissions(self, user_roles, resource, scope):
        """
        Evaluates the all the permissions for a given resource and scope
        returns the decision

        :param user_roles <list>: A list of roles in the access token

        :rtype: bool
        """
        # Get all the polices the user has passed
        logger.debug(f"User Roles: {user_roles}")
        user_policies = [
            policy_name for policy_name in self.policies if self.evaluate_policy(
                policy_name, user_roles
            )
        ]

        logger.debug(f"User policies: {user_policies}")
        # Get an appropriate function for deciding overall decsion as the outcome
        # of evaluation of multiple permissions
        # https://github.com/keycloak/keycloak-documentation/blob/master/\
        # authorization_services/topics/resource-server-enable-authorization.adoc

        permissions_dsf = DECISION_STRATEGY_METHODS.get(self.decision_stratergy)
        return permissions_dsf(
            self.evaluate_permission(
                permission_name, user_policies, resource, scope
                ) for permission_name in self.permissions
        )
