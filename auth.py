import requests
from azure_ad_verify_token import (
    get_public_key,
    jwt,
    verify_jwt,
    InvalidAuthorizationToken,
)
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, AnonymousUser
from rest_framework import status
from rest_framework.exceptions import APIException

import fleet_backend.env as env

from integrations.azure_b2c.roles import Roles, roles_replacement_mapping
from integrations.azure_b2c.utils import AzureCredentialsForAD


class ExpiredToken(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Token provided has expired"
    default_code = "invalid_token"


# requires to define two functions authenticate and get_user
class AzureADB2CBackend:
    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
            return AnonymousUser(), None

        token_split = auth_header.split(" ")
        token = token_split.pop()

        azure_ad_client_id = env.AZURE_AD_CLIENT_ID
        azure_ad_issuer = env.AZURE_AD_ISSUER
        azure_ad_jwks_uri = env.AZURE_AD_JWKS_URI

        try:
            if settings.TESTING:
                public_key = get_public_key(token=token, jwks_uri=azure_ad_jwks_uri)
                decoded = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    audience=[azure_ad_client_id],
                    issuer=azure_ad_issuer,
                    options={"verify_exp": False},
                )

            else:
                decoded = verify_jwt(
                    token=token,
                    valid_audiences=[azure_ad_client_id],
                    issuer=azure_ad_issuer,
                    jwks_uri=azure_ad_jwks_uri,
                    verify=True,
                )
        except InvalidAuthorizationToken:
            raise ExpiredToken("Invalid auth token")

        azure_id = decoded.get("sub")
        username = decoded.get("name")
        first_name = decoded.get("given_name", "")
        last_name = decoded.get("family_name", "")
        identity_provider = decoded.get("idp")
        email = decoded.get("email")
        if not email:
            email = decoded.get("emails", [None])[0]

        if azure_id and email and username:

            user = get_user_model().objects.filter(azure_id=azure_id).first()

            if not user:
                user, created = get_user_model().objects.get_or_create(email=email)
                user.azure_id = azure_id
                user.username = username

                if created:
                    user.first_name = first_name
                    user.last_name = last_name
                    user.is_active = True
                    user.is_staff = identity_provider == "Hercules"

                user.save()
            ValidADB2CGroups(user_principal_name=email).process(user=user)
            return user, None
        return None, None

    def update_azure_b2c_user_email(self, user_id, new_email, token: str):
        # tenant = "hrxextstaging.onmicrosoft.com"
        graph_endpoint = env.AZURE_AD_CLIENT_ID
        graph_api_url = f"{graph_endpoint}/{user_id}"

        payload = {"userPrincipalName": new_email}
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        response = requests.patch(graph_api_url, json=payload, headers=headers)

        if response.status_code == 200:
            return True
        else:
            return False

    def get_user(self, user_id):
        try:
            return get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist:
            return None

    def set_user_active_status(self, user_id, is_active):
        try:
            user = get_user_model().objects.get(pk=user_id)
            user.is_active = is_active
            user.save()
            return True
        except get_user_model().DoesNotExist:
            return False


class ValidADB2CGroups:
    ad_azure_credentials = AzureCredentialsForAD()
    url = env.AZURE_AD_B2C_GRAPH_ENDPOINT

    def __init__(self, user_principal_name: str) -> None:
        self.headers = {
            "Authorization": self.ad_azure_credentials.get_token(),
            "Content-Type": "application/json",
        }
        self.url = f"{self.url}/{user_principal_name}/memberOf"

    def get_b2c_groups(self):
        my_groups = requests.get(url=self.url, headers=self.headers)
        # print(json.dumps(my_groups.json(), indent=4))
        if my_groups.status_code == requests.codes.ok:
            response_groups_name = [
                group["displayName"] for group in my_groups.json().get("value", [])
            ]
            return [
                roles_replacement_mapping.get(rol.lower(), rol)
                for rol in response_groups_name
            ]
        return []

    @staticmethod
    def valid_admin(user, is_admin):
        if is_admin:
            user.is_superuser = True
            user.is_staff = True
        else:
            user.is_superuser = False
            user.is_staff = False
        user.save()

    @staticmethod
    def get_groups(b2c_groups):
        groups = list()
        for group_name in b2c_groups:
            group, _ = Group.objects.get_or_create(name=group_name)
            groups.append(group)
        return groups

    def sync_roles(self, user):
        user.groups.clear()
        b2c_groups = self.get_b2c_groups()
        self.valid_admin(user, Roles.ADMIN.value in b2c_groups)
        for group in self.get_groups(b2c_groups):
            user.groups.add(group)
        # if env.DEBUG:
        #     print(f"Your roles are {user.groups.all()}")

    def process(self, user):
        self.sync_roles(user)
