import requests
from fleet_backend.env import AZURE_AD_B2C_GRAPH_ENDPOINT
from integrations.azure_b2c.utils import AzureCredentials


class CreateUserOnAzure:
    """
    - response example:
    {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
        "id": "__azure_id__",
        "businessPhones": [],
        "displayName": "Lisa Middleway",
        "givenName": null,
        "jobTitle": null,
        "mail": null,
        "mobilePhone": null,
        "officeLocation": null,
        "preferredLanguage": null,
        "surname": null,
        "userPrincipalName": "user_test@order.hrxstaging.com"
    }
    """

    azure_credentials = AzureCredentials()
    url = AZURE_AD_B2C_GRAPH_ENDPOINT

    @staticmethod
    def generate_user_payload(
        display_name: str,
        mail_nickname: str,
        password: str,
        user_principal_name: str,
        force_password_change: bool = False,
        enabled: bool = True,
    ):
        return {
            "accountEnabled": enabled,
            "displayName": f"{display_name}",
            "mailNickname": f"{mail_nickname}",
            "passwordProfile": {"forceChangePasswordNextSignIn": force_password_change, "password": f"{password}"},
            "userPrincipalName": f"{user_principal_name}",
        }

    def create(
        self,
        display_name: str,
        mail_nickname: str,
        password: str,
        user_principal_name: str,
        force_password_change: bool = False,
        enabled: bool = True,
    ) -> None or dict:
        user = requests.post(
            url=self.url,
            headers={"Authorization": self.azure_credentials.get_token(), "Content-Type": "application/json"},
            json=self.generate_user_payload(
                display_name, mail_nickname, password, user_principal_name, force_password_change, enabled
            ),
        )
        if user.status_code == requests.codes.ok:
            return user.json()
        return None
