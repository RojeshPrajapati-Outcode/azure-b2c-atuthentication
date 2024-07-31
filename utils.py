import requests

from fleet_backend.env import (
    AZURE_AD_CLIENT_ID,
    AZURE_AD_CLIENT_SECRET,
    AZURE_AD_RESOURCE,
    AZURE_AD_B2C_AUTH_ENDPOINT,
    O365_MAIL_CLIENT_ID,
    O365_MAIL_CLIENT_SECRET,
    O365_MAIL_TENANT_ID,
)


class AzureCredentials:
    client_id = AZURE_AD_CLIENT_ID
    client_secret = AZURE_AD_CLIENT_SECRET
    grant_type = "client_credentials"
    resource = AZURE_AD_RESOURCE
    request_url = AZURE_AD_B2C_AUTH_ENDPOINT
    headers = {"content-type": "application/x-www-form-urlencoded"}

    def get_token(self) -> None or str:
        """
        Todo it has to valid if there is a token cached and if not request it
        - Payload example
        {
            "token_type": "Bearer",
            "expires_in": "3599",
            "ext_expires_in": "3599",
            "expires_on": "1676994266",
            "not_before": "1676990366",
            "resource": "https://graph.microsoft.com",
            "access_token": "__token__"
        }
        """
        request_token = requests.post(
            url=self.request_url,
            headers=self.headers,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": self.grant_type,
                "resource": self.resource,
            },
        )
        if request_token.status_code == requests.codes.ok:
            data = request_token.json()
            return data.get("access_token", None)
        return None


class AzureCredentialsForAD(AzureCredentials):
    client_id = O365_MAIL_CLIENT_ID
    client_secret = O365_MAIL_CLIENT_SECRET
    request_url = (
        f"https://login.microsoftonline.com/{O365_MAIL_TENANT_ID}/oauth2/token"
    )
