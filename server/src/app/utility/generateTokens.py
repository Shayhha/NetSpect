import sys, os
from google_auth_oauthlib.flow import InstalledAppFlow
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))) #ensures that generateTokens.py file will run from main folder in the terminal
from app.config.config import emailConfig


# function for generating Gmail API access and refresh tokens, requesting user consent and printing token details
def GenerateTokens() -> None:
    try:
        # create flow using the client configuration for generating Gmail API tokens
        flow = InstalledAppFlow.from_client_config(
            {'installed': {
                'client_id': emailConfig.clientId,
                'client_secret': emailConfig.clientSecret,
                'auth_uri': emailConfig.authUrl,
                'token_uri': emailConfig.tokenUrl,
                'redirect_uris': ['http://localhost/']
            }},
            scopes=[emailConfig.scopeUrl]
        )

        # run local server to handle the OAuth flow and get user consent for generating tokens
        credentials = flow.run_local_server(port=0, prompt='consent')

        # print the generated tokens and expiry time
        print(
            f'\nAccess Token: {credentials.token}'
            f'\nRefresh Token: {credentials.refresh_token}'
            f'\nToken Expiry: {credentials.expiry}'
        )

    # if exception occured we print error message
    except Exception as e:
        print(f'Error generating tokens: {e}.')


# main function for generating Gmail API tokens
if __name__ == '__main__':
    # run function to generate tokens
    GenerateTokens()