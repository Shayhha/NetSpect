from enum import Enum


# represents base enum class
class BaseEnum(str, Enum):

    # override str method to return the value of enum
    def __str__(self) -> str:
        return str(self.value)


# represents base endpoint enum class for endpoints for server API
class BaseEndpointEnum(BaseEnum):

    # method for getting current endpoint name
    def Endpoint(self) -> str:
        # get last endpoint name in path
        endpoint = self.value.rstrip('/').split('/')[-1]
        # return endpoint name
        return f'/{endpoint}'


    # method for getting parent endpoint
    def Parent(self) -> str:
        # get parent endpoint without base endpoint name
        endpoints = self.value.rstrip('/').split('/')
        # if there's more than one endpoint, return parent
        if len(endpoints) > 1:
            return '/'.join(endpoints[:-1])
        # else return base endpoint
        return self.value 


# represents HTTP methods enum class for server API
class HttpMethods(BaseEnum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    OPTIONS = 'OPTIONS'


# class for defining server API endpoints
class Endpoints(BaseEndpointEnum):
    Base = '/'
    Health = '/health'
    Ready = '/ready'
    Static = '/static'
    OpenApi = '/openapi.json'
    Docs = '/docs'
    Redoc = '/redoc'

    # represents api endpoints
    class API(BaseEndpointEnum):
        Base = '/api'

        # represents auth endpoints
        class Auth(BaseEndpointEnum):
            Base = f'/api/auth'
            Login = f'{Base}/login'
            Register = f'{Base}/register'

        # represents session endpoints
        class Sessions(BaseEndpointEnum):
            Base = f'/api/sessions'
            CheckSession = f'{Base}/check-session'
            DeleteSession = f'{Base}/delete-session'

        # represents reset password endpoints
        class ResetPassword(BaseEndpointEnum):
            Base = f'/api/reset-password'
            SendResetCode = f'{Base}/send-reset-code'
            VerifyResetCode = f'{Base}/verify-reset-code'

        # represents users endpoints
        class Users(BaseEndpointEnum):
            Base = f'/api/users'
            ChangeEmail = f'{Base}/change-email'
            ChangeUsername = f'{Base}/change-username'
            ChangePassword = f'{Base}/change-password'
            DeleteAccount = f'{Base}/delete-account'
            HardDeleteAccount = f'{Base}/hard-delete-account'
            UpdateLightMode = f'{Base}/update-light-mode'
            UpdateOperationMode = f'{Base}/update-operation-mode'

        # represents blacklist endpoints
        class Blacklist(BaseEndpointEnum):
            Base = f'/api/blacklist'
            AddBlacklistMac = f'{Base}/add-blacklist-mac'
            DeleteBlacklistMac = f'{Base}/delete-blacklist-mac'

        # represents alerts endpoints
        class Alerts(BaseEndpointEnum):
            Base = f'/api/alerts'
            AddAlert = f'{Base}/add-alert'
            DeleteAlerts = f'{Base}/delete-alerts'