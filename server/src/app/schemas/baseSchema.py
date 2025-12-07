from typing import Annotated
from pydantic import BaseModel, StringConstraints, Field


#----------------------------------------------STRING-VALIDATORS---------------------------------------------#
# represents required string validator with pattern and length validation
RequiredStr = Annotated[str, StringConstraints(
    pattern='^.+$',
    min_length=1,
    strip_whitespace=True
)]


# represents url string validator with pattern and length validation
UrlStr = Annotated[str, StringConstraints(
    pattern='^(?:[A-Za-z][A-Za-z0-9+\\-.]*:)?(?://(?:[A-Za-z0-9\\-._~%!$&\'()*+,;=]+@)?(?:\\[[0-9A-Fa-f:.]+\\]|(?:[0-9]{1,3}\\.){3}[0-9]{1,3}|(?:[a-zA-Z0-9\\-]+(?:\\.[a-zA-Z0-9\\-]+)*))(:[0-9]{1,5})?)?(?:/[a-zA-Z0-9\\-._~%!$&\'()*+,;=:@/]*)?(?:\\?[a-zA-Z0-9\\-._~%!$&\'()*+,;=:@/?]*)?(?:#[a-zA-Z0-9\\-._~%!$&\'()*+,;=:@/?]*)?$',
    min_length=5,
    max_length=2000,
    strip_whitespace=True
)]


# represents email string validator with pattern and length validation
EmailStr = Annotated[str, StringConstraints(
    pattern='^[A-Za-z0-9](?:[A-Za-z0-9_%+-]*\\.?[A-Za-z0-9_%+-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z]{2,})+$',
    min_length=5,
    max_length=320,
    strip_whitespace=True
)]


# represents username string validator with pattern and length validation
UsernameStr = Annotated[str, StringConstraints(
    pattern='^[A-Za-z][A-Za-z0-9]{3,15}$',
    min_length=4,
    max_length=16,
    strip_whitespace=True
)]


# represents password string validator with pattern and length validation
PasswordStr = Annotated[str, StringConstraints(
    pattern='^[A-Za-z0-9$&?@#|\\\\./\\^*()%!<>=\\-\\]\\[{};\'~`,+"\\:_]{6,50}$',
    min_length=6,
    max_length=50
)]


# represents mac address string validator with pattern and length validation
MacAddressStr = Annotated[str, StringConstraints(
    pattern='^(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$',
    min_length=17,
    max_length=17,
    to_lower=True,
    strip_whitespace=True
)]


# represents ipv4 and ipv6 ip address string validator with pattern validation
IPAddressStr = Annotated[str, StringConstraints(
    pattern='^(([0-9]{1,3}\\.){3}[0-9]{1,3}|([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7}|:))$',
    strip_whitespace=True
)]


# represents attack type string validator with pattern validation
AttackTypeStr = Annotated[str, StringConstraints(
    pattern='^(ARP Spoofing|Port Scan|DoS|DNS Tunneling)$',
    strip_whitespace=True
)]


# represents protocol string validator with pattern validation
ProtocolStr = Annotated[str, StringConstraints(
    pattern='^(TCP|UDP|DNS|ARP)$',
    to_upper=True,
    strip_whitespace=True
)]


# represents timestamp string validator with pattern validation
TimestampStr = Annotated[str, StringConstraints(
    pattern='^(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] (?:0[1-9]|[12][0-9]|3[01])/(?:0[1-9]|1[0-2])/([0-9][0-9])$',
    min_length=17,
    max_length=17,
    strip_whitespace=True
)]


# represents positive int validator with range validation
PositiveInt = Annotated[int, Field(
    ge=0
)]


# represents light mode int validator with range validation
LightModeInt = Annotated[int, Field(
    ge=0,
    le=1
)]


# represents operation mode int validator with range validation
OperationModeInt = Annotated[int, Field(
    ge=0,
    le=2
)]

#--------------------------------------------STRING-VALIDATORS-END-------------------------------------------#

#--------------------------------------------BASE-REQUEST-SCHEMA---------------------------------------------#
# represents base request class for router requests
class BaseRequest(BaseModel):
    pass

#------------------------------------------BASE-REQUEST-SCHEMA-END-------------------------------------------#

#--------------------------------------------BASE-RESPONSE-SCHEMA--------------------------------------------#
# represents base response class for router responses
class BaseResponse(BaseModel):
    state: bool = False
    message: str = ''
    error: bool = False


# represents base result response class for router responses
class BaseResultResponse(BaseResponse):
    result: dict = {}


# represents base validation error response class for router responses
class BaseValidationErrorResponse(BaseResponse):
    details: list = []


# represents dictionary for our http responses for routers with their models and descriptions
responseModels = {
    400: {'model': BaseResponse, 'description': 'Bad Request'},
    401: {'model': BaseResponse, 'description': 'Unauthorized'},
    403: {'model': BaseResponse, 'description': 'Forbidden'},
    422: {'model': BaseValidationErrorResponse, 'description': 'Validation Error'}, 
    429: {'model': BaseResponse, 'description': 'Too Many Requests'}, 
    500: {'model': BaseResponse, 'description': 'Internal Server Error'},
    503: {'model': BaseResponse, 'description': 'Service Unavailable'}
}

#-------------------------------------------BASE-RESPONSE-SCHEMA-END-----------------------------------------#