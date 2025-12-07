from app.schemas.baseSchema import RequiredStr, EmailStr, BaseRequest, BaseResponse, BaseResultResponse, responseModels


#-------------------------------------------RESET-PASSWORD-SCHEMA--------------------------------------------#
# represents send reset code request schema
class SendResetCodeRequest(BaseRequest):
    email: EmailStr


# represents verify reset code request schema
class VerifyResetCodeRequest(BaseRequest):
    email: EmailStr
    resetCode: RequiredStr

#-----------------------------------------RESET-PASSWORD-SCHEMA-END------------------------------------------#