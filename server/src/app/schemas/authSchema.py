from app.schemas.baseSchema import RequiredStr, EmailStr, UsernameStr, PasswordStr, BaseRequest, BaseResponse, BaseResultResponse, responseModels


#-----------------------------------------------AUTH-SCHEMA--------------------------------------------------#
# represents login request schema
class LoginRequest(BaseRequest):
    username: RequiredStr
    password: RequiredStr


# represents register request schema
class RegisterRequest(BaseRequest):
    email: EmailStr
    username: UsernameStr
    password: PasswordStr

#----------------------------------------------AUTH-SCHEMA-END-----------------------------------------------#