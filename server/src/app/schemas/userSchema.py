from app.schemas.baseSchema import EmailStr, UsernameStr, PasswordStr, LightModeInt, OperationModeInt, BaseRequest, BaseResponse, BaseResultResponse, responseModels


#-----------------------------------------------USERS-SCHEMA-------------------------------------------------#
# represents change email request schema
class ChangeEmailRequest(BaseRequest):
    newEmail: EmailStr


# represents change username request schema
class ChangeUsernameRequest(BaseRequest):
    newUsername: UsernameStr


# represents change password request schema
class ChangePasswordRequest(BaseRequest):
    newPassword: PasswordStr
    oldPassword: PasswordStr


# represents delete account request schema
class DeleteAccountRequest(BaseRequest):
    pass


# represents hard delete account request schema
class HardDeleteAccountRequest(BaseRequest):
    pass


# represents update light mode request schema
class UpdateLightModeRequest(BaseRequest):
    lightMode: LightModeInt


# represents update operation mode request schema
class UpdateOperationModeRequest(BaseRequest):
    operationMode: OperationModeInt

#---------------------------------------------USERS-SCHEMA-END-----------------------------------------------#