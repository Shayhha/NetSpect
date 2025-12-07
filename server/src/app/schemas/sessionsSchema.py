from app.schemas.baseSchema import BaseModel, BaseRequest, BaseResponse, BaseResultResponse, responseModels


#---------------------------------------------SESSION-AUTH-SCHEMA--------------------------------------------#
# represents session authentication schema
class SessionData(BaseModel):
    userId: int
    sessionId: str

#-------------------------------------------SESSION-AUTH-SCHEMA-END------------------------------------------#

#----------------------------------------------SESSIONS-SCHEMA-----------------------------------------------#
# represents check session request schema
class CheckSessionRequest(BaseRequest):
    pass


# represents delete session request schema
class DeleteSessionRequest(BaseRequest):
    pass

#--------------------------------------------SESSIONS-SCHEMA-END---------------------------------------------#