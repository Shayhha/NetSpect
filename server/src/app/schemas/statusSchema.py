from app.schemas.baseSchema import BaseModel, BaseRequest, BaseResponse, BaseResultResponse, responseModels


#-----------------------------------------------STATUS-SCHEMA------------------------------------------------#
# represents check root request schema
class CheckRootRequest(BaseRequest):
    pass


# represents check health request schema
class CheckHealthRequest(BaseRequest):
    pass


# represents check ready request schema
class CheckReadyRequest(BaseRequest):
    pass

#---------------------------------------------STATUS-SCHEMA-END----------------------------------------------#