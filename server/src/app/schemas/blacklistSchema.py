from app.schemas.baseSchema import MacAddressStr, BaseRequest, BaseResponse, BaseResultResponse, responseModels


#---------------------------------------------BLACKLIST-SCHEMA-----------------------------------------------#
# represents add blacklist mac request schema
class AddBlacklistMacRequest(BaseRequest):
    macAddress: MacAddressStr


# represents delete blacklist mac request schema
class DeleteBlacklistMacRequest(BaseRequest):
    macAddress: MacAddressStr

#-------------------------------------------BLACKLIST-SCHEMA-END---------------------------------------------#