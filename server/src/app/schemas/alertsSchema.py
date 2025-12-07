from app.schemas.baseSchema import RequiredStr, MacAddressStr, IPAddressStr, AttackTypeStr, ProtocolStr, TimestampStr, BaseRequest, BaseResponse, BaseResultResponse, responseModels


#-----------------------------------------------ALERTS-SCHEMA------------------------------------------------#
# represents add alert request schema
class AddAlertRequest(BaseRequest):
    interface: RequiredStr
    attackType: AttackTypeStr
    sourceIp: IPAddressStr
    sourceMac: MacAddressStr
    destinationIp: IPAddressStr
    destinationMac: MacAddressStr
    protocol: ProtocolStr
    osType: RequiredStr
    timestamp: TimestampStr


# represents delete alerts request schema
class DeleteAlertsRequest(BaseRequest):
    pass

#----------------------------------------------ALERTS-SCHEMA-END---------------------------------------------#