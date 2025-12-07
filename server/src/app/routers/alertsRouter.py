from fastapi import APIRouter, Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from app.database.database import Database
from app.schemas.sessionsSchema import SessionData
from app.dependancies.sessionAuth import SessionAuth
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import rateLimitConfig, limiter
from app.schemas.alertsSchema import AddAlertRequest, DeleteAlertsRequest, BaseResponse, responseModels
from app.services import alertsService

# define router for alerts endpoint
router = APIRouter(prefix=Endpoints.API.Alerts.Base.Endpoint(), tags=['Alerts'])


# endpoint function for handeling add alert for users
@router.post(Endpoints.API.Alerts.AddAlert.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Add alert for users.**')
@limiter.limit(rateLimitConfig.api)
async def AddAlert(request: Request, addAlertRequest: AddAlertRequest, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our add alert service to add alert for user
            addAlertResult = await alertsService.AddAlert(connection, sessionData.userId, addAlertRequest.interface, addAlertRequest.attackType, addAlertRequest.sourceIp, addAlertRequest.sourceMac,
                                                            addAlertRequest.destinationIp, addAlertRequest.destinationMac, addAlertRequest.protocol, addAlertRequest.osType, addAlertRequest.timestamp)

            # check if error occured, if so raise exception with message
            if addAlertResult.get('error'):
                raise Exception(addAlertResult.get('message'))

            # return add alert result in http response
            return JSONResponse(content=addAlertResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error adding alert due to server error, try again later.', 'error': True}
        print(f'Error adding alert: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling delete alerts for users
@router.delete(Endpoints.API.Alerts.DeleteAlerts.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Delete alerts for users.**')
@limiter.limit(rateLimitConfig.api)
async def DeleteAlerts(request: Request, deleteAlertsRequest: DeleteAlertsRequest=None, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our delete alerts service to delete alerts for user
            deleteAlertsResult = await alertsService.DeleteAlerts(connection, sessionData.userId)

            # check if error occured, if so raise exception with message
            if deleteAlertsResult.get('error'):
                raise Exception(deleteAlertsResult.get('message'))

            # return delete alerts result in http response
            return JSONResponse(content=deleteAlertsResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error deleting alerts due to server error, try again later.', 'error': True}
        print(f'Error deleting alerts: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)