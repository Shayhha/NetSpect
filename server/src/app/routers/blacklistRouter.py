from fastapi import APIRouter, Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from app.database.database import Database
from app.schemas.sessionsSchema import SessionData
from app.dependancies.sessionAuth import SessionAuth
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import rateLimitConfig, limiter
from app.schemas.blacklistSchema import AddBlacklistMacRequest, DeleteBlacklistMacRequest, BaseResponse, responseModels
from app.services import blacklistService

# define router for blacklist endpoint
router = APIRouter(prefix=Endpoints.API.Blacklist.Base.Endpoint(), tags=['Blacklist'])


# endpoint function for handeling add blacklist mac for users
@router.post(Endpoints.API.Blacklist.AddBlacklistMac.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Add MAC address to blacklist for users.**')
@limiter.limit(rateLimitConfig.api)
async def AddBlacklistMac(request: Request, addBlacklistMacRequest: AddBlacklistMacRequest, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our add blacklist mac service to add mac address to blacklist for user
            addBlacklistMacResult = await blacklistService.AddBlacklistMac(connection, sessionData.userId, addBlacklistMacRequest.macAddress)

            # check if error occured, if so raise exception with message
            if addBlacklistMacResult.get('error'):
                raise Exception(addBlacklistMacResult.get('message'))

            # return add blacklist mac result in http response
            return JSONResponse(content=addBlacklistMacResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error adding blacklist MAC due to server error, try again later.', 'error': True}
        print(f'Error adding blacklist MAC: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling delete blacklist mac for users
@router.post(Endpoints.API.Blacklist.DeleteBlacklistMac.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Delete MAC address from blacklist for users.**')
@limiter.limit(rateLimitConfig.api)
async def DeleteBlacklistMac(request: Request, deleteBlacklistMacRequest: DeleteBlacklistMacRequest, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our delete blacklist mac service to delete mac address from blacklist for user
            deleteBlacklistMacResult = await blacklistService.DeleteBlacklistMac(connection, sessionData.userId, deleteBlacklistMacRequest.macAddress)

            # check if error occured, if so raise exception with message
            if deleteBlacklistMacResult.get('error'):
                raise Exception(deleteBlacklistMacResult.get('message'))

            # return delete blacklist mac result in http response
            return JSONResponse(content=deleteBlacklistMacResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error deleting blacklist MAC due to server error, try again later.', 'error': True}
        print(f'Error deleting blacklist MAC: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)