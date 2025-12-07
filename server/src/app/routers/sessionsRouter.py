from fastapi import APIRouter, Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from app.database.database import Database
from app.schemas.sessionsSchema import SessionData, CheckSessionRequest, DeleteSessionRequest, BaseResponse, BaseResultResponse, responseModels
from app.dependancies.sessionAuth import SessionAuth
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import rateLimitConfig, limiter
from app.services import sessionsService

# define router for sessions endpoint
router = APIRouter(prefix=Endpoints.API.Sessions.Base.Endpoint(), tags=['Sessions'])


# endpoint function for handeling check session for users
@router.get(Endpoints.API.Sessions.CheckSession.Endpoint(), response_model=BaseResultResponse, responses=responseModels, description='**Check session state for users.**')
@limiter.limit(rateLimitConfig.api)
async def CheckSession(request: Request, checkSessionRequest: CheckSessionRequest=None, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our check session service to check user session
            checkSessionResult = await sessionsService.CheckSession(connection, None, sessionData.sessionId)

            # check if error occured, if so raise exception with message
            if checkSessionResult.get('error'):
                raise Exception(checkSessionResult.get('message'))

            # return check session result in http response
            return JSONResponse(content=checkSessionResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error checking session due to server error, try again later.', 'error': True}
        print(f'Error checking session: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling delete session for users
@router.delete(Endpoints.API.Sessions.DeleteSession.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Delete session for users.**')
@limiter.limit(rateLimitConfig.api)
async def DeleteSession(request: Request, deleteSessionRequest: DeleteSessionRequest=None, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our delete session service to delete user session
            deleteSessionResult = await sessionsService.DeleteSession(connection, sessionData.userId, sessionData.sessionId)

            # check if error occured, if so raise exception with message
            if deleteSessionResult.get('error'):
                raise Exception(deleteSessionResult.get('message'))

            # return delete session result in http response
            return JSONResponse(content=deleteSessionResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error deleting session due to server error, try again later.', 'error': True}
        print(f'Error deleting session: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)