from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from app.database.database import Database
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import rateLimitConfig, limiter
from app.schemas.statusSchema import CheckRootRequest, CheckHealthRequest, CheckReadyRequest, BaseResponse, responseModels
from app.services import statusService

# define router for status endpoint
router = APIRouter(tags=['Status'])


# endpoint function for handeling check root endpoint and redirects to check health for users
@router.get(Endpoints.Base, response_model=BaseResponse, responses=responseModels, description='**Check root redirects to check health for users.**')
@limiter.limit(rateLimitConfig.api)
async def CheckRoot(request: Request, checkRootRequest: CheckRootRequest=None) -> RedirectResponse:
    # redirect to our check health endpoint
    return RedirectResponse(url=Endpoints.Health)


# endpoint function for handeling check health for users
@router.get(Endpoints.Health, response_model=BaseResponse, responses=responseModels, description='**Check server health for users.**')
@limiter.limit(rateLimitConfig.api)
async def CheckHealth(request: Request, checkHealthRequest: CheckHealthRequest=None) -> JSONResponse:
    try:
        # call our check health service and check if server is healty
        checkHealthResult = await statusService.CheckHealth()

        # check if error occured, if so raise exception with message
        if checkHealthResult.get('error'):
            raise Exception(checkHealthResult.get('message'))
        
        # check if check health failed, if so raise http exeption
        elif not checkHealthResult.get('state'):
            raise HTTPException(detail=checkHealthResult, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

        # return check health result in http response
        return JSONResponse(content=checkHealthResult, status_code=status.HTTP_200_OK)

    # if http exception we raise and return http response
    except HTTPException:
        raise

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error checking health due to server error, try again later.', 'error': True}
        print(f'Error checking health: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling check ready for users
@router.get(Endpoints.Ready, response_model=BaseResponse, responses=responseModels, description='**Check server readiness for users.**')
@limiter.limit(rateLimitConfig.api)
async def CheckReady(request: Request, checkReadyRequest: CheckReadyRequest=None) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our check ready service and check if server ready for requests
            checkReadyResult = await statusService.CheckReady(connection)

            # check if error occured, if so raise exception with message
            if checkReadyResult.get('error'):
                raise Exception(checkReadyResult.get('message'))

            # check if check ready failed, if so raise http exeption
            elif not checkReadyResult.get('state'):
                raise HTTPException(detail=checkReadyResult, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

            # return check ready result in http response
            return JSONResponse(content=checkReadyResult, status_code=status.HTTP_200_OK)

    # if http exception we raise and return http response
    except HTTPException:
        raise

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error checking readiness due to server error, try again later.', 'error': True}
        print(f'Error checking readiness: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)