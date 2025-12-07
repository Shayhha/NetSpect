from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse
from app.database.database import Database
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import rateLimitConfig, limiter
from app.schemas.authSchema import LoginRequest, RegisterRequest, BaseResponse, BaseResultResponse, responseModels
from app.services import authService

# define router for auth endpoint
router = APIRouter(prefix=Endpoints.API.Auth.Base.Endpoint(), tags=['Authentication'])


# endpoint function for handeling login and returning user data for users
@router.post(Endpoints.API.Auth.Login.Endpoint(), response_model=BaseResultResponse, responses=responseModels, description='**Login and retrieve user data for users.**')
@limiter.limit(rateLimitConfig.auth)
async def Login(request: Request, loginRequest: LoginRequest) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our login service to fetch user data
            loginResult = await authService.Login(connection, loginRequest.username, loginRequest.password)

            # check if error occured, if so raise exception with message
            if loginResult.get('error'):
                raise Exception(loginResult.get('message'))

            # return login result in http response
            return JSONResponse(content=loginResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error logging in due to server error, try again later.', 'result': {}, 'error': True}
        print(f'Error logging in: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling registration for users
@router.post(Endpoints.API.Auth.Register.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Register new account for users.**')
@limiter.limit(rateLimitConfig.auth)
async def Register(request: Request, registerRequest: RegisterRequest) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our register service to register user in database
            registerResult = await authService.Register(connection, registerRequest.email, registerRequest.username, registerRequest.password)

            # check if error occured, if so raise exception with message
            if registerResult.get('error'):
                raise Exception(registerResult.get('message'))

            # return register result in http response
            return JSONResponse(content=registerResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error registering due to server error, try again later.', 'error': True}
        print(f'Error registering: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)