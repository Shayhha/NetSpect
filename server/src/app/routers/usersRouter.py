from fastapi import APIRouter, Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from app.database.database import Database
from app.schemas.sessionsSchema import SessionData
from app.dependancies.sessionAuth import SessionAuth
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import rateLimitConfig, limiter
from app.schemas.userSchema import ChangeEmailRequest, ChangeUsernameRequest, ChangePasswordRequest, DeleteAccountRequest, HardDeleteAccountRequest, UpdateLightModeRequest, UpdateOperationModeRequest, BaseResponse, responseModels
from app.services import usersService

# define router for users endpoint
router = APIRouter(prefix=Endpoints.API.Users.Base.Endpoint(), tags=['Users'])


# endpoint function for handeling change email for users
@router.put(Endpoints.API.Users.ChangeEmail.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Change email for users.**')
@limiter.limit(rateLimitConfig.api)
async def ChangeEmail(request: Request, changeEmailRequest: ChangeEmailRequest, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our change email service and change email for user
            changeEmailResult = await usersService.ChangeEmail(connection, sessionData.userId, changeEmailRequest.newEmail)

            # check if error occured, if so raise exception with message
            if changeEmailResult.get('error'):
                raise Exception(changeEmailResult.get('message'))

            # return change email result in http response
            return JSONResponse(content=changeEmailResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error changing email due to server error, try again later.', 'error': True}
        print(f'Error changing email: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling change username for users
@router.put(Endpoints.API.Users.ChangeUsername.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Change username for users.**')
@limiter.limit(rateLimitConfig.api)
async def ChangeUsername(request: Request, changeUsernameRequest: ChangeUsernameRequest, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our change username service and change username for user
            changeEmailResult = await usersService.ChangeUsername(connection, sessionData.userId, changeUsernameRequest.newUsername)

            # check if error occured, if so raise exception with message
            if changeEmailResult.get('error'):
                raise Exception(changeEmailResult.get('message'))

            # return change username result in http response
            return JSONResponse(content=changeEmailResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error changing username due to server error, try again later.', 'error': True}
        print(f'Error changing username: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling change password for users
@router.put(Endpoints.API.Users.ChangePassword.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Change password for users.**')
@limiter.limit(rateLimitConfig.api)
async def ChangePassword(request: Request, changePasswordRequest: ChangePasswordRequest, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our change password service and change password for user
            changePasswordResult = await usersService.ChangePassword(connection, sessionData.userId, changePasswordRequest.newPassword, changePasswordRequest.oldPassword)

            # check if error occured, if so raise exception with message
            if changePasswordResult.get('error'):
                raise Exception(changePasswordResult.get('message'))

            # return change password result in http response
            return JSONResponse(content=changePasswordResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error changing password due to server error, try again later.', 'error': True}
        print(f'Error changing password: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling account deletion for users
@router.delete(Endpoints.API.Users.DeleteAccount.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Delete account for users.**')
@limiter.limit(rateLimitConfig.api)
async def DeleteAccount(request: Request, deleteAccountRequest: DeleteAccountRequest=None, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool and start transaction
        async with Database.GetTransaction() as connection:
            # call our delete account service and delete account for user
            deleteAccountResult = await usersService.DeleteAccount(connection, sessionData.userId)

            # check if error occured, if so raise exception with message
            if deleteAccountResult.get('error'):
                raise Exception(deleteAccountResult.get('message'))

            # return delete account result in http response
            return JSONResponse(content=deleteAccountResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error deleting account due to server error, try again later.', 'error': True}
        print(f'Error deleting account: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling permanent account deletion for users
@router.delete(Endpoints.API.Users.HardDeleteAccount.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Hard delete account for users.**')
@limiter.limit(rateLimitConfig.api)
async def HardDeleteAccount(request: Request, hardDeleteAccountRequest: HardDeleteAccountRequest=None, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool and start transaction
        async with Database.GetTransaction() as connection:
            # call our hard delete account service and permanently delete account for user
            hardDeleteAccountResult = await usersService.HardDeleteAccount(connection, sessionData.userId)

            # check if error occured, if so raise exception with message
            if hardDeleteAccountResult.get('error'):
                raise Exception(hardDeleteAccountResult.get('message'))

            # return hard delete account result in http response
            return JSONResponse(content=hardDeleteAccountResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error permanently deleting account due to server error, try again later.', 'error': True}
        print(f'Error permanently deleting account: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling update light mode for users
@router.put(Endpoints.API.Users.UpdateLightMode.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Update light mode state for users.**')
@limiter.limit(rateLimitConfig.api)
async def UpdateLightMode(request: Request, updateLightModeRequest: UpdateLightModeRequest, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our update light mode service and update light mode for user
            updateLightModeResult = await usersService.UpdateLightMode(connection, sessionData.userId, updateLightModeRequest.lightMode)

            # check if error occured, if so raise exception with message
            if updateLightModeResult.get('error'):
                raise Exception(updateLightModeResult.get('message'))

            # return update light mode result in http response
            return JSONResponse(content=updateLightModeResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error updating light mode due to server error, try again later.', 'error': True}
        print(f'Error updating light mode: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling update operation mode for users
@router.put(Endpoints.API.Users.UpdateOperationMode.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Update operation mode state for users.**')
@limiter.limit(rateLimitConfig.api)
async def UpdateOperationMode(request: Request, updateOperationModeRequest: UpdateOperationModeRequest, sessionData: SessionData=Depends(SessionAuth)) -> JSONResponse:
    try:
        # get new database connection from connection pool
        async with Database.GetConnection() as connection:
            # call our update operation mode service and update operation mode for user
            updateOperationModeResult = await usersService.UpdateOperationMode(connection, sessionData.userId, updateOperationModeRequest.operationMode)

            # check if error occured, if so raise exception with message
            if updateOperationModeResult.get('error'):
                raise Exception(updateOperationModeResult.get('message'))

            # return update operation mode result in http response
            return JSONResponse(content=updateOperationModeResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error updating operation mode due to server error, try again later.', 'error': True}
        print(f'Error updating operation mode: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)