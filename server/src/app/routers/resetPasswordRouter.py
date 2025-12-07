from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse
from app.database.database import Database
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import rateLimitConfig, limiter
from app.schemas.resetPasswordSchema import SendResetCodeRequest, VerifyResetCodeRequest, BaseResponse, BaseResultResponse, responseModels
from app.services import resetPasswordService

# define router for reset password endpoint
router = APIRouter(prefix=Endpoints.API.ResetPassword.Base.Endpoint(), tags=['Reset Password'])


# endpoint function for sending reset code to user's email for users
@router.post(Endpoints.API.ResetPassword.SendResetCode.Endpoint(), response_model=BaseResponse, responses=responseModels, description='**Send reset code for registered users.**')
@limiter.limit(rateLimitConfig.resetPassword)
async def SendResetCode(request: Request, sendResetCodeRequest: SendResetCodeRequest) -> JSONResponse:
    try:
        # get new database connection from connection pool and start transaction
        async with Database.GetTransaction() as connection:
            # call our send reset code service to send reset code to user's email
            sendResetCodeResult = await resetPasswordService.SendResetCode(connection, sendResetCodeRequest.email)

            # check if error occured, if so raise exception with message
            if sendResetCodeResult.get('error'):
                raise Exception(sendResetCodeResult.get('message'))

            # return send reset code result in http response
            return JSONResponse(content=sendResetCodeResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error sending reset code due to server error, try again later.', 'error': True}
        print(f'Error sending reset code: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endpoint function for handeling reset code verification for users
@router.post(Endpoints.API.ResetPassword.VerifyResetCode.Endpoint(), response_model=BaseResultResponse, responses=responseModels, description='**Verify reset code for registered users.**')
@limiter.limit(rateLimitConfig.resetPassword)
async def VerifyResetCode(request: Request, verifyResetCodeRequest: VerifyResetCodeRequest) -> JSONResponse:
    try:
        # get new database connection from connection pool and start transaction
        async with Database.GetTransaction() as connection:
            # call our verify reset code service to verify reset code for user
            verifyResetCodeResult = await resetPasswordService.VerifyResetCode(connection, verifyResetCodeRequest.email, verifyResetCodeRequest.resetCode)

            # check if error occured, if so raise exception with message
            if verifyResetCodeResult.get('error'):
                raise Exception(verifyResetCodeResult.get('message'))

            # return verify reset code result in http response
            return JSONResponse(content=verifyResetCodeResult, status_code=status.HTTP_200_OK)

    # if exception occured we return error message
    except Exception as e:
        errorResponse = {'state': False, 'message': 'Error verifying reset code due to server error, try again later.', 'error': True}
        print(f'Error verifying reset code: {e}') #log error message
        raise HTTPException(detail=errorResponse, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)