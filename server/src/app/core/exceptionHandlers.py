from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from slowapi.errors import RateLimitExceeded


# override RequestValidationError method for using our own response with custom dictionary result
async def RequestValidationErrorHandler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # create result dict with error message and details
    resultDict = {'state': False, 'message': 'Invalid request parameters.', 'error': True, 'details': exc.errors()}
    return JSONResponse(content=resultDict, status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)


# override HTTPException method for using our own response with custom dictionary result
async def HTTPExceptionHandler(request: Request, exc: HTTPException) -> JSONResponse:
    # check if given detail is a dictionary, if so return response with given detail
    if isinstance(exc.detail, dict):
        return JSONResponse(content=exc.detail, status_code=exc.status_code)
    # else we set message with given detail and return result dict
    else:
        resultDict = {'state': False, 'message': str(exc.detail), 'error': True}
        return JSONResponse(content=resultDict, status_code=exc.status_code)


# override RateLimitExceeded method for using our own response with custom dictionary result
async def RateLimitExceededHandler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    # create result dict with error message and details
    resultDict = {'state': False, 'message': 'Too many requests, try again later.', 'error': False}
    return JSONResponse(content=resultDict, status_code=status.HTTP_429_TOO_MANY_REQUESTS)