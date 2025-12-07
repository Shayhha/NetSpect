from fastapi import Request, HTTPException, status, Depends
from fastapi.security.api_key import APIKeyHeader
from app.database.database import Database
from app.schemas.sessionsSchema import SessionData
from app.services.sessionsService import CheckSession


# dependency for extracting the session header from authorization header in request for session authentication
sessionHeader = APIKeyHeader(name='Authorization', scheme_name='SessionAuth', description='**Enter your session in the format:** `Session <SessionID>`', auto_error=False)


# dependency function for authenticating given user session in authorization header and returning user's session data
async def SessionAuth(request: Request, session: str=Depends(sessionHeader)) -> SessionData:
    resultDict = {'state': False, 'message': '', 'error': False}  # represents result dict
    try:
        async with Database.GetConnection() as connection:
            # get session list and extract session id from session in authorization header
            sessionList = session.split() if session else []
            sessionId = sessionList[-1] if sessionList else None

            # if authorization header format is invalid we return error
            if len(sessionList) != 2 or sessionList[0].lower() != 'session':
                resultDict.update({'message': 'Invalid authorization header format. Use: Session <SessionID>', 'error': True})
                raise HTTPException(detail=resultDict, status_code=status.HTTP_401_UNAUTHORIZED)

            # check if user's session id is assigned to an active session
            checkSessionResult = await CheckSession(connection, None, sessionId)

            # if check session result failed with error we raise exception with message
            if checkSessionResult.get('error'):
                raise Exception(checkSessionResult.get('message'))

            # else we check if no matching session found, return invalid session message
            elif not checkSessionResult.get('state'):
                resultDict.update({'message': 'Invalid or expired session.'})
                raise HTTPException(detail=resultDict, status_code=status.HTTP_403_FORBIDDEN)

            # return authenticated user session data
            return SessionData(userId=checkSessionResult.get('result').get('userId'), sessionId=sessionId)

    # if http exception we raise and return http response
    except HTTPException:
        raise

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': 'Error verifying session due to server error, try again later.', 'error': True})
        print(f'Error verifying session: {e}') #log error message
        raise HTTPException(detail=resultDict, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)