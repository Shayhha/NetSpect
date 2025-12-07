from app.database.database import asyncpg
from app.utility.utility import Utility


# function for adding session for user in sessions table
async def AddSession(connection: asyncpg.Connection, userId: int) -> dict:
    resultDict = {'state': True, 'message': '', 'result': {'userId': '', 'sessionId': ''}, 'error': False} #represents result dict
    try:
        oldSessionResult = await CheckSession(connection, userId) #check if user has an active session

        # if there's an old session active we delete it from sessions table
        if oldSessionResult.get('state') and oldSessionResult.get('result').get('sessionId'):
            deleteSessionResult = await DeleteSession(connection, userId, oldSessionResult.get('result').get('sessionId')) #delete old session for user
            resultDict.update(deleteSessionResult) #update resultDict based on delete session result

        # check if old session deletion was successful, if so add new user session to sessions table
        if resultDict.get('state') and not resultDict.get('error'):
            # insert new session for user into sessions table
            query = '''
                INSERT INTO sessions (userid) 
                VALUES ($1) 
                RETURNING sessionid, userid
                '''
            queryResult = await connection.fetchrow(query, userId)

            # if we received result we return session id as result
            if queryResult:
                # update result dict with result session id and user id for user
                resultDict.update({'message': 'Added session successfully.', 'result': {'userId': queryResult['userid'], 'sessionId': str(queryResult['sessionid'])}})
            else:
                resultDict.update({'message': 'Failed adding session.', 'state': False})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error adding session: {e}.', 'state': False, 'error': True})
    finally:
        return resultDict


# function for checking if given session is active for user in sessions table
async def CheckSession(connection: asyncpg.Connection, userId: int=None, sessionId: str=None) -> dict:
    resultDict = {'state': False, 'message': '', 'result': {'userId': '', 'sessionId': ''}, 'error': False}
    try:
        query = '' #represents query for check session
        queryResult = None #represents query result

        # check if sessionId given
        if sessionId != None:
            sessionIdUUID = Utility.GetUUID(sessionId) #get uuid from sessionId string
            # check that sessionIdUUID is valid uuid, if not we return invalid session
            if not sessionIdUUID:
                resultDict.update({'message': 'Invalid session.'})
                return resultDict

            # check if session active by sessionId for user is present in sessions table
            query = '''
                SELECT userid, sessionid 
                FROM sessions 
                WHERE sessionid = $1
                '''
            queryResult = await connection.fetchrow(query, sessionIdUUID)

        # else check if userId given
        elif userId != None:
            # check if session active by userId for user is present in sessions table
            query = '''
                SELECT userid, sessionid 
                FROM sessions 
                WHERE userid = $1
                '''
            queryResult = await connection.fetchrow(query, userId)

        # if we received result we return userId and sessionId as result
        if queryResult:
            # update result dict with active session's user id and session id for user
            resultDict.update({'message': 'Active session found successfully.', 'result': {'userId': queryResult['userid'], 'sessionId': str(queryResult['sessionid'])}, 'state': True})
        else:
            resultDict.update({'message': 'No active session found.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error checking session: {e}.', 'error': True})
    finally:
        return resultDict


# function for deleting session for user in sessions table
async def DeleteSession(connection: asyncpg.Connection, userId: int, sessionId: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        sessionIdUUID = Utility.GetUUID(sessionId) #get uuid from sessionId string
        # check that sessionIdUUID is valid uuid, if not we return invalid session
        if not sessionIdUUID:
            resultDict.update({'message': 'Invalid session.'})
            return resultDict

        # delete session for user from sessions table
        query = '''
            DELETE FROM sessions 
            WHERE userid = $1 AND sessionid = $2
            '''
        queryResult = await connection.execute(query, userId, sessionIdUUID)
        rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'Session deleted successfully.', 'state': True})
        else:
            resultDict.update({'message': 'No matching session found.', 'state': True})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error deleting session: {e}.', 'error': True})
    finally:
        return resultDict