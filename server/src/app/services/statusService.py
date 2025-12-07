from app.database.database import asyncpg


# function for checking if server is healthy and responsive
async def CheckHealth() -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        resultDict.update({'message': 'Server is healthy and responsive.', 'state': True})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error checking health: {e}.', 'error': True})
    finally:
        return resultDict


# function for checking if server is ready for handeling requests
async def CheckReady(connection: asyncpg.Connection) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # check if database is reachable and responding
        query = 'SELECT 1 AS result'
        queryResult = await connection.fetchrow(query)

        # check if we received result from database
        if queryResult and queryResult['result'] == 1:
            resultDict.update({'message': 'Server is ready to handle requests.', 'state': True})
        else:
            resultDict.update({'message': 'Server is not ready, database is unreachable.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error checking readiness: {e}.', 'error': True})
    finally:
        return resultDict