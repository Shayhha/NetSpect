from app.database.database import asyncpg


# function for getting all blacklisted mac addresses for user in blacklist table
async def GetBlacklistMacs(connection: asyncpg.Connection, userId: int) -> list:
    # get blacklisted mac addresses for user in blacklist table
    query = '''
        SELECT macaddress 
        FROM blacklist 
        WHERE userid = $1
        '''
    blacklistMacsResult = await connection.fetch(query, userId)
    blacklistMacs = [] #represents our blacklist of mac addresses

    # check if we received blacklisted mac addresses from query
    if blacklistMacsResult:
        # create list of blacklisted mac addresses with given result
        blacklistMacs = [macAddress['macaddress'] for macAddress in blacklistMacsResult]

    # return blacklisted mac addresses for user
    return blacklistMacs


# function for adding a mac address to the blacklist for user in blacklist table
async def AddBlacklistMac(connection: asyncpg.Connection, userId: int, macAddress: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # we first get the existing blacklist for the given user
        existingBlacklistMacs = await GetBlacklistMacs(connection, userId)

        # check if the mac address already exists in the blacklist
        if macAddress in existingBlacklistMacs:
            resultDict.update({'message': 'MAC address is already blacklisted for this user.'})
        else:
            # add blacklisted mac address for user in blacklist table
            query = '''
                INSERT INTO blacklist (userid, macaddress) 
                VALUES ($1, $2)
                '''
            queryResult = await connection.execute(query, userId, macAddress)
            rowsAffected = int(queryResult.split()[-1]) #get how many rows effected

            # we check if operation was successful and rows affected
            if rowsAffected > 0:
                resultDict.update({'message': 'Blacklist MAC added successfully.', 'state': True})
            else:
                resultDict.update({'message': 'Failed adding blacklist MAC.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error adding blacklist MAC: {e}.', 'error': True})
    finally:
        return resultDict


# function for deleting specific mac address for user in blacklist table
async def DeleteBlacklistMac(connection: asyncpg.Connection, userId: int, macAddress: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # delete blacklisted mac address for user from blacklist table
        query = '''
            DELETE FROM blacklist 
            WHERE userid = $1 AND macaddress = $2
            '''
        queryResult = await connection.execute(query, userId, macAddress)
        rowsAffected = int(queryResult.split()[-1]) #get how many rows effected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'Blacklist MAC deleted successfully.', 'state': True})
        else:
            resultDict.update({'message': 'No matching MAC address found.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error deleting blacklist MAC: {e}.', 'error': True})
    finally:
        return resultDict