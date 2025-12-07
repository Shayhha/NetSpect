from app.database.database import asyncpg
from app.utility.utility import Utility


# function for changing user's email in users table
async def ChangeEmail(connection: asyncpg.Connection, userId: int, newEmail: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # check if the new email is already taken
        emailExists = await CheckEmail(connection, newEmail)
        if emailExists != None:
            resultDict.update({'message': 'Email is already taken.'})
        else:
            # update user's email in users table
            query = '''
                UPDATE users 
                SET email = $1 
                WHERE userid = $2
                '''
            queryResult = await connection.execute(query, newEmail, userId)
            rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

            # we check if operation was successful and rows affected
            if rowsAffected > 0:
                resultDict.update({'message': 'Changed email successfully.', 'state': True})
            else:
                resultDict.update({'message': 'Failed changing email.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error changing email: {e}.', 'error': True})
    finally:
        return resultDict



# fucntion for checking if the email is taken in users table
async def CheckEmail(connection: asyncpg.Connection, email: str, isDeleted: int=None) -> int | None:
    # check if username is present in users table
    query = '''
        SELECT userid 
        FROM users 
        WHERE email = $1
        '''
    queryResult = None #represents query result

    # check if isDeleted given, if so we add it
    if isDeleted != None:
        query += ' AND isdeleted = $2'
        queryResult = await connection.fetchrow(query, email, isDeleted)
    else:
        queryResult = await connection.fetchrow(query, email)

    # if we received result we return userId as result
    return queryResult['userid'] if queryResult else None


# fucntion for changing user's username in users table
async def ChangeUsername(connection: asyncpg.Connection, userId: int, newUsername: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # check if the new username is already taken
        usernameExists = await CheckUsername(connection, newUsername)
        if usernameExists != None:
            resultDict.update({'message': 'Username is already taken.'})
        else:
            # update user's username in users table
            query = '''
                UPDATE users 
                SET username = $1 
                WHERE userid = $2
                '''
            queryResult = await connection.execute(query, newUsername, userId)
            rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

            # we check if operation was successful and rows affected
            if rowsAffected > 0:
                resultDict.update({'message': 'Changed username successfully.', 'state': True})
            else:
                resultDict.update({'message': 'Failed changing username.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error changing username: {e}.', 'error': True})
    finally:
        return resultDict


# function for checking if the username is taken in users table
async def CheckUsername(connection: asyncpg.Connection, username: str, isDeleted: int=None) -> int | None:
    # check if username is present in users table
    query = '''
        SELECT userid 
        FROM users 
        WHERE username = $1
        '''
    queryResult = None #represents query result

    # check if isDeleted given, if so we add it
    if isDeleted != None:
        query += ' AND isdeleted = $2'
        queryResult = await connection.fetchrow(query, username, isDeleted)
    else:
        queryResult = await connection.fetchrow(query, username)

    # if we received result we return userId as result
    return queryResult['userid'] if queryResult else None


# function for updating passowrd of user in users table
async def ChangePassword(connection: asyncpg.Connection, userId: int, newPassword: str, oldPassword: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        newPasswordHash = Utility.ToSHA256(newPassword) #get SHA-256 hash for newPassword
        oldPasswordHash = Utility.ToSHA256(oldPassword) #get SHA-256 hash for oldPassword

        # check that the old password is correct
        oldPasswordValid = await CheckPassword(connection, userId, oldPasswordHash)
        if oldPasswordValid == None:
            resultDict.update({'message': 'Old password is incorrect.'})
        else:
            # update user's password in users table
            query = '''
                UPDATE users 
                SET password = $1 
                WHERE userid = $2
                '''
            queryResult = await connection.execute(query, newPasswordHash, userId)
            rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

            # we check if operation was successful and rows affected
            if rowsAffected > 0:
                resultDict.update({'message': 'Changed password successfully.', 'state': True})
            else:
                resultDict.update({'message': 'Failed changing password.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error changing password: {e}.', 'error': True})
    finally:
        return resultDict


# function for resetting passowrd of user with specified password in users table
async def ResetPassword(connection: asyncpg.Connection, email: str, newPassword: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        newPasswordHash = Utility.ToSHA256(newPassword) #get SHA-256 hash for newPassword

        # reset user's password in users table
        query = '''
            UPDATE users 
            SET password = $1 
            WHERE email = $2
            '''
        queryResult = await connection.execute(query, newPasswordHash, email)
        rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'resetted password successfully.', 'state': True})
        else:
            resultDict.update({'message': 'Failed resetting password.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error resetting password: {e}.', 'error': True})
    finally:
        return resultDict


# function for checking if the provided password is correct for user in users table
async def CheckPassword(connection: asyncpg.Connection, userId: int, password: str, isDeleted: int=None) -> int | None:
    # check if password matches user's password in Users table
    query = '''
        SELECT userid 
        FROM users 
        WHERE userid = $1 AND password = $2
        '''
    queryResult = None #represents query result

    # check if isDeleted given, if so we add it
    if isDeleted != None:
        query += ' AND isdeleted = $3'
        queryResult = await connection.fetchrow(query, userId, password, isDeleted)
    else:
        queryResult = await connection.fetchrow(query, userId, password)

    # if we received result we return userId as result
    return queryResult['userid'] if queryResult else None


# function for deleting user account from alerts, resetcodes, sessions and users tables
async def DeleteAccount(connection: asyncpg.Connection, userId: int) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # delete all alerts for user in alerts table
        alertsQuery = '''
            UPDATE alerts 
            SET isdeleted = 1 
            WHERE userid = $1 AND isdeleted = 0
            '''
        await connection.execute(alertsQuery, userId)

        # delete reset password code for user in resetcodes table
        resetcodesQuery = '''
            DELETE FROM resetcodes 
            WHERE email = (SELECT email FROM users WHERE userid = $1)
            '''
        await connection.execute(resetcodesQuery, userId)

        # delete active session for user in sessions table
        sessionsQuery = '''
            DELETE FROM sessions 
            WHERE userid = $1
            '''
        await connection.execute(sessionsQuery, userId)

        # delete given user from users table
        usersQuery = '''
            UPDATE users 
            SET isdeleted = 1 
            WHERE userid = $1 AND isdeleted = 0
            '''
        usersResult = await connection.execute(usersQuery, userId)
        rowsAffected = int(usersResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'User account deleted successfully.', 'state': True})
        else:
            resultDict.update({'message': 'Failed deleting user account.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error deleting user account: {e}.', 'error': True})
    finally:
        return resultDict


# function for permanently deleting user account from alerts, blacklist resetcodes, sessions and users tables
async def HardDeleteAccount(connection: asyncpg.Connection, userId: int) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # hard delete all alerts for user in alerts table
        alertsQuery = '''
            DELETE FROM alerts 
            WHERE userid = $1
            '''
        await connection.execute(alertsQuery, userId)

        # hard delete all blacklisted mac addresses for user in blacklist table
        blacklistQuery = '''
            DELETE FROM blacklist 
            WHERE userid = $1
            '''
        await connection.execute(blacklistQuery, userId)

        # hard delete reset password code for user in resetcodes table
        resetCodesQuery = '''
            DELETE FROM resetcodes 
            WHERE email = (SELECT email FROM users WHERE userid = $1)
            '''
        await connection.execute(resetCodesQuery, userId)

        # hard delete active session for user in sessions table
        sessionsQuery = '''
            DELETE FROM sessions 
            WHERE userid = $1
            '''
        await connection.execute(sessionsQuery, userId)

        # hard delete given user from users table
        usersQuery = '''
            DELETE FROM users 
            WHERE userid = $1
            '''
        usersResult = await connection.execute(usersQuery, userId)
        rowsAffected = int(usersResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'User account permanently deleted successfully.', 'state': True})
        else:
            resultDict.update({'message': 'Failed permanently deleting user account.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error permanently deleting user account: {e}.', 'error': True})
    finally:
        return resultDict


# fucntion for updating light mode for given user in users table
async def UpdateLightMode(connection: asyncpg.Connection, userId: int, lightMode :int=0) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # update light mode for user in users table
        query = '''
            UPDATE users 
            SET lightmode = $1 
            WHERE userid = $2
            '''
        queryResult = await connection.execute(query, lightMode, userId)
        rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'Updated light mode status.', 'state': True})
        else:
            resultDict.update({'message': 'Failed updating light mode status.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error updating light mode: {e}.', 'error': True})
    finally:
        return resultDict


# fucntion for updating operation mode for given user in users table
async def UpdateOperationMode(connection: asyncpg.Connection, userId: int, operationMode :int=0) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # update operation mode for user in users table
        query = '''
            UPDATE users 
            SET operationmode = $1 
            WHERE userid = $2
            '''
        queryResult = await connection.execute(query, operationMode, userId)
        rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'Updated operation mode status.', 'state': True})
        else:
            resultDict.update({'message': 'Failed updating operation mode status.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error updating operation mode: {e}.', 'error': True})
    finally:
        return resultDict