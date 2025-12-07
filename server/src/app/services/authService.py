from app.database.database import asyncpg
from app.utility.utility import Utility
from app.services import usersService, sessionsService, blacklistService, alertsService


# function for logging into user account for user in users table
async def Login(connection: asyncpg.Connection, username: str, password: str) -> dict:
    resultDict = {'state': False, 'message': '', 'result': {}, 'error': False} #represents result dict
    try:
        passwordHash = Utility.ToSHA256(password); #get SHA-256 hash for password

        # query to fetch user details
        query = '''
            SELECT userid, email, username, lightmode, operationmode 
            FROM users 
            WHERE username = $1 AND password = $2 AND isdeleted = 0
            '''
        queryResult = await connection.fetchrow(query, username, passwordHash)

        # check if we received result, if so initialize user data dictionary
        if queryResult:
            # represents user data dictionary
            userData = {
                'userId': queryResult['userid'],
                'email': queryResult['email'],
                'username': queryResult['username'],
                'lightMode': queryResult['lightmode'],
                'operationMode': queryResult['operationmode']
            }

            sessionResult = await sessionsService.AddSession(connection, userData.get('userId')) #create new session for logged in user
            # check if we sucessfully created a new session
            if sessionResult.get('state') and sessionResult.get('result') and sessionResult.get('result').get('sessionId'):
                # set session id in user data
                userData['sessionId'] = sessionResult.get('result').get('sessionId')

                # retrieve alert list, pie chart data, analytics chart data, black list and number of detections with user service functions
                userData['alertList'] = await alertsService.GetAlerts(connection, userData.get('userId'))
                userData['pieChartData'] = await alertsService.GetPieChartData(connection, userData.get('userId'))
                userData['analyticsChartData'] = await alertsService.GetAnalyticsChartData(connection, userData.get('userId'))
                userData['blackList'] = await blacklistService.GetBlacklistMacs(connection, userData.get('userId'))
                userData['numberOfDetections'] = len(userData.get('alertList'))

                # set state and result with successful login attempt with user data
                resultDict.update({'message': 'Login successful.', 'result': userData, 'state': True})

            else:
                resultDict.update({'message': 'Login failed. Try again later.'})
        else:
            resultDict.update({'message': 'Invalid username or password. Please try again.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error logging in: {e}.', 'error': True})
    finally:
        return resultDict


# function for adding a new user to the users table
async def Register(connection: asyncpg.Connection, email: str, username: str, password: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        passwordHash = Utility.ToSHA256(password) #get SHA-256 hash for password
        emailExists = await usersService.CheckEmail(connection, email) #check if email already exists in database
        usernameExists = await usersService.CheckUsername(connection, username) #check if username already exists in database

        # check if email or username already exists in database and send relevent error message
        if emailExists != None and usernameExists != None:
            resultDict.update({'message': 'Both email and username are already taken, please try different ones.'})
        elif emailExists != None:
                resultDict.update({'message': 'Email is already taken, please try another one.'})
        elif usernameExists != None:
                resultDict.update({'message': 'Username is already taken, please try another one.'})
        else:
            # insert new user into users table
            query = '''
                INSERT INTO users (email, username, password) 
                VALUES ($1, $2, $3)
                '''
            queryResult = await connection.execute(query, email, username, passwordHash)
            rowsAffected = int(queryResult.split()[-1]) #get how many rows effected

            # we check if operation was successful and rows affected
            if rowsAffected > 0:
                resultDict.update({'message': 'Registration successful.', 'state': True})
            else:
                resultDict.update({'message': 'Registration failed. Try again later.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error registering: {e}.', 'error': True})
    finally:
        return resultDict

