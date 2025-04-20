import sys, os, pyodbc
from PySide6.QtCore import Signal, Slot, QThread
from dotenv import load_dotenv
from smtplib import SMTP
from email.message import EmailMessage
from pathlib import Path

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located

#---------------------------------------------------------SQL-THREAD------------------------------------------------------------#
# thread for performing various SQL queries and receiving or updating data in database
class SQL_Thread(QThread):
    # define signals for interacting with main gui thread
    loginResultSignal = Signal(dict)
    registrationResultSignal = Signal(dict)
    changeEmailResultSignal = Signal(dict)
    changeUsernameResultSignal = Signal(dict)
    changePasswordResultSignal = Signal(dict)
    resetPasswordResultSignal = Signal(dict)
    deleteAccountResultSignal = Signal(dict)
    addAlertResultSignal = Signal(dict)
    deleteAlertsResultSignal = Signal(dict)
    addBlacklistMacResultSignal = Signal(dict)
    deleteBlacklistMacResultSignal = Signal(dict)
    updateLightModeResultSignal = Signal(dict)
    updateOperationtModeResultSignal = Signal(dict)
    sendCodeResultSignal = Signal(dict)
    connectionResultSignal = Signal(dict)
    initEmailCredentilsResultSignal = Signal(dict)
    finishSignal = Signal(dict)

    # constructor of sql thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.envFilePath = currentDir.parent / 'database' / '.env' #represents env file path
        self.connection = None #represents our connection for SQL server database
        self.cursor = None #represents our cursor for executig SQL commands
        self.appEmail = None #represents app email for sending reset codes
        self.appPassword = None #represents app password for sending reset codes
        self.appEmailHost = None #represents app email host for sending reset codes


    # method for stopping sql thread
    @Slot()
    def StopThread(self):
        if self.isRunning():
            self.quit() #exit main loop and end task
            self.wait() #we wait to ensure thread cleanup


    # method for connecting to SQL server database and initialize connection
    def Connect(self):
        stateDict = {'state': True, 'message': ''} #represents state of database connection
        maxRetries = 3 #represents max retries before we declare failed connection
        failedaAttempts = 0 #represents number of failed attempts

        # check if env file does'nt exists, if so we return error message
        if not self.envFilePath.exists():
            stateDict.update({'state': False, 'message': 'Database .env file was not found. Please ensure it exists in database folder.'})
            return stateDict

        # load environment variables from env file
        load_dotenv(dotenv_path=self.envFilePath)

        # receive necessary database credentials from env file for database connection
        connectionString = os.getenv('DB_CONNECTION_STRING')

        # check if env file missing the connection string, if so we return error message
        if not connectionString:
            stateDict.update({'state': False, 'message': 'Database connection string is missing from .env file. Please ensure the file contains a valid connection string.'})
            return stateDict
        
        # we try to connect to the database, if failed more then max attemps we return failed connection
        while failedaAttempts < maxRetries:
            try:
                # try to initialize database connection and cursor 
                self.connection = pyodbc.connect(connectionString)
                self.cursor = self.connection.cursor()
                stateDict.update({'state': True, 'message': 'Connected to database successfully.'})
                return stateDict
            except pyodbc.Error as e:
                failedaAttempts += 1 #increment failed attempt
                # if reached max attempts we finish with failed connection
                if failedaAttempts == maxRetries:
                    stateDict.update({'state': False, 'message': 'Database connection failed. The application will function, but login will be unavailable.'})
                    return stateDict


    # method for closing database connection and curosr
    def Close(self):
        # close connection and cursor
        if self.cursor:
            self.cursor.close() #close cursor
        if self.connection: 
            self.connection.close() #close connection


    # method for initializing app email credentils from env file
    def InitEmailCredentils(self):
        stateDict = {'state': True, 'message': ''} #represents state of app email initialization

        # receive necessary app email credentials from env file for reset code emails
        self.appEmail = os.getenv('APP_EMAIL')
        self.appPassword = os.getenv('APP_PASSWORD')
        self.appEmailHost = os.getenv('APP_EMAIL_HOST')

        # check if env file missing the app email credentials, if so we return error message
        if not self.appEmail or not self.appPassword or not self.appEmailHost:
            stateDict.update({'state': False, 'message': 'App email credentials are missing from .env file. Please ensure the file contains valid app email credentials.'})
        return stateDict


    # run method for performing various database related commands
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            # initialize database connection and send result to main thread
            connectionResult = self.Connect() #connect to our SQL server database
            stateDict.update({'state': connectionResult.get('state')}) #set the connection result state in stateDict
            self.connectionResultSignal.emit(connectionResult) #send connection result signal to main thread

            # initialize app email credentils and send result to main thread
            emailCredentilsResult = self.InitEmailCredentils()
            self.initEmailCredentilsResultSignal.emit(emailCredentilsResult) #send email credentils result signal to main thread

            # execute thread process only if connection was established
            if stateDict.get('state'):
                self.exec() #execute sql thread process
        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
        finally:
            self.Close() #close database connection
            self.finishSignal.emit(stateDict) #send finish signal to main thread


    #----------------------------------------------SQL-FUNCTIONS-------------------------------------------------#
    # method for logging into account in main app
    @Slot(str, str)
    def Login(self, username, password):
        resultDict = {'state': False, 'message': '', 'result': None, 'error': False} #represents result dict
        try:
            # query to fetch user details
            query = '''
                SELECT userId, email, userName, lightMode, operationMode
                FROM Users 
                WHERE userName = ? AND password = ? AND isDeleted = 0
                '''
            self.cursor.execute(query, (username, password))
            result = self.cursor.fetchone()
            
            if result:
                # represents user data dictionary
                userData = {
                    'userId': result[0],
                    'email': result[1],
                    'userName': result[2],
                    'lightMode': result[3],
                    'operationMode': result[4]
                }
                
                # retrieve alert list, pie chart data, analytics chart data, black list and num of detections with helper functions
                userData['alertList'] = self.GetAlerts(userData.get('userId'))
                userData['pieChartData'] = self.GetPieChartData(userData.get('userId'))
                userData['analyticsChartData'] = self.GetAnalyticsChartData(userData.get('userId'))
                userData['blackList'] = self.GetBlacklistMacs(userData.get('userId'))
                userData['numberOfDetections'] = len(userData.get('alertList'))

                # set state and result with successful login attempt with user data
                resultDict['result'] = userData
                resultDict['state'] = True
            else:
                resultDict['message'] = 'Invalid username or password. Please try again.'
        
        except Exception as e:
            resultDict['message'] = f'Error logging in: {e}.'
            resultDict['error'] = True
        finally:
            # emit signal with complete user data including alerts and blacklist to main thread
            self.loginResultSignal.emit(resultDict)


    # method for adding a new user to the Users table
    @Slot(str, str, str)
    def Register(self, email, username, password):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            emailExists = self.CheckEmail(email) #check if email already exists in database
            usernameExists = self.CheckUserName(username) #check if username already exists in database

            # check if email or username already exists in database and send relevent error message
            if emailExists and usernameExists:
                resultDict['message'] = 'Both email and username are already taken, please try different ones.'
            elif emailExists:
                resultDict['message'] = 'Email is already taken, please try another one.'
            elif usernameExists:
                resultDict['message'] = 'Username is already taken, please try another one.'
            else:
                # insert new user into Users table
                query = '''
                    INSERT INTO Users (email, userName, password) 
                    VALUES (?, ?, ?)
                    '''
                self.cursor.execute(query, (email, username, password))
                
                # we check if operation was successful
                if self.cursor.rowcount > 0:
                    self.connection.commit() #commit transaction
                    resultDict['message'] = 'Registration successful.'
                    resultDict['state'] = True
                else:
                    resultDict['message'] = 'Registration failed.'
        
        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error registering: {e}.'
            resultDict['error'] = True
        finally:
            # emit registration signal to main thread
            self.registrationResultSignal.emit(resultDict)

    
    # method for changing user's email in Users table
    @Slot(int, str)
    def ChangeEmail(self, userId, newEmail):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # check if the new email is already taken
            if self.CheckEmail(newEmail):
                resultDict['message'] = 'Email is already taken.'
            
            else:
                # otherwise, update the email
                query = '''
                    UPDATE Users 
                    SET email = ? 
                    WHERE userId = ?
                    '''
                self.cursor.execute(query, (newEmail, userId))
            
                if self.cursor.rowcount > 0:
                    self.connection.commit() #commit the transaction for update
                    resultDict['message'] = 'Changed email successfully.'
                    resultDict['state'] = True
                else:
                    resultDict['message'] = 'Failed changing email.'
            
        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error changing email: {e}.'
            resultDict['error'] = True
        finally:
            # emit change email signal to main thread
            self.changeEmailResultSignal.emit(resultDict)


    # method to check if the email is taken in database
    @Slot(str)
    def CheckEmail(self, email, isDeleted=None):
        # check if username is present in Users table
        query = '''
            SELECT userId
            FROM Users 
            WHERE email = ?
            '''
        
        # check if isDeleted given, if so we add it
        if isDeleted:
            query += 'AND isDeleted = ?'
            self.cursor.execute(query, (email, isDeleted))
        else:
            self.cursor.execute(query, (email,))

        result = self.cursor.fetchone()
        return result[0] if result else None

    
    # method for changing user's username in Users table
    @Slot(int, str)
    def ChangeUserName(self, userId, newUsername):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # check if the new username is already taken
            if self.CheckUserName(newUsername):
                resultDict['message'] = 'Username is already taken.'
            
            else:
                # otherwise, update the username
                query = '''
                    UPDATE Users 
                    SET userName = ? 
                    WHERE userId = ?
                    '''
                self.cursor.execute(query, (newUsername, userId))
            
                if self.cursor.rowcount > 0:
                    self.connection.commit() #commit the transaction for update
                    resultDict['message'] = 'Changed username successfully.'
                    resultDict['state'] = True
                else:
                    resultDict['message'] = 'Failed changing username.'
            
        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error changing username: {e}.'
            resultDict['error'] = True
        finally:
            # emit change username signal to main thread
            self.changeUsernameResultSignal.emit(resultDict)


    # method to check if the username is taken in database
    @Slot(str)
    def CheckUserName(self, username, isDeleted=None):
        # check if username is present in Users table
        query = '''
            SELECT userId
            FROM Users 
            WHERE userName = ?
            '''
        
        # check if isDeleted given, if so we add it
        if isDeleted:
            query += 'AND isDeleted = ?'
            self.cursor.execute(query, (username, isDeleted))
        else:
            self.cursor.execute(query, (username,))

        result = self.cursor.fetchone()
        return result[0] if result else None


    # method for updating passowrd of user in Users table
    @Slot(int, str, str)
    def ChangePassword(self, userId, newPassword, oldPassword):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # check that the old password is correct
            if not self.CheckPassword(userId, oldPassword):
                resultDict['message'] = 'Old password is incorrect.'
            else:
                # update the password in the database
                query = '''
                    UPDATE Users SET 
                    password = ? 
                    WHERE userId = ?
                    '''
                self.cursor.execute(query, (newPassword, userId))
                
                if self.cursor.rowcount > 0:
                    self.connection.commit() #commit the transaction for the update
                    resultDict['message'] = 'Password updated successfully.'
                    resultDict['state'] = True
                else:
                    resultDict['message'] = 'Password update failed.'

        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error changing password: {e}.'
            resultDict['error'] = True
        finally:
            # emit change password signal to main thread
            self.changePasswordResultSignal.emit(resultDict)


    # method for resetting passowrd of user with specified password in Users table
    @Slot(int, str, str)
    def ResetPassword(self, email, newPassword):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # reset the password in the database
            query = '''
                UPDATE Users SET 
                password = ? 
                WHERE email = ?
                '''
            self.cursor.execute(query, (newPassword, email))
            
            if self.cursor.rowcount > 0:
                self.connection.commit() #commit the transaction for the update
                resultDict['message'] = 'password resetted successfully.'
                resultDict['state'] = True
            else:
                resultDict['message'] = 'Password reset failed.'

        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error resetting password: {e}.'
            resultDict['error'] = True
        finally:
            # emit reset password signal to main thread
            self.resetPasswordResultSignal.emit(resultDict)


    # method for checking if the provided password is correct for given user
    @Slot(int, str)
    def CheckPassword(self, userId, password, isDeleted=None):
        # check if password matches user's password in Users table
        query = '''
            SELECT userId
            FROM Users 
            WHERE userId = ? AND password = ?
            '''

        # check if isDeleted given, if so we add it
        if isDeleted:
            query += 'AND isDeleted = ?'
            self.cursor.execute(query, (userId, password, isDeleted))
        else:
            self.cursor.execute(query, (userId, password))

        result = self.cursor.fetchone()
        return result[0] if result else None
    

    # method for deleting user account from Users table
    @Slot(int)
    def DeleteAccount(self, userId):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # set autocommit to false for executing both queires together
            self.connection.autocommit = False

            # delete all alerts for user in Alerts table and delete user in Users table
            query = '''
                BEGIN
                    UPDATE Alerts 
                    SET isDeleted = 1 
                    WHERE userId = ?

                    UPDATE Users 
                    SET isDeleted = 1 
                    WHERE userId = ?
                END
                '''
            self.cursor.execute(query, (userId, userId))
            
            if self.cursor.rowcount > 0:
                self.connection.commit() #commit the transaction for the update
                resultDict['message'] = 'User account deleted successfully.'
                resultDict['state'] = True
            else:
                resultDict['message'] = 'Failed deleting user account.'

        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error deleting user account: {e}.'
            resultDict['error'] = True
        finally:
            # set autocommit back to true for next queries
            self.connection.autocommit = True
            # emit delete account signal to main thread
            self.deleteAccountResultSignal.emit(resultDict)


    # method for getting all alerts that registered for given user in decreasing order
    @Slot(int)
    def GetAlerts(self, userId):
        query = '''
            SELECT interface, attackType, sourceIp, sourceMac, 
                destinationIp, destinationMac, protocol, osType, timestamp
            FROM Alerts
            WHERE userId = ? AND isDeleted = 0
            ORDER BY CONVERT(datetime, SUBSTRING(timestamp, 10, 8) + ' ' + SUBSTRING(timestamp, 1, 8), 3) ASC
            '''
        self.cursor.execute(query, (userId,))
        alerts = self.cursor.fetchall()
        alertsList = [] #represents our alerts list

        # check if we received alerts from query
        if alerts:
            # iterate over each row and add it as a dictionary to list
            for row in alerts:
                alert = {
                    'interface': row[0],
                    'attackType': row[1],
                    'srcIp': row[2],
                    'srcMac': row[3],
                    'dstIp': row[4],
                    'dstMac': row[5],
                    'protocol': row[6],
                    'osType': row[7],
                    'timestamp': row[8]
                }
                alertsList.append(alert)

        # return list of alerts for user
        return alertsList
    

    # method for getting number of attacks from each type in Alerts table for pie chart
    @Slot(int)
    def GetPieChartData(self, userId):
        query = '''
            SELECT attackType, COUNT(*) AS attackCount
            FROM Alerts
            WHERE userId = ? AND isDeleted = 0
            GROUP BY attackType
            '''
        self.cursor.execute(query, (userId,))
        result = self.cursor.fetchall()
        pieChartData = {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0} #represents dict of attacks count

        # check if we received result from query
        if result:
            # iterate over each row and update our pieChartData dictionary
            for row in result:
                # initialize parameters based on row values
                attackType, attackCount = row[0], row[1]

                # check if attack type is present in our pieChartData dictionary
                if attackType in pieChartData:
                    # set corrent attack type with its attack counter from database
                    pieChartData[attackType] = attackCount
        
        return pieChartData


    # method for getting number of attacks in each year and also in each month of each year in Alerts table for analytics charts
    @Slot(int)
    def GetAnalyticsChartData(self, userId):
        # we get the yearly attack types that occured (month index 0) and also the monthly attack types that occured (month index 1-12)
        query = '''
            SELECT YEAR(attackTable.date) AS year, 0 AS month, attackTable.attackType, COUNT(*) AS attackCount
            FROM (
                SELECT CONVERT(datetime, SUBSTRING(timestamp, 10, 8) + ' ' + SUBSTRING(timestamp, 1, 8), 3) AS date, attackType
                FROM Alerts
                WHERE userId = ? AND isDeleted = 0
            ) AS attackTable
            GROUP BY YEAR(attackTable.date), attackType

            UNION ALL

            SELECT YEAR(attackTable.date) AS year, MONTH(attackTable.date) AS month, attackTable.attackType, COUNT(*) AS attackCount
            FROM (
                SELECT CONVERT(datetime, SUBSTRING(timestamp, 10, 8) + ' ' + SUBSTRING(timestamp, 1, 8), 3) AS date, attackType
                FROM Alerts
                WHERE userId = ? AND isDeleted = 0
            ) AS attackTable
            GROUP BY YEAR(attackTable.date), MONTH(attackTable.date), attackType

            ORDER BY year, month, attackType ASC
            '''
        self.cursor.execute(query, (userId, userId))
        result = self.cursor.fetchall()

        # chartData represents dictionary of years, each year has dictionary of months, where each month has dictionary of attack types with their attack counter
        # yearData represents dictionary of years, each year has dictionary of attack types with their attack counter related to this year
        analyticsChartData = {'chartData': {}, 'yearData': {}}

        # check if we received result from query
        if result:
            # iterate over each row and update our analyticsChartData dictionary
            for row in result:
                # initialize parameters based on row values
                year, month, attackType, attackCount = str(row[0]), row[1], row[2], row[3]

                # initialize chartData for the year if not present in our dict
                if year not in analyticsChartData.get('chartData'):
                    analyticsChartData['chartData'][year] = {attackMonth: {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0} for attackMonth in range(1, 13)}

                # initialize yearData for the year if not present in our dict
                if year not in analyticsChartData.get('yearData'):
                    analyticsChartData['yearData'][year] = {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0}

                # check if month is not zero, if so it means its monthly attack type data
                if month != 0:
                    # check if attack type is present in our chartData dictionary
                    if attackType in analyticsChartData.get('chartData').get(year).get(month):
                        analyticsChartData['chartData'][year][month][attackType] = attackCount

                # else it means its yearly attack type data
                else:
                    # check if attack type is present in our yearData dictionary
                    if attackType in analyticsChartData.get('yearData').get(year):
                        analyticsChartData['yearData'][year][attackType] = attackCount

        return analyticsChartData
    

    # method for adding alert for user in Alerts table
    @Slot(int, str, str, str, str, str, str, str, str)
    def AddAlert(self, userId, interface, attackType, sourceIp, sourceMac, destinationIp, destinationMac, protocol, osType, timestamp):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            query = '''
                INSERT INTO Alerts (userId, interface, attackType, sourceIp, sourceMac, 
                                    destinationIp, destinationMac, protocol, osType, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                '''
            self.cursor.execute(query, (userId, interface, attackType, sourceIp, sourceMac, 
                                        destinationIp, destinationMac, protocol, osType, timestamp))
            
            if self.cursor.rowcount > 0:
                self.connection.commit()
                resultDict['message'] = 'Added alert successfully.'
                resultDict['state'] = True
            else:
                resultDict['message'] = 'Failed adding alert.'

        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error adding alert: {e}.'
            resultDict['error'] = True
        finally:
            # emit add alert signal to main thread
            self.addAlertResultSignal.emit(resultDict)


    # method for deleting all alerts for user in Alerts table
    @Slot(int)
    def DeleteAlerts(self, userId):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # delete all alerts for user in Alerts table
            query = '''
                UPDATE Alerts 
                SET isDeleted = 1 
                WHERE userId = ?
                '''
            self.cursor.execute(query, (userId,))
            
            if self.cursor.rowcount > 0:
                self.connection.commit()
                resultDict['message'] = 'All alerts deleted successfully.'
                resultDict['state'] = True
            else:
                resultDict['message'] = 'No alerts were found to delete.'

        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error deleting alerts: {e}.'
            resultDict['error'] = True
        finally:
            # emit delete alerts signal to main thread
            self.deleteAlertsResultSignal.emit(resultDict)
    

    # method for getting all blacklisted mac addresses for given user
    @Slot(int)
    def GetBlacklistMacs(self, userId):
        query = '''
            SELECT macAddress 
            FROM Blacklist 
            WHERE userId = ?
            '''
        self.cursor.execute(query, (userId,))
        blacklistMacsResult = self.cursor.fetchall()
        blacklistMacs = [] #represents our blacklist of mac addresses

        # check if we received blacklist mac addresses from query
        if blacklistMacsResult:
            # create list of blacklist mac addresses with given result
            blacklistMacs = [row[0] for row in blacklistMacsResult]

        # return blacklist macs for user
        return blacklistMacs
    

    # Method for adding a MAC address to the blacklist for a given user
    @Slot(int, str)
    def AddBlacklistMac(self, userId, macAddress):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # first, get the existing blacklist for the given user
            existingBlacklistMacs = self.GetBlacklistMacs(userId)
            
            # check if the MAC address already exists in the blacklist
            if macAddress in existingBlacklistMacs:
                resultDict['message'] = 'MAC address is already blacklisted for this user.'
            else:
                query = '''
                    INSERT INTO Blacklist (userId, macAddress) 
                    VALUES (?, ?)
                    '''
                self.cursor.execute(query, (userId, macAddress))

                if self.cursor.rowcount > 0:
                    self.connection.commit()
                    resultDict['message'] = 'Blacklist MAC added successfully.'
                    resultDict['state'] = True
                else:
                    resultDict['message'] = 'Error adding blacklist MAC.'
        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error adding blacklist MAC: {e}.'
            resultDict['error'] = True
        finally:
            # emit add blacklist mac address signal to main thread
            self.addBlacklistMacResultSignal.emit(resultDict)
        

    # method for deleting specific mac address for user in Blacklist table
    @Slot(int, str)
    def DeleteBlacklistMac(self, userId, macAddress):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # method for deleting blacklisted mac address for user from Blacklist table
            query = '''
                DELETE FROM Blacklist 
                WHERE userId = ? AND macAddress = ?
                '''
            self.cursor.execute(query, (userId, macAddress))
            
            if self.cursor.rowcount > 0:
                self.connection.commit()
                resultDict['message'] = 'Blacklist MAC deleted successfully.'
                resultDict['state'] = True
            else:
                resultDict['message'] = 'No matching MAC address found.'
        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error deleting blacklist MAC: {e}.'
            resultDict['error'] = True
        finally:
            # emit delete blacklist mac address signal to main thread
            self.deleteBlacklistMacResultSignal.emit(resultDict)
    

    # method for updating value of light mode for given user in Users table
    @Slot(int, int)
    def UpdateLightMode(self, userId, lightMode=0):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # update lightMode for user in Users table
            query = '''
                UPDATE Users 
                SET lightMode = ? 
                WHERE userId = ?
                '''
            self.cursor.execute(query, (lightMode, userId))
            
            if self.cursor.rowcount > 0:
                self.connection.commit()
                resultDict['message'] = 'Updated light mode status.'
                resultDict['state'] = True
            else:
                resultDict['message'] = 'Failed updating light mode status.'

        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error updating light mode: {e}.'
            resultDict['error'] = True
        finally:
            # emit update light mode signal to main thread
            self.updateLightModeResultSignal.emit(resultDict)

    
    # method for updating value of operation mode for given user in Users table
    @Slot(int, int)
    def UpdateOperationMode(self, userId, operationMode=0):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # update operationMode for user in Users table
            query = '''
                UPDATE Users 
                SET operationMode = ? 
                WHERE userId = ?
                '''
            self.cursor.execute(query, (operationMode, userId))
            
            if self.cursor.rowcount > 0:
                self.connection.commit()
                resultDict['message'] = 'Updated operation mode status.'
                resultDict['state'] = True
            else:
                resultDict['message'] = 'Failed updating operation mode status.'

        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error updating operation mode: {e}.'
            resultDict['error'] = True
        finally:
            # emit update operation mode signal to main thread
            self.updateOperationtModeResultSignal.emit(resultDict)


    # method for sending reset password code for a user in Users table
    @Slot(str, str)
    def SendResetPasswordCode(self, userEmail, resetCode):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # check if email exists in database and not associated to deleted user
            if not self.CheckEmail(userEmail, isDeleted=0):
                resultDict['message'] = 'Email is not associated with any account, please try another one.'
            else:
                # check that both email and app password are set before trying to send email
                if self.appEmail and self.appPassword and self.appEmailHost:
                    # try to send reset code to user'e email with app email credentials
                    if self.SendEmail(userEmail, resetCode, self.appEmail, self.appPassword, self.appEmailHost):
                        resultDict['message'] = 'Sent reset password email to user.'
                        resultDict['state'] = True
                    else:
                        resultDict['message'] = 'Failed Sending reset password email to user.'
                else:
                     resultDict['message'] = 'App email credentials are missing from .env file. Please ensure the file contains valid app email credentials.'
                     resultDict['error'] = True

        except Exception as e:
            resultDict['message'] = f'Error sending reset password email: {e}.'
            resultDict['error'] = True
        finally:
            # emit send code result signal to main thread
            self.sendCodeResultSignal.emit(resultDict)


    # method for sending email with reset code to user's registered email
    @Slot(str, str, str, str, str)
    def SendEmail(self, userEmail, resetCode, appEmail, appPassword, appEmailHost):
        try:
            # create email message with our desired format with password reset code
            message = EmailMessage()
            message.set_content(f'''
                <html>
                    <body>
                        <p>Hello,</p>
                        <p>You requested a password reset for your NetSpect account.</p>
                        <p>Your reset code is: <strong>{resetCode}</strong></p>
                        <p>This code is valid for 5 minutes.</p>
                        <p>If you did not request this reset, please ignore this email.</p>
                        <p>Best Regards,<br>NetSpect Team</p>
                    </body>
                </html>
                ''', subtype='html')
            message['Subject'] = 'NetSpect Password Reset Request'
            message['From'] = appEmail
            message['To'] = userEmail

            # sending reset password email with host smtp server with TLS
            with SMTP(appEmailHost, 587) as server:
                server.ehlo()
                server.starttls()
                server.login(appEmail, appPassword)
                server.send_message(message)
            return True
        except Exception as e:
            return False

    #---------------------------------------------SQL-FUNCTIONS-END----------------------------------------------#

#--------------------------------------------------------SQL-THREAD-END---------------------------------------------------------#