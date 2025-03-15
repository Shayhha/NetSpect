import sys, os, pyodbc
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot
from dotenv import load_dotenv
from pathlib import Path

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located

#---------------------------------------------------------SQL-THREAD------------------------------------------------------------#
# thread for performing various SQL queries and receiving or updating data in database
class SQL_Thread(QThread):
    # define signals for interacting with main gui thread
    loginResultSignal = pyqtSignal(dict)
    registrationResultSignal = pyqtSignal(dict)
    changeEmailResultSignal = pyqtSignal(dict)
    changeUsernameResultSignal = pyqtSignal(dict)
    changePasswordResultSignal = pyqtSignal(dict)
    deleteUserResultSignal = pyqtSignal(dict)
    addAlertResultSignal = pyqtSignal(dict)
    deleteAlertsResultSignal = pyqtSignal(dict)
    addBlacklistMacResultSignal = pyqtSignal(dict)
    deleteBlacklistMacResultSignal = pyqtSignal(dict)
    finishSignal = pyqtSignal(dict)

    # constructor of sql thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.connection = None # connection for SQL server database
        self.cursor = None # cursor for executig SQL commands


    # method for stopping sql thread
    @pyqtSlot()
    def StopThread(self):
        if self.isRunning():
            self.quit() #exit main loop and end task
            self.wait() #we wait to ensure thread cleanup


    # method for connecting to SQL server database
    def Connect(self):
        try:
            # load environment variables from env file
            load_dotenv(dotenv_path=currentDir.parent / 'database' / '.env' )
            # getting necessary database credentials from env file for database connection
            connectionString = os.getenv('DB_CONNECTION_STRING')
            self.connection = pyodbc.connect(connectionString)
            self.cursor = self.connection.cursor() #initialize cursor 
            print('SQL_Thread: Connected to database successfully.')
        except pyodbc.Error as e:
            raise Exception('Database connection failed. The application will function, but login will be unavailable')


    # method for closing database connection
    def Close(self):
        # close cursor and connection
        if self.cursor:
            self.cursor.close() #close cursor
        if self.connection: 
            self.connection.close() #close connection


    # run method for performing various database related commands
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            self.Connect() #connect to our SQL server database
            self.exec_() #execute sql thread process
        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
            print(f'SQL_Thread: {stateDict['message']}') #print error message in terminal
        finally:
            self.Close() #close database connection
            self.finishSignal.emit(stateDict) #send finish signal to main thread
            print('SQL_Thread: Finsihed database tasks.\n')


    #----------------------------------------------SQL-FUNCTIONS-------------------------------------------------#
    # method for logging into account in main app
    @pyqtSlot(str, str)
    def Login(self, username, password):
        resultDict = {'state': False, 'message': '', 'result': None, 'error': False} #represents result dict
        try:
            # query to fetch user details
            query = '''
                SELECT userId, email, userName, numberOfDetectedAttacks, lightMode 
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
                    'numberOfDetectedAttacks': result[3],
                    'lightMode': result[4]
                }
                
                # retrieve alert list and black list with helper functions
                userData['alertList'] = self.GetAlerts(userData['userId'])
                userData['blackList'] = self.GetBlacklistMacs(userData['userId'])

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
    @pyqtSlot(str, str, str)
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
    @pyqtSlot(int, str)
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
    @pyqtSlot(str)
    def CheckEmail(self, email):
        # check if username is present in Users table
        query = '''
            SELECT COUNT(*) 
            FROM Users 
            WHERE email = ?
        '''
        self.cursor.execute(query, (email,))
        result = self.cursor.fetchone()
        return result[0] > 0 if result else True

    
    # method for changing user's username in Users table
    @pyqtSlot(int, str)
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
    @pyqtSlot(str)
    def CheckUserName(self, username):
        # check if username is present in Users table
        query = '''
            SELECT COUNT(*) 
            FROM Users 
            WHERE userName = ?
        '''
        self.cursor.execute(query, (username,))
        result = self.cursor.fetchone()
        return result[0] > 0 if result else True


    # method for updating passowrd of user in Users table
    @pyqtSlot(int, str, str)
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


    # method for checking if the provided password is correct for given user
    @pyqtSlot(int, str)
    def CheckPassword(self, userId, password):
        # check if password matches user's password in Users table
        query = '''
            SELECT COUNT(*) 
            FROM Users 
            WHERE userId = ? AND password = ?
        '''
        self.cursor.execute(query, (userId, password))
        result = self.cursor.fetchone()
        return result[0] > 0 if result else False
    

    # method for deleting a user from Users table
    @pyqtSlot(int)
    def ChangePassword(self, userId):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # delete given user from Users table by userId
            query = '''
                UPDATE Users SET 
                isDeleted = 1 
                WHERE userId = ?
            '''
            self.cursor.execute(query, (userId))
            
            if self.cursor.rowcount > 0:
                self.connection.commit() #commit the transaction for the update
                resultDict['message'] = 'User deleted successfully.'
                resultDict['state'] = True
            else:
                resultDict['message'] = 'Failed deleting user.'

        except Exception as e:
            self.connection.rollback() #rollback on error
            resultDict['message'] = f'Error deleting user: {e}.'
            resultDict['error'] = True
        finally:
            # emit delete user signal to main thread
            self.deleteUserResultSignal.emit(resultDict)


    # method for getting all alerts that registered for given user in decreasing order
    @pyqtSlot(int)
    def GetAlerts(self, userId):
        query = '''
            SELECT interface, attackType, sourceIp, sourceMac, 
                destinationIp, destinationMac, protocol, osType, timestamp
            FROM Alerts
            WHERE userId = ? AND isDeleted = 0
            ORDER BY CONVERT(datetime, SUBSTRING(timestamp, 10, 9) + ' ' + SUBSTRING(timestamp, 1, 8), 3) DESC
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
                    'sourceIp': row[2],
                    'sourceMac': row[3],
                    'destinationIp': row[4],
                    'destinationMac': row[5],
                    'protocol': row[6],
                    'osType': row[7],
                    'timestamp': row[8]
                }
                alertsList.append(alert)

        # return list of alerts for user
        return alertsList


    # method for adding alert for user in Alerts table
    @pyqtSlot(int, str, str, str, str, str, str, str, str)
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
    @pyqtSlot(int)
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
    @pyqtSlot(int)
    def GetBlacklistMacs(self, userId):
        query = '''
            SELECT macAddress 
            FROM Blacklist 
            WHERE userId = ?
        '''
        self.cursor.execute(query, (userId,))
        blacklistResults = self.cursor.fetchall()

        # convert fetched tuples into a list of mac addresses
        blacklist = [row[0] for row in blacklistResults]

        # return blacklist macs for user
        return blacklist
    

    # Method for adding a MAC address to the blacklist for a given user
    @pyqtSlot(int, str)
    def AddBlacklistMac(self, userId, macAddress):
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # first, get the existing blacklist for the given user
            existingBlacklist = self.GetBlacklistMacs(userId)
            
            # check if the MAC address already exists in the blacklist
            if macAddress in existingBlacklist:
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
    @pyqtSlot(int, str)
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


    #---------------------------------------------SQL-FUNCTIONS-END----------------------------------------------#

#--------------------------------------------------------SQL-THREAD-END---------------------------------------------------------#