import sys, os, json
from PySide6.QtCore import Signal, Slot, QTimer, QObject, QByteArray, QUrl
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
from dotenv import load_dotenv
from pathlib import Path
from utility.serverEnums import HttpMethods, Endpoints

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located

#---------------------------------------------------------SQL-MANAGER-----------------------------------------------------------#
# class for managing restful api server requests for receiving or updating data in database
class SQL_Manager(QObject):
     # define signals for interacting with main gui thread
    loginResultSignal: Signal = Signal(dict)
    registrationResultSignal: Signal = Signal(dict)
    checkSessionResultSignal: Signal = Signal(dict)
    deleteSessionResultSignal: Signal = Signal(dict)
    sendResetCodeResultSignal: Signal = Signal(dict)
    verifyResetCodeResultSignal: Signal = Signal(dict)
    changeEmailResultSignal: Signal = Signal(dict)
    changeUsernameResultSignal: Signal = Signal(dict)
    changePasswordResultSignal: Signal = Signal(dict)
    deleteAccountResultSignal: Signal = Signal(dict)
    updateLightModeResultSignal: Signal = Signal(dict)
    updateOperationtModeResultSignal: Signal = Signal(dict)
    addBlacklistMacResultSignal: Signal = Signal(dict)
    deleteBlacklistMacResultSignal: Signal = Signal(dict)
    addAlertResultSignal: Signal = Signal(dict)
    deleteAlertsResultSignal: Signal = Signal(dict)
    finishSignal: Signal = Signal(dict)


    # constructor of sql manager class
    def __init__(self, parent: QObject=None) -> None:
        super().__init__(parent)
        self.envFilePath = currentDir.parent / 'config' / '.env' #represents env file path
        self.manager = QNetworkAccessManager(self) #represents access manager for sending HTTP requests to server
        self.manager.finished.connect(self.HandleReply) #connect request finish signal to its method
        self.serverUrl = '' #represents server url for performing database operations
        self.sessionId = '' #represents session id for logged in users, used for authentication with server


    # method for setting sesionId in sql manager class
    def SetSessionId(self, sessionId: str) -> None:
        self.sessionId = sessionId #set given sessionId in our class


    # method for getting sessionId from sql manager class
    def GetSessionId(self) -> str:
        return self.sessionId #return sessionId


    # method for initializing server url for connecting to Express server for database operations
    def InitServerUrl(self) -> None:
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        try:
            # check if env file exists, if so load server url from env file
            if self.envFilePath.exists():
                # load environment variables from env file
                load_dotenv(dotenv_path=self.envFilePath)

                # receive server url from env file for server connection
                self.serverUrl = os.getenv('SERVER_URL', '').strip()

                # check if env file has server url, if so we check if url is valid
                if self.serverUrl:
                    # create QUrl object for validating server url
                    serverUrlObj = QUrl(self.serverUrl)

                    # check if given server url is valid and has scheme and host
                    if serverUrlObj.isValid() and serverUrlObj.scheme() and serverUrlObj.host():
                        resultDict.update({'message': 'Initialized server URL from .env file successfully.', 'state': True}) #update resultDict with success message
                    else:
                         resultDict.update({'message': 'Invalid server URL format in .env file. Please ensure it includes a valid scheme.', 'error': True}) #update resultDict
                else:
                    resultDict.update({'message': 'Server URL is missing from .env file. Please ensure it contains a valid server URL.', 'error': True}) #update resultDict
            else:
                resultDict.update({'message': 'Server .env file was not found. Please ensure it exists in config folder.', 'error': True}) #update resultDict

        # if exception occured we return error message
        except Exception as e:
                resultDict.update({'message': f'Error initiazling server URL from .env file: {e}.', 'error': True}) #update resultDict
        finally:
            # we check if error occured, if so emit finish signal with error
            if resultDict.get('error'):
                self.finishSignal.emit(resultDict)


    # method for sending HTTP request to desired server endpoint
    def SendRequest(self, method: HttpMethods, endpoint: Endpoints, data: dict=None, callback=None, isSession: bool=True, timeout: int=30000) -> None:
        try:
            # check if serverUrl is initialized before attempting to send request to server
            if self.serverUrl:
                requestUrl = QUrl(f'{self.serverUrl}{endpoint}') #represents our request url with server url and endpoint
                request = QNetworkRequest(requestUrl) #represents our request object
                request.setHeader(QNetworkRequest.ContentTypeHeader, 'application/json') #set headers for request
                reply = None #represents our replay object received from request

                # check if sessionId is initialized and isSession flag given, if so add sessionId in authorization header
                if isSession and self.sessionId:
                    request.setRawHeader(b'Authorization', f'Session {self.sessionId}'.encode('utf-8')) #add sessionId in authorization header

                # encode given data into a byte array for request
                dataBytes = QByteArray(json.dumps(data).encode('utf-8')) if data else QByteArray()

                # send reply based on given method type
                match method:
                    case HttpMethods.GET:
                        reply = self.manager.get(request) #send get request
                    case HttpMethods.POST:
                        reply = self.manager.post(request, dataBytes) #send post request with data
                    case HttpMethods.PUT:
                        reply = self.manager.put(request, dataBytes) #send put request with data
                    case HttpMethods.DELETE:
                        reply = self.manager.deleteResource(request) #send delete request
                    case HttpMethods.PATCH:
                        reply = self.manager.sendCustomRequest(request, b'PATCH', dataBytes) #send patch request with data
                    case HttpMethods.HEAD:
                        reply = self.manager.sendCustomRequest(request, b'HEAD') #send head request
                    case HttpMethods.OPTIONS:
                        reply = self.manager.sendCustomRequest(request, b'OPTIONS') #send options request
                    case _:
                        reply = None #if invalid method given we set reply to none

                # check if reply is initialized, if so set callback slot and start request timeout
                if reply:
                    reply.setProperty('callback', callback) #set request callback slot
                    reply.setProperty('handled', False) #set handled flag for request
                    self.StartRequestTimer(reply, timeout) #start request timeout

        # if exception occured we return error message
        except Exception as e:
            resultDict = {'state': False, 'message': f'Error sending request: {e}.', 'error': True} #create error result dict
            # call callback and emit signal back to main thread
            if callable(callback):
                callback(resultDict) #call callback slot


    # method for handling reply from server and calling callback slot in main thread
    @Slot(QNetworkReply)
    def HandleReply(self, reply: QNetworkReply) -> None:
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        callback = reply.property('callback') #get callback slot from reply object
        try:
            # check if handled flag is false, if so handle reply
            if not reply.property('handled'):
                reply.setProperty('handled', True) #set flag to mark request as handled
                statusCode = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute) #get reply status code

                # check if reply is open and has valid status code, if so read the reply data
                if reply.isOpen() and statusCode != None and statusCode > 0:
                    data = reply.readAll().data().decode('utf-8') #read given reply data and decode it
                    # check if we can parse server reply data as json, if so assign it to result dict
                    try:
                        resultDict = json.loads(data) #update resultDict with decoded reply data as json

                    # if exception occured we failed receving reply data, we update result dict with error message
                    except json.JSONDecodeError:
                        resultDict.update({'message': 'Failed receving reply data from server.', 'error': True}) #update resultDict

                # else we failed receving reply, we update result dict with error message
                else:
                    resultDict.update({'message': 'Failed receving reply from server.', 'error': True}) #update resultDict

                # call callback and emit signal back to main thread and delete reply object
                if callable(callback):
                    callback(resultDict) #call callback slot
                reply.deleteLater() #delete reply object

        # if exception occured we return error message
        except Exception as e:
            resultDict.update({'message': f'Error receving reply: {e}.', 'error': True}) #update resultDict
            # call callback and emit signal back to main thread and delete reply object
            if callable(callback):
                callback(resultDict) #call callback slot
            reply.deleteLater() #delete reply object


    # method for starting request timer for closing request if timeout reached
    def StartRequestTimer(self, reply: QNetworkReply, timeout: int=30000) -> None:
        requestTimer = QTimer(reply) #create timer for request
        requestTimer.setSingleShot(True) #set singleshot
        requestTimer.timeout.connect(lambda: self.HandleRequestTimeout(reply)) #connect request timeout signal to its method
        requestTimer.start(timeout) #start request timer
        reply.finished.connect(requestTimer.stop) #stop requestTimer if reply finishes before timeout


    # method for handling request timeout and calling callback slot in main thread
    @Slot()
    def HandleRequestTimeout(self, reply: QNetworkReply) -> None:
        resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
        callback = reply.property('callback') #get callback slot from reply object
        try:
            # check if handled flag is false and request still running
            if not reply.property('handled') and reply.isRunning():
                reply.setProperty('handled', True) #set flag to mark request as handled
                reply.abort() #stop the request and call abort on reply object
                resultDict.update({'message': 'Failed receiving reply from server within timeout.', 'error': True}) #update resultDict

                # call callback and emit signal back to main thread and delete reply object
                if callable(callback):
                    callback(resultDict) #call callback slot
                reply.deleteLater() #delete reply object

        # if exception occured we return error message
        except Exception as e:
            resultDict.update({'message': f'Error receving reply: {e}.', 'error': True}) #update resultDict
            # call callback and emit signal back to main thread and delete reply object
            if callable(callback):
                callback(resultDict) #call callback slot
            reply.deleteLater() #delete reply object

    #------------------------------------------SERVER-REQUEST-FUNCTIONS------------------------------------------#
    # method for logging into account in main app
    @Slot(str, str)
    def Login(self, username: str, password: str) -> None:
        data = {'username': username, 'password': password}
        self.SendRequest(method=HttpMethods.POST, endpoint=Endpoints.API.Auth.Login, data=data, callback=self.loginResultSignal.emit, isSession=False, timeout=5000)


    # method for adding a new user in database
    @Slot(str, str, str)
    def Register(self, email: str, username: str, password: str) -> None:
        data = {'email': email, 'username': username, 'password': password}
        self.SendRequest(method=HttpMethods.POST, endpoint=Endpoints.API.Auth.Register, data=data, callback=self.registrationResultSignal.emit, isSession=False, timeout=5000)


    # method to check if given session is active for user in database
    @Slot()
    def CheckSession(self) -> None:
        self.SendRequest(method=HttpMethods.GET, endpoint=Endpoints.API.Sessions.CheckSession, callback=self.checkSessionResultSignal.emit, timeout=30000)


    # method for deleting session for user in database
    @Slot()
    def DeleteSession(self) -> None:
        self.SendRequest(method=HttpMethods.DELETE, endpoint=Endpoints.API.Sessions.DeleteSession, callback=self.deleteSessionResultSignal.emit, timeout=30000)
    

    # method for sending reset email for user in database
    @Slot(str)
    def SendResetCode(self, email: str) -> None:
        data = {'email': email}
        self.SendRequest(method=HttpMethods.POST, endpoint=Endpoints.API.ResetPassword.SendResetCode, data=data, callback=self.sendResetCodeResultSignal.emit, isSession=False, timeout=5000)


    # method for verifing reset code for user in database
    @Slot(str, str)
    def VerifyResetCode(self, email: str, resetCode: str) -> None:
        data = {'email': email, 'resetCode': resetCode}
        self.SendRequest(method=HttpMethods.POST, endpoint=Endpoints.API.ResetPassword.VerifyResetCode, data=data, callback=self.verifyResetCodeResultSignal.emit, isSession=False, timeout=5000)


    # method for changing user's email in database
    @Slot(str)
    def ChangeEmail(self, newEmail: str) -> None:
        data = {'newEmail': newEmail}
        self.SendRequest(method=HttpMethods.PUT, endpoint=Endpoints.API.Users.ChangeEmail, data=data, callback=self.changeEmailResultSignal.emit, timeout=30000)


    # method for changing user's username in database
    @Slot(str)
    def ChangeUsername(self, newUsername: str) -> None:
        data = {'newUsername': newUsername}
        self.SendRequest(method=HttpMethods.PUT, endpoint=Endpoints.API.Users.ChangeUsername, data=data, callback=self.changeUsernameResultSignal.emit, timeout=30000)


    # method for updating passowrd of user in database
    @Slot(str, str)
    def ChangePassword(self, newPassword: str, oldPassword: str) -> None:
        data = {'newPassword': newPassword, 'oldPassword': oldPassword}
        self.SendRequest(method=HttpMethods.PUT, endpoint=Endpoints.API.Users.ChangePassword, data=data, callback=self.changePasswordResultSignal.emit, timeout=30000)


    # method for deleting user account from database
    @Slot()
    def DeleteAccount(self) -> None:
        self.SendRequest(method=HttpMethods.DELETE, endpoint=Endpoints.API.Users.DeleteAccount, callback=self.deleteAccountResultSignal.emit, timeout=30000)


    # method for permanently deleting user account from database
    @Slot()
    def HardDeleteAccount(self) -> None:
        self.SendRequest(method=HttpMethods.DELETE, endpoint=Endpoints.API.Users.HardDeleteAccount, callback=self.deleteAccountResultSignal.emit, timeout=30000)
    

    # method for updating light mode for given user in database
    @Slot(int)
    def UpdateLightMode(self, lightMode: int=0) -> None:
        data = {'lightMode': lightMode}
        self.SendRequest(method=HttpMethods.PUT, endpoint=Endpoints.API.Users.UpdateLightMode, data=data, callback=self.updateLightModeResultSignal.emit, timeout=30000)


    # method for updating operation mode for given user in database
    @Slot(int)
    def UpdateOperationMode(self, operationMode: int=0) -> None:
        data = {'operationMode': operationMode}
        self.SendRequest(method=HttpMethods.PUT, endpoint=Endpoints.API.Users.UpdateOperationMode, data=data, callback=self.updateOperationtModeResultSignal.emit, timeout=30000)


    # method for adding a mac address to the blacklist for user in database
    @Slot(str)
    def AddBlacklistMac(self, macAddress: str) -> None:
        data = {'macAddress': macAddress}
        self.SendRequest(method=HttpMethods.POST, endpoint=Endpoints.API.Blacklist.AddBlacklistMac, data=data, callback=self.addBlacklistMacResultSignal.emit, timeout=30000)


    # method for deleting specific mac address for user in database
    @Slot(str)
    def DeleteBlacklistMac(self, macAddress: str) -> None:
        data = {'macAddress': macAddress}
        self.SendRequest(method=HttpMethods.POST, endpoint=Endpoints.API.Blacklist.DeleteBlacklistMac, data=data, callback=self.deleteBlacklistMacResultSignal.emit, timeout=30000)


    # method for adding alert for user in database
    @Slot(str, str, str, str, str, str, str, str)
    def AddAlert(self, interface: str, attackType: str, sourceIp: str, sourceMac: str, destinationIp: str, destinationMac: str, protocol: str, osType: str, timestamp: str) -> None:
        data = {'interface': interface, 'attackType': attackType, 'sourceIp': sourceIp, 'sourceMac': sourceMac, 'destinationIp': destinationIp,
                    'destinationMac': destinationMac, 'protocol': protocol, 'osType': osType, 'timestamp': timestamp}
        self.SendRequest(method=HttpMethods.POST, endpoint=Endpoints.API.Alerts.AddAlert, data=data, callback=self.addAlertResultSignal.emit, timeout=30000)


    # method for deleting all alerts for user in database
    @Slot()
    def DeleteAlerts(self) -> None:
        self.SendRequest(method=HttpMethods.DELETE, endpoint=Endpoints.API.Alerts.DeleteAlerts, callback=self.deleteAlertsResultSignal.emit, timeout=30000)

    #----------------------------------------SERVER-REQUEST-FUNCTIONS-END----------------------------------------#

#--------------------------------------------------------SQL-MANAGER-END--------------------------------------------------------#