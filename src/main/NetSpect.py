import UserInterfaceFunctions
from MainFunctions import *
from SQLHelper import *
from interface.ui_NetSpect import Ui_NetSpect
from PySide6.QtCore import Qt, Signal, Slot, QTimer, QRegularExpression, QThread, QMutex, QMutexLocker, QWaitCondition
from PySide6.QtGui import QGuiApplication, QValidator, QRegularExpressionValidator
from PySide6.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QFileDialog
from hashlib import sha256
from secrets import choice, token_hex
from string import digits, ascii_letters, ascii_uppercase

#--------------------------------------------------------NetSpect-CLASS---------------------------------------------------------#
# class that represents main app of NetSpect
class NetSpect(QMainWindow):
    ui = None #represents main ui object of GUI with all our objects
    userData = {'userId': None, 'email': None, 'userName': None, 'lightMode': 0, 'operationMode': 0, 'numberOfDetections': 0, 'alertList': [], 'pieChartData': {}, 'analyticsChartData': {}, 'blackList': []} #represents user data in interface
    isDetection = False #represents flag for indicating if detection is active
    resetPasswordValidator = {'resetCode': None, 'timestamp': None, 'newPassword': None} #represents reset password validator dictionary
    emailValidator, usernameValidator, passwordValidator, finalPasswordValidator, macValidator = None, None, None, None, None #represents the validators that hold regexes for various input fields in the program
    totalTimer, arpTimer, portScanDosTimer, dnsTimer = None, None, None, None #represents timer for each thread for evaluating when to send data
    totalTimeout, arpTimeout, portScanDosTimout, dnsTimout = 1000, 40000, 40000, 40000 #represents timeout for each timer
    arpThreshold, portScanDosThreshold, dnsThreshold = 20, 10000, 350 #represents thresholds for each thread
    repeatedAttackTimeout = 2 #represents timeout for repeated attacks, we alert again for attacks from same source after few minutes
    timeElapsed = timedelta() #initialize a timedelta object to track elapsed time
    arpList = [] #represents list of packets related to arp spoofing
    portScanDosDict = {} #represents dict of {(flow tuple) - [packet list]} related to port scanning and dos
    dnsDict = {} #represents dict of {(flow tuple) - [packet list]} related to dns tunneling
    arpCounter, tcpUdpCounter, dnsCounter = 0, 0, 0 #represents counters for our packet data structures for arp, portDos and dns
    sqlThread, reportThread, loggerThread, dataCollectorThread = None, None, None, None #represents our worker threads for sql queires, report creation and data collection for training models
    snifferThread, arpThread, portScanDosThread, dnsThread = None, None, None, None #represents our worker threads for sniffing and detecting network cyber attacks
    arpMutex, portScanDosMutex, dnsMutex = QMutex(), QMutex(), QMutex() #represents mutex objects for thread safe operations on our dictionaries
    arpAttackDict, portScanDosAttackDict, dnsAttackDict = {'ipToMac': {}, 'macToIp': {}}, {}, {} #represents attack dictionaries for each attack we previously detected

    # constructor of main gui application
    def __init__(self):
        super(NetSpect, self).__init__()
        self.ui = Ui_NetSpect() #set mainwindow ui object
        self.ui.setupUi(self) #load the ui file of NetSpect
        self.initUI() #call init method
        
    
    # method to initialize GUI methods and events
    def initUI(self):
        # connect timers for detection
        self.totalTimer, self.arpTimer, self.portScanDosTimer, self.dnsTimer = QTimer(self), QTimer(self), QTimer(self), QTimer(self) #initailize our timers
        self.totalTimer.timeout.connect(self.UpdateRunningTimeCounterLabel) #connect timeout event for total timer
        self.arpTimer.timeout.connect(self.SendArpList) #connect timeout event for arp timer
        self.portScanDosTimer.timeout.connect(self.SendPortScanDosDict) #connect timeout event for portScanDos timer
        self.dnsTimer.timeout.connect(self.SendDnsDict) #connect timeout event for dns timer

        # connect interface buttons to their methods
        self.ui.startStopPushButton.clicked.connect(self.StartStopButtonClicked)
        self.ui.loginPushButton.clicked.connect(self.LoginButtonClicked)
        self.ui.registerPushButton.clicked.connect(self.RegisterButtonClicked)
        self.ui.sendCodePushButton.clicked.connect(self.SendCodeButtonClicked)
        self.ui.verifyCodePushButton.clicked.connect(self.VerifyCodeButtonClicked)
        self.ui.deleteAccoutPushButton.clicked.connect(self.DeleteAccoutButtonClicked)
        self.ui.clearHistoryPushButton.clicked.connect(self.DeleteAlertsButtonClicked)
        self.ui.addMacAddressPushButton.clicked.connect(self.AddMacAddressButtonClicked)
        self.ui.emailPushButton.clicked.connect(self.SaveEmailButtonClicked)
        self.ui.usernamePushButton.clicked.connect(self.SaveUsernameButtonClicked)
        self.ui.passwordPushButton.clicked.connect(self.SavePasswordButtonClicked)
        self.ui.downloadReportPushButton.clicked.connect(self.DownloadReportButtonClicked)
        self.ui.cancelReportPushButton.clicked.connect(self.CancelReportButtonClicked)

        # connect interface labels to their methods
        self.ui.accountIcon.mousePressEvent = lambda event: UserInterfaceFunctions.AccountIconClicked(self)
        self.ui.moveToRegisterLabel.mousePressEvent = lambda event: UserInterfaceFunctions.SwitchBetweenLoginAndRegister(self)
        self.ui.moveToLoginLabel.mousePressEvent = lambda event: UserInterfaceFunctions.SwitchBetweenLoginAndRegister(self, False)
        self.ui.moveToForgotPasswordLabel.mousePressEvent = lambda event: UserInterfaceFunctions.SwitchBetweenLoginAndForgotPassword(self, True)
        self.ui.cancelResetPasswordProcessLabel.mousePressEvent = lambda event: UserInterfaceFunctions.SwitchBetweenLoginAndForgotPassword(self, False)
        self.ui.menuIcon.mousePressEvent = lambda event: UserInterfaceFunctions.OpenSideFrame(self)
        self.ui.closeMenuIcon.mousePressEvent = lambda event: UserInterfaceFunctions.CloseSideFrame(self)
        self.ui.homePageIconHorizontalFrame.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 0) #switch to Home Page
        self.ui.analyticsIconHorizontalFrame.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 1) #switch to Analytics Page
        self.ui.reportIconHorizontalFrame.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 2) #switch to Report Page
        self.ui.infoIconHorizontalFrame.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 3) #switch to Information Page
        self.ui.settingsIcon.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 4) #switch to Settings Page
        self.ui.logoutIcon.mousePressEvent = lambda event: self.LogoutButtonClicked() #log out of user's account and clear interface

        # connect comboboxes and checkboxes to their methods
        self.ui.arpSpoofingCheckBox.stateChanged.connect(lambda: UserInterfaceFunctions.ReportCheckboxToggled(self))
        self.ui.portScanningCheckBox.stateChanged.connect(lambda: UserInterfaceFunctions.ReportCheckboxToggled(self))
        self.ui.denialOfServiceCheckBox.stateChanged.connect(lambda: UserInterfaceFunctions.ReportCheckboxToggled(self))
        self.ui.dnsTunnelingCheckBox.stateChanged.connect(lambda: UserInterfaceFunctions.ReportCheckboxToggled(self))
        self.ui.reportDurationComboBox.currentIndexChanged.connect(lambda: UserInterfaceFunctions.ReportDurationComboboxChanged(self))
        self.ui.networkInterfaceComboBox.clear() #clear interfaces combobox
        self.ui.networkInterfaceComboBox.addItems(NetworkInformation.InitNetworkInfo()) #intialize our interfaces combobox with host network info
        self.ui.networkInterfaceComboBox.currentIndexChanged.connect(self.ChangeNetworkInterface) #connect interfaces combobox to its method
        self.ui.colorModeComboBox.currentIndexChanged.connect(self.ChangeColorMode) #connecct color mode combobox to its method
        self.ui.operationModeComboBox.currentIndexChanged.connect(self.ChangeOperationMode) #connect operation mode combobox to its method
        self.ui.analyticsYearComboBox.currentIndexChanged.connect(self.ChangeAnalyticsYear) #connect analytics year combobox to its method
        self.ChangeNetworkInterface() #set default network interface from combobox

        # initialize other interface components and show interface
        self.InitUserData() #initialize user data dictionary to default
        UserInterfaceFunctions.InitUserInterface(self) # setup left sidebar and various elements in gui
        self.InitSystemInfo(NetworkInformation.GetSystemInformation()) #initialize the system information in the info page (machine name, version, etc.)
        self.InitValidators() #initialize the network information in the info page (interface name, mac address, ips, etc.)
        self.UpdateNumberOfDetectionsCounterLabel(0) #reset number of detections counter label
        self.InitLoggerThread() #call init method for logger thread
        self.InitSQLThread() #call init method for sql thread
        self.InitModels() #call init method for initializing models and scalers
        self.center() #make the app open in center of screen
        self.show() #show the application


    # method for making the app open in the center of screen
    def center(self):
        qr = self.frameGeometry()
        cp = QGuiApplication.primaryScreen().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


    # method for closing the program and managing threads
    def closeEvent(self, event):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes

        # we check if detection is active, if so we close threads
        if self.isDetection:
            self.StopDetection() #stop detection and stop running threads

        # we check if sniffer thread is active, if so we close it
        if self.snifferThread:
            self.snifferThread.StopThread() #stop sniffer thread
            self.snifferThread.wait() #wait until the thread finishes execution
            self.CloseSnifferThread(stateDict) #call close method
        
        # we check if arp thread is active, if so we close it
        if self.arpThread:
            self.arpThread.StopThread() #stop arp thread
            self.arpThread.wait() #wait until the thread finishes execution
            self.CloseArpThread(stateDict) #call close method
        
        # we check if portScanDos thread is active, if so we close it
        if self.portScanDosThread:
            self.portScanDosThread.StopThread() #stop portScanDos thread
            self.portScanDosThread.wait() #wait until the thread finishes execution
            self.ClosePortScanDosThread(stateDict) #call close method
        
        # we check if dns thread is active, if so we close it
        if self.dnsThread:
            self.dnsThread.StopThread() #stop dns thread
            self.dnsThread.wait() #wait until the thread finishes execution
            self.CloseDnsThread(stateDict) #call close method

        # we check if data collector thread is active, if so we close it
        if self.dataCollectorThread:
            self.dataCollectorThread.StopThread() #stop data collector thread
            self.dataCollectorThread.wait() #wait until the thread finishes execution
            self.CloseDataCollectorThread(stateDict) #call close method

        # we check if report thread is active, if so we close it
        if self.reportThread:
            self.reportThread.StopThread(True) #stop report thread
            self.reportThread.wait() #wait until the thread finishes execution
            self.CloseReportThread(stateDict) #call close method

        # we check if sql thread is active, if so we close it
        if self.sqlThread:
            self.sqlThread.StopThread() #stop sql thread and close connection
            self.sqlThread.wait() #wait until the thread finishes execution
            self.CloseSQLThread(stateDict) #call close method

        # we check if logger thread is active, if so we close it
        if self.loggerThread:
            self.loggerThread.StopThread() #stop logger thread
            self.loggerThread.wait() #wait until the thread finishes execution
            self.CloseLoggerThread(stateDict) #call close method
        
        event.accept() #accept the close event


    # function for hashing given password with sha-256, retuns hex representation
    @staticmethod
    def ToSHA256(message):
        sha256Obj = sha256() #create a sha-256 object
        sha256Obj.update(message.encode()) #update message with its sha-256 hash
        return sha256Obj.hexdigest() #return hash as hexadecimal
    

    # method for generating a password for user in specified length
    @staticmethod
    def GetPassword(length=8):
        # create a password in specified length with at least one uppercase and one digit
        password = [choice(ascii_letters + digits) for _ in range(length)]
        password[choice(range(length))] = choice(ascii_uppercase) #set uppercase letter in random position
        password[choice(range(length))] = choice(digits) #set digit in random position
        return ''.join(password)


    # method for generating a reset code in specified length with timestamp
    @staticmethod
    def GetResetCode(length=8):
        resetCode = token_hex(length // 2) #generate a reset code in specified length
        return resetCode


    # method for initializing logger thread for writing logs into log file
    def InitLoggerThread(self):
        # intialize logger thread for logging operations
        self.loggerThread = Logger_Thread(self)
        # connect relevant signals for logger thread
        self.loggerThread.finishSignal.connect(self.CloseLoggerThread)
        # start logger thread
        self.loggerThread.start()
        # log opening application and initializing logger thread
        self.SendLogDict('Main_Thread: Opened Application.', 'INFO')
        self.SendLogDict('Logger_Thread: Starting logger thread.', 'INFO')


    # method for initializing sql thread for database operations
    def InitSQLThread(self):
        # intialize sql thread for database operations
        self.sqlThread = SQL_Thread(self)
        # connect relevant signals for sql thread
        self.sqlThread.loginResultSignal.connect(self.LoginResult)
        self.sqlThread.registrationResultSignal.connect(self.RegisterResult)
        self.sqlThread.changeEmailResultSignal.connect(self.SaveEmailResult)
        self.sqlThread.changeUsernameResultSignal.connect(self.SaveUsernameResult)
        self.sqlThread.changePasswordResultSignal.connect(self.SavePasswordResult)
        self.sqlThread.resetPasswordResultSignal.connect(self.VerifyCodeResult)
        self.sqlThread.deleteAccountResultSignal.connect(self.DeleteAccountResult)
        self.sqlThread.addAlertResultSignal.connect(self.AddAlertResult)
        self.sqlThread.deleteAlertsResultSignal.connect(self.DeleteAlertsResult)
        self.sqlThread.addBlacklistMacResultSignal.connect(self.AddMacToBlackListResult)
        self.sqlThread.deleteBlacklistMacResultSignal.connect(self.DeleteMacFromBlackListResult)
        self.sqlThread.updateLightModeResultSignal.connect(self.UpdateColorModeResult)
        self.sqlThread.updateOperationtModeResultSignal.connect(self.UpdateOperationModeResult)
        self.sqlThread.sendCodeResultSignal.connect(self.SendCodeResult)
        self.sqlThread.connectionResultSignal.connect(self.ConnectionResult)
        self.sqlThread.initEmailCredentilsResultSignal.connect(self.InitEmailCredentilsResult)
        self.sqlThread.finishSignal.connect(self.CloseSQLThread)
        # start sql thread
        self.sqlThread.start()
        # log initializing sql thread
        self.SendLogDict('SQL_Thread: Starting SQL thread.', 'INFO')
    

    # method for initializing user data dictionary including pie chart, histogram chart and bar chart dictionaries
    def InitUserData(self, userData=None):
        # means we need to initialize userData dictionary with given data
        if userData:
            self.userData = userData

        # else means we need to reset userData dictionary to default state
        else:
            # initialize user data dictionary to default state
            self.userData = {'userId': None, 'email': None, 'userName': None, 'lightMode': 0, 'operationMode': 0, 
                                'numberOfDetections': 0, 'alertList': [], 'pieChartData': {}, 'analyticsChartData': {}, 'blackList': []}

        # initialize pie chart, histogram chart and bar chart dictionaries with default states if not initialized
        self.userData.setdefault('pieChartData', {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0})
        self.userData.setdefault('analyticsChartData', {}).setdefault('barChartData', {}).setdefault(str(datetime.now().year), {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0})
        self.userData.setdefault('analyticsChartData', {}).setdefault('histogramChartData', {}).setdefault(str(datetime.now().year), 
                                    {month: {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0} for month in range(1, 13)})


    # method for initializing SVM models ans scalers for portScanDos and dnsTunneling
    def InitModels(self):
        # call init methods and save result
        isPortScanDosModel, isDnsTunnelingModel = PortScanDoS.InitModel(), DNSTunneling.InitModel()

        # check if portScanDos and dnsTunneling model or scaler are not initialized 
        if not isPortScanDosModel and not isDnsTunnelingModel:
            self.SendLogDict('Main_Thread: Failed to initialize PortScanDoS and DNSTunneling models or scalers.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', 'PortScanDoS and DNSTunneling models or scalers files were not found. Please ensure they exist in the models folder.', 'Critical')

        # check if portScanDos model or scaler is not initialized
        elif not isPortScanDosModel:
            self.SendLogDict('Main_Thread: Failed to initialize PortScanDoS model or scaler.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', 'PortScanDoS model or scaler files were not found. Please ensure they exist in the models folder.', 'Critical')

        # check if dnsTunneling model or scaler is not initialized 
        elif not isDnsTunnelingModel:
            self.SendLogDict('Main_Thread: Failed to initialize DNSTunneling model or scaler.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', 'DNSTunneling model or scaler files were not found. Please ensure they exist in the models folder.', 'Critical')

        # else portScanDos and dnsTunneling model and scaler are initialzied
        else:
            self.SendLogDict('Main_Thread: Initialized PortScanDoS and DNSTunneling models and scalers successfully.', 'INFO') #log initialization event


    # method for setting input validators on line edits in gui
    def InitValidators(self):
        # create regex expressions and validators
        self.emailValidator = QRegularExpressionValidator(QRegularExpression('^(?:$|(?!.*\\.\\.)[A-Za-z\\d._%+-]+@(?:[A-Za-z\\d](?:[A-Za-z\\d-]{0,61}[A-Za-z\\d])?\\.)+[A-Za-z]{2,})$'))
        self.usernameValidator = QRegularExpressionValidator(QRegularExpression('^(?:$|[A-Za-z][A-Za-z\\d]{3,15})$'))
        self.passwordValidator = QRegularExpressionValidator(QRegularExpression('^(?:$|[A-Za-z\\d$&?@#|\\.\\^*()%!]{6,50})$'))
        self.finalPasswordValidator = QRegularExpressionValidator(QRegularExpression('^(?:$|(?=.*[A-Z])(?=.*\\d)[A-Za-z\\d$&?@#|\\.\\^*()%!]{6,50})$'))
        self.macValidator = QRegularExpressionValidator(QRegularExpression('^(?:$|(?:[\\da-fA-F]{2}:){5}[\\da-fA-F]{2})$'))

        # set validaotrs for email, username, password and mac line edits in the register popup and settings page
        self.ui.loginUsernameLineEdit.setValidator(self.usernameValidator)
        self.ui.loginPasswordLineEdit.setValidator(self.passwordValidator)
        self.ui.registerEmailLineEdit.setValidator(self.emailValidator)
        self.ui.registerUsernameLineEdit.setValidator(self.usernameValidator)
        self.ui.registerPasswordLineEdit.setValidator(self.passwordValidator)
        self.ui.registerConfirmPasswordLineEdit.setValidator(self.passwordValidator)
        self.ui.emailLineEdit.setValidator(self.emailValidator)
        self.ui.usernameLineEdit.setValidator(self.usernameValidator)
        self.ui.currentPasswordLineEdit.setValidator(self.passwordValidator)
        self.ui.newPasswordLineEdit.setValidator(self.passwordValidator)
        self.ui.confirmPasswordLineEdit.setValidator(self.passwordValidator)
        self.ui.macAddressLineEdit.setValidator(self.macValidator)
    
        # connect the textChanged signal to the function that checks validation, this adds borders to the line edits if the text does not match the regex
        self.ui.loginUsernameLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.ClearErrorMessageText(self.ui.loginErrorMessageLabel))
        self.ui.loginPasswordLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.ClearErrorMessageText(self.ui.loginErrorMessageLabel))
        self.ui.registerEmailLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.registerEmailLineEdit, 'registerEmailLineEdit', self.ui.registerErrorMessageLabel))
        self.ui.registerUsernameLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.registerUsernameLineEdit, 'registerUsernameLineEdit', self.ui.registerErrorMessageLabel))
        self.ui.registerPasswordLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.registerPasswordLineEdit, 'registerPasswordLineEdit', self.ui.registerErrorMessageLabel))
        self.ui.registerConfirmPasswordLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.registerConfirmPasswordLineEdit, 'registerConfirmPasswordLineEdit', self.ui.registerErrorMessageLabel))
        self.ui.emailLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.emailLineEdit, 'emailLineEdit', self.ui.saveEmailErrorMessageLabel))
        self.ui.usernameLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.usernameLineEdit, 'usernameLineEdit', self.ui.saveUsernameErrorMessageLabel))
        self.ui.currentPasswordLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.currentPasswordLineEdit, 'currentPasswordLineEdit', self.ui.savePasswordErrorMessageLabel))
        self.ui.newPasswordLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.newPasswordLineEdit, 'newPasswordLineEdit', self.ui.savePasswordErrorMessageLabel))
        self.ui.confirmPasswordLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.confirmPasswordLineEdit, 'confirmPasswordLineEdit', self.ui.savePasswordErrorMessageLabel))
        self.ui.macAddressLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.NotifyInvalidLineEdit(self, self.ui.macAddressLineEdit, 'macAddressLineEdit', self.ui.macAddressBlacklistErrorMessageLabel))


    # method that validates that a given password matches both of our password validator regexes
    def ValidatePassword(self, password):
        simpleValidatorState= self.passwordValidator.validate(password, 0)[0]
        complexValidatorState = self.finalPasswordValidator.validate(password, 0)[0]
        if simpleValidatorState != QValidator.Acceptable or complexValidatorState != QValidator.Acceptable:
            return False
        return True


    # method that sets the text in the info page with the system information of the users machine
    def InitSystemInfo(self, systemDict):
        # initialize system information section (left side)
        self.ui.OSTypeInfoLabel.setText(systemDict.get('osType'))
        self.ui.OSVersionInfoLabel.setText(systemDict.get('osVersion'))
        self.ui.architectureInfoLabel.setText(systemDict.get('architecture'))
        self.ui.hostNameInfoLabel.setText(systemDict.get('hostName'))


    # method for updating network interface from combobox in gui
    def ChangeNetworkInterface(self):
        # set selected interface to chosen interfaces selected in combobox in gui
        NetworkInformation.selectedInterface = self.ui.networkInterfaceComboBox.currentText()
        self.SendLogDict(f'Main_Thread: Changed interface to {NetworkInformation.selectedInterface}', 'INFO') #log interface change event

        # initialize network information section (right side)
        selectedInterface = NetworkInformation.networkInfo.get(NetworkInformation.selectedInterface)
        self.ui.connectedInterfaceInfoLabel.setText(selectedInterface.get('name'))
        self.ui.macAddressInfoLabel.setText(selectedInterface.get('mac'))
        self.ui.descriptionInfoLabel.setText(selectedInterface.get('description'))
        self.ui.maxTransmitionUnitInfoLabel.setText(selectedInterface.get('maxTransmitionUnit'))
        self.ui.ipAddressesListWidget.clear()
        self.ui.ipAddressesListWidget.addItems(selectedInterface.get('ipv4Addrs') + selectedInterface.get('ipv6Addrs'))


    # method for showing file dialog for user to choose his desired path and file name
    def GetPathFromFileDialog(self, title, fileName, extensions):
        options = QFileDialog.Options()
        filePath, _ = QFileDialog.getSaveFileName(
            parent=None, #represents parent window
            caption=title, #represents dialog title
            dir=fileName, #represents default filename
            filter=extensions, #represents supported extensions
            options=options
        )
        return filePath


    # method for initializing mac addresses blacklist in gui
    def InitMacAddresses(self, macBlacklist):
        self.ui.macAddressListWidget.clear() #clear mac addresses list
        self.ui.macAddressListWidget.addItems(macBlacklist) #add all mac addresses to our blacklist


    # method for initializing history table in gui
    def InitHistoryTable(self, alertList):
        self.ui.historyTableWidget.setRowCount(0) #clear history table

        # iterate over each alert in list and add it to our table
        for alert in alertList:
            self.AddRowToHistoryTable(alert.get('srcIp'), alert.get('srcMac'), alert.get('dstIp'),
                                       alert.get('dstMac'), alert.get('attackType'), alert.get('timestamp'))


    # method for initializing report table in gui
    def InitReportTable(self, alertList):
        self.ui.reportPreviewTableModel.ClearRows() #clear report table

        # iterate over each alert in list and add it to our table
        for alert in alertList:
            self.AddRowToReportTable(alert.get('interface'), alert.get('attackType'), alert.get('srcIp'), alert.get('srcMac'), alert.get('dstIp'), 
                                       alert.get('dstMac'), alert.get('protocol'), alert.get('osType'), alert.get('timestamp'))


    # method for adding row to history table at the first index in gui
    def AddRowToHistoryTable(self, srcIp, srcMac, dstIp, dstMac, attackType, timestamp):
        # check that all given parameters are valid and initialized
        if srcIp and srcMac and dstIp and dstMac and attackType and timestamp:
            # create new row to insert into history table at the first index in top row
            row = [srcIp, srcMac, dstIp, dstMac, attackType, timestamp]
            self.ui.historyTableWidget.insertRow(0) #create row at top index

            # iterate over each item in row and add it into history table
            for col, value in enumerate(row):
                item = QTableWidgetItem(str(value)) #create item to insert
                item.setToolTip(item.text()) #set tooltip for specific item
                item.setTextAlignment(Qt.AlignCenter) #center the text
                self.ui.historyTableWidget.setItem(0, col, item) #insert item


    # method for adding row to report preview table at the first index in gui
    def AddRowToReportTable(self, interface, attackType, srcIp, srcMac, dstIp, dstMac, protocol, osType, timestamp):
        # check that all given parameters are valid and initialized
        if interface and attackType and srcIp and srcMac and dstIp and dstMac and protocol and osType and timestamp:
            # call out custom AddRow method for adding given parameters as a row in report preview table
            self.ui.reportPreviewTableModel.AddRow(interface, attackType, srcIp, srcMac, dstIp, dstMac, protocol, osType, timestamp)


    # method for setting user interface to logged in or logged out state 
    def ChangeUserState(self, state, userData=None):
        # check if detection is off
        if not self.isDetection:
            # means we need to set user interface for logged in user
            if state and userData:
                self.InitUserData(userData) #initialzie user data dictionary for logged in user
                UserInterfaceFunctions.AccountIconClicked(self) #close login popup
                self.ui.colorModeComboBox.setCurrentIndex(self.userData.get('lightMode')) #set color mode combobox to the value received from database
                self.ui.operationModeComboBox.setCurrentIndex(self.userData.get('operationMode')) #set operation mode combobox to the value received from database
                UserInterfaceFunctions.ToggleUserInterface(self, True) #toggle user interface
                self.ui.welcomeLabel.setText(f'Welcome {self.userData.get('userName')}')
                self.UpdateNumberOfDetectionsCounterLabel(self.userData.get('numberOfDetections')) #set num of detections counter
                self.ui.emailLineEdit.setText(self.userData.get('email')) #set email of user in settings page
                self.ui.usernameLineEdit.setText(self.userData.get('userName')) #set username of user in settings page
                self.InitHistoryTable(self.userData.get('alertList')) #initialize our history table
                self.InitReportTable(self.userData.get('alertList')) #initialize our report table
                self.InitMacAddresses(self.userData.get('blackList')) #intialize our mac address black list
                UserInterfaceFunctions.UpdatePieChartAfterLogin(self, self.userData.get('pieChartData')) #initialize pie chart
                UserInterfaceFunctions.UpdateHistogramChartAfterLogin(self, self.userData.get('analyticsChartData').get('histogramChartData')) #initialize histogram chart
                UserInterfaceFunctions.UpdateBarChartAfterLogin(self, self.userData.get('analyticsChartData').get('barChartData')) #initialize horizontal bar chart
                UserInterfaceFunctions.SetDataIntoCards(self) #initialize analytics cards section
                self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has logged in.', 'INFO') #log login event

            # means we set user interface for logged out user
            else:
                self.InitUserData() #initialzie user data dictionary to default
                UserInterfaceFunctions.ToggleUserInterface(self, False) #reset our user interface
                self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has logged out.', 'INFO') #log logout event


    # method for updating number of detections counter label in gui
    def UpdateNumberOfDetectionsCounterLabel(self, value, isIncrement=False):
        if self.userData:
            # increment by value if flag set
            if isIncrement:
                self.userData.setdefault('numberOfDetections', 0)
                self.userData['numberOfDetections'] += value
            # else we set value
            else:
                self.userData['numberOfDetections'] = value
            # set numberOfDetectionsCounter with new value
            self.ui.numberOfDetectionsCounter.setText(str(self.userData.get('numberOfDetections')))


    # method for toggling message box visability state
    def ToggleMessageBox(self, state):
        # set the custom message box visability flag
        UserInterfaceFunctions.CustomMessageBox.isMessageBox = state


    # method for sending logs to logger thread for writing logs
    @Slot(str, str)
    def SendLogDict(self, message, level='INFO'):
        # if logger thread active we send logs
        if self.loggerThread:
            logDict = {'timestamp': NetworkInformation.GetCurrentTimestamp(), 'level': level, 'message': message}
            self.loggerThread.ReceiveLog(logDict)


    # method for updating report progress bar in gui
    @Slot(int)
    def UpdateReportProgressBar(self, value):
         self.ui.reportProgressBar.setValue(value)


    # method for updating running time label in gui
    @Slot()
    def UpdateRunningTimeCounterLabel(self):
        # increment timer by 1 second
        self.timeElapsed += timedelta(seconds=1)
        # get number of total seconds passed with timedelta object
        totalSeconds = int(self.timeElapsed.total_seconds())
        # extract days, hours, minutes and seconds directly from the timedelta object
        days = totalSeconds // 86400 #get the number of days
        hours = (totalSeconds % 86400) // 3600 #get the remaining hours
        minutes = (totalSeconds % 3600) // 60 #get the remaining minutes
        seconds = totalSeconds % 60 #get the remaining seconds
        # calcluated formatted time in our desired format
        formattedTime = f'{f'{days}:{hours:02}' if days else hours}:{minutes:02}:{seconds:02}'
        # update label with formatted time
        self.ui.runningTimeCounter.setText(formattedTime)


    # method for updating timer in main thread
    @Slot(bool)
    def UpdateTimer(self, state):
        if state:
            #starting timer for determine when to start our defence
            self.totalTimer.start(self.totalTimeout)
            self.arpTimer.start(self.arpTimeout)
            self.portScanDosTimer.start(self.portScanDosTimout)
            self.dnsTimer.start(self.dnsTimout)
        else:
            #else we reset our timer
            self.totalTimer.stop()
            self.arpTimer.stop()
            self.portScanDosTimer.stop()
            self.dnsTimer.stop()
            self.timeElapsed = timedelta()
            self.ui.runningTimeCounter.setText('0:00:00')

    
    # method for updating arp list in main thread
    @Slot(ARP_Packet)
    def UpdateArpList(self, arpPacket):
        # we check if our arp tables are initialized, if so continue
        if ArpSpoofing.isArpTables:
            # we ensure thread safety with our arp mutex
            with QMutexLocker(self.arpMutex):
                self.arpList.append(arpPacket)
                self.arpCounter += 1 #increment counter

            # check if we reached packet threshold
            if self.arpCounter >= self.arpThreshold:
                self.arpTimer.stop() #stopping timer
                self.arpTimer.start(self.arpTimeout) #resetting timer
                self.SendArpList() #call our method to send packets for analysis

    
    # method for updating portScanDos dict in main thread
    @Slot(tuple, Default_Packet)
    def UpdatePortScanDosDict(self, flowTuple, packet):
        # we ensure thread safety with our portScanDos mutex
        with QMutexLocker(self.portScanDosMutex):
            if flowTuple in self.portScanDosDict: #if flow tuple exists in dict
                self.portScanDosDict[flowTuple].append(packet) #append to list our packet
            else: #else we create new entry with flow tuple
                self.portScanDosDict[flowTuple] = [packet] #create new list with packet
            self.tcpUdpCounter += 1 #increment counter

        # check if we reached packet threshold
        if self.tcpUdpCounter >= self.portScanDosThreshold:
            self.portScanDosTimer.stop() #stopping timer
            self.portScanDosTimer.start(self.portScanDosTimout) #resetting timer
            self.SendPortScanDosDict() #call our method to send packets for analysis


    # method for updating portScanDos dict in main thread
    @Slot(tuple, DNS_Packet)
    def UpdateDnsDict(self, flowTuple, dnsPacket):
        # we ensure thread safety with our dns mutex
        with QMutexLocker(self.dnsMutex):
            if flowTuple in self.dnsDict: #if flow tuple exists in dict
                self.dnsDict[flowTuple].append(dnsPacket) #append to list our packet
            else: #else we create new entry with flow tuple
                self.dnsDict[flowTuple] = [dnsPacket] #create new list with packet
            self.dnsCounter += 1 #increment counter

        # check if we reached packet threshold
        if self.dnsCounter >= self.dnsThreshold:
            self.dnsTimer.stop() #stopping timer
            self.dnsTimer.start(self.dnsTimout) #resetting timer
            self.SendDnsDict() #call our method to send packets for analysis

    
    # method for extracting packet batches from arp list and sending to thread for analysis from main thread
    @Slot()
    def SendArpList(self):
        # we ensure thread safety with our arp mutex
        with QMutexLocker(self.arpMutex):
            arpBatch = [] #represents list of extracted packets

            # calculate the number of packets to extract for batch
            batchSize = min(len(self.arpList), 20) #max 20 arp packets in batch
            if batchSize > 0:
                # Extract the packets into arp batch
                arpBatch = self.arpList[:batchSize] #get first batchSize packets out of arp list

                # remove the extracted packets from arp list
                del self.arpList[:batchSize] #remove the first batchSize packets from arp list

                # Send the extracted batch to the worker thread
                self.arpCounter -= len(arpBatch) #update arp counter
                if not self.dataCollectorThread and self.ui.operationModeComboBox.currentIndex() == 0:
                    self.arpThread.ReceiveArpBatch(arpBatch) #send batch to arp thread
                    self.SendLogDict('Main_Thread: Sent arp list for analysis.', 'INFO') #log send event


    # method for extracting packet batches from portScanDos dict and sending to thread for analysis from main thread
    @Slot()
    def SendPortScanDosDict(self):
        # we ensure thread safety with our portScanDos mutex
        with QMutexLocker(self.portScanDosMutex):
            portScanDosBatch = {} #represents dict of extracted packets
            totalPackets = 0 #represents number of extracted packets

            # loop through the dict and try to get our threshold (10,000) packets if possible
            while self.portScanDosDict and totalPackets < self.portScanDosThreshold:
                emptyFlows = [] #we track empty flows for cleanup

                # iterate over each flow in dict
                for flow, packetList in self.portScanDosDict.items():
                    if totalPackets >= self.portScanDosThreshold: #means we have enough packets
                        break

                    if len(packetList) == 0: #means flow empty
                        emptyFlows.append(flow) #add flow to our emptyFlows dict for removal
                        continue

                    # calculate the batch size for each flow and add it to our batch
                    batchSize = min(self.portScanDosThreshold - totalPackets, len(packetList), 500) #max packets in each iteration is 500
                    portScanDosBatch.setdefault(flow, []).extend(self.portScanDosDict[flow][:batchSize]) #add batch packets to portScanDos dict

                    # remove extracted packets from flow's list
                    del self.portScanDosDict[flow][:batchSize]

                    totalPackets += batchSize #add batchSize to our total packets

                # remove empty flows dns dict
                for flow in emptyFlows:
                    del self.portScanDosDict[flow]

            # send packets batch only if batch isn't empty
            if totalPackets > 0:
                self.tcpUdpCounter -= totalPackets #update tcp udp counter
                # means we send batch to portScanDos thread for analysis
                if not self.dataCollectorThread and self.ui.operationModeComboBox.currentIndex() == 0:
                    self.portScanDosThread.ReceivePortScanDosBatch(portScanDosBatch) #send batch to portScanDos thread
                    self.SendLogDict('Main_Thread: Sent portScanDos list for analysis.', 'INFO') #log send event
                # else we send batch to data collector thread for data collection
                elif self.dataCollectorThread and self.ui.operationModeComboBox.currentIndex() == 1:
                    self.dataCollectorThread.ReceivePacketBatch(portScanDosBatch) #send batch to data collector thread
                    self.SendLogDict('Main_Thread: Sent portScanDos list for data collection.', 'INFO') #log send event


    # method for extracting packet batches from dns dict and sending to thread for analysis from main thread
    @Slot()
    def SendDnsDict(self):
        # we ensure thread safety with our dns mutex
        with QMutexLocker(self.dnsMutex):
            dnsBatch = {} #represents dict of extracted packets
            totalPackets = 0 #represents number of extracted packets

            # loop through the dict and try to get our threshold (350) packets if possible
            while self.dnsDict and totalPackets < self.dnsThreshold:
                emptyFlows = [] #we track empty flows for cleanup

                # iterate over each flow in dict
                for flow, packetList in self.dnsDict.items():
                    if totalPackets >= self.dnsThreshold: #means we have enough packets
                        break

                    if len(packetList) == 0: #means flow empty
                        emptyFlows.append(flow) #add flow to our emptyFlows dict for removal
                        continue

                    # calculate the batch size for each flow and add it to our batch
                    batchSize = min(self.dnsThreshold - totalPackets, len(packetList), 50) #max packets in each iteration is 50
                    dnsBatch.setdefault(flow, []).extend(self.dnsDict[flow][:batchSize]) #add batch packets to dnsBatch dict

                    # remove extracted packets from flow's list
                    del self.dnsDict[flow][:batchSize]

                    totalPackets += batchSize #add batchSize to our total packets

                # remove empty flows dns dict
                for flow in emptyFlows:
                    del self.dnsDict[flow]
            
            # send packets batch only if batch isn't empty
            if totalPackets > 0:
                self.dnsCounter -= totalPackets #update dns counter
                # means we send batch to dns thread for analysis
                if not self.dataCollectorThread and self.ui.operationModeComboBox.currentIndex() == 0:
                    self.dnsThread.ReceiveDnsBatch(dnsBatch) #send batch to dns thread
                    self.SendLogDict('Main_Thread: Sent dns list for analysis.', 'INFO') #log send event
                # else we send batch to data collector thread for data collection
                elif self.dataCollectorThread and self.ui.operationModeComboBox.currentIndex() == 2:
                    self.dataCollectorThread.ReceivePacketBatch(dnsBatch) #send batch to data collector thread
                    self.SendLogDict('Main_Thread: Sent dns list for data collection.', 'INFO') #log send event


    # method for closing SQL thread and setting it back to none
    @Slot(dict)
    def CloseSQLThread(self, stateDict):
        self.sqlThread = None #set thread to none
        # in case of an error we show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.SendLogDict(f'SQL_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', stateDict.get('message'), 'Critical')
        self.SendLogDict('SQL_Thread: Finsihed database tasks.', 'INFO') #log finish event


    # method for closing report thread and setting it back to none
    @Slot(dict, bool)
    def CloseReportThread(self, stateDict, isClosing=False):
        self.reportThread = None #set thread to none
        # toggle report interface to be hidden
        UserInterfaceFunctions.ToggleReportInterface(self, False)
        # only show popup messages if isClosing flag is not set
        if not isClosing:
            # in case of an error we show error message
            if stateDict.get('state') == False and stateDict.get('message'):
                self.SendLogDict(f'Report_Thread: {stateDict.get('message')}', 'ERROR') #log error event
                UserInterfaceFunctions.ShowMessageBox('Error Occurred', stateDict.get('message'), 'Critical')
            # in case of cancelation, we show cancelation messsage
            elif stateDict.get('state') == True and stateDict.get('message'):
                self.SendLogDict(f'Report_Thread: {stateDict.get('message')}', 'INFO') #log cancel report event
                UserInterfaceFunctions.ShowMessageBox('Canceled Report Generation', stateDict.get('message'), 'Information')
            # else we show success message
            else:
                UserInterfaceFunctions.ShowMessageBox('Generated Report Successfully', 'Generated report in desired format successfully.', 'Information')
        self.SendLogDict('Report_Thread: Finsihed Creating Report.', 'INFO') #log finish event


    # method for closing logger thread and setting it back to none
    @Slot(dict)
    def CloseLoggerThread(self, stateDict):
        self.loggerThread = None #set thread to none
        # in case of an error we show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.SendLogDict(f'Logger_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', stateDict.get('message'), 'Critical')


    # method for closing sniffer thread and setting it back to none
    @Slot(dict)
    def CloseSnifferThread(self, stateDict):
        self.snifferThread = None #set thread to none for next detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.arpThread and not self.portScanDosThread and not self.dnsThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            self.SendLogDict(f'Sniffer_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', stateDict.get('message'), 'Critical')
        self.SendLogDict('Sniffer_Thread: Finsihed network scan.', 'INFO') #log finish event


    # method for closing arp thread and setting it back to none
    @Slot(dict)
    def CloseArpThread(self, stateDict):
        self.arpThread = None #set thread to none for next detection
        ArpSpoofing.isArpTables = False #set our initialized flag to false for arp detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.snifferThread and not self.portScanDosThread and not self.dnsThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            self.SendLogDict(f'Arp_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', stateDict.get('message'), 'Critical')
        self.SendLogDict('Arp_Thread: Finsihed analysis of traffic.', 'INFO') #log finish event


    # method for closing portScanDos thread and setting it back to none
    @Slot(dict)
    def ClosePortScanDosThread(self, stateDict):
        self.portScanDosThread = None #set thread to none for next detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.snifferThread and not self.arpThread and not self.dnsThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            self.SendLogDict(f'PortScanDos_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', stateDict.get('message'), 'Critical')
        self.SendLogDict('PortScanDos_Thread: Finsihed analysis of traffic.', 'INFO') #log finish event


    # method for closing dns thread and setting it back to none
    @Slot(dict)
    def CloseDnsThread(self, stateDict):
        self.dnsThread = None #set thread to none for next detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.snifferThread and not self.arpThread and not self.portScanDosThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            self.SendLogDict(f'Dns_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', stateDict.get('message'), 'Critical')
        self.SendLogDict('Dns_Thread: Finsihed analysis of traffic.', 'INFO') #log finish event


    # method for closing data collector thread and setting it back to none
    @Slot(dict)
    def CloseDataCollectorThread(self, stateDict):
        self.dataCollectorThread = None #set thread to none for next detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.snifferThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            self.SendLogDict(f'Data_Collector_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Occurred', stateDict.get('message') , 'Critical')
        self.SendLogDict('Data_Collector_Thread: Finsihed collecting data.', 'INFO') #log finish event


    # method for receiving database connection result
    @Slot(dict)
    def ConnectionResult(self, stateDict):
        # we check if failed connecting to database
        if stateDict.get('state') == False and stateDict.get('message'):
            self.SendLogDict(f'SQL_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Database Connection Failed', stateDict.get('message'), 'Critical')
        # else we successfully connected to database
        elif stateDict.get('state') == True and stateDict.get('message'):
            self.SendLogDict(f'SQL_Thread: {stateDict.get('message')}', 'INFO') #log connection event


    # method for receiving initialize email credentils result
    @Slot(dict)
    def InitEmailCredentilsResult(self, stateDict):
        # we check if failed initialization of email credentils for reset password emails
        if stateDict.get('state') == False and stateDict.get('message'):
            self.SendLogDict(f'SQL_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Failed Initializing App Email', stateDict.get('message') , 'Critical')
        # else we successfully initialized email credentils for reset password emails
        elif stateDict.get('state') == True and stateDict.get('message'):
            self.SendLogDict(f'SQL_Thread: {stateDict.get('message')}', 'INFO') #log initialize credentils event
    

    # method for receiving number of collected flows in dataset for data collection
    @Slot(int)
    def CollectionResult(self, collectedFlows):
        self.SendLogDict(f'Data_Collector_Thread: Collected {collectedFlows} flows.', 'INFO') #log collection event


    # method for analyzing detection result of arp spoofing attack
    @Slot(dict)
    def ArpDetectionResult(self, result):
        # check if ARP tables are being initialized (type 3)
        if result.get('type') == 3:
            ArpSpoofing.isArpTables = True #set isArpTable to true indicating we can sniff arp packets
            self.SendLogDict('Arp_Thread: Initialized ARP tables successfully.', 'INFO') #log arp tables initialization event

        # process only if an attack is detected state is false and an attackDict provided
        if result.get('state') == False and result.get('attackDict'):
            type = result.get('type') #represents type of result, 1-ipToMac, 2-macToIp, 3-Both
            attackDict = result.get('attackDict') #represents attack dictionary with all anomalies found

            # handle Ip to Mac anomalies we found in arp spoofing attack (including initialization)
            if type in (1, 3):
                # represents the ipDict of arp spoofing, for type 3 its nested under 'ipToMac'
                ipDict = attackDict if type == 1 else attackDict.get('ipToMac', {})
                for ip, details in ipDict.items():
                    isNewAttack = False #represents a flag for indicating if attack is new or not

                    # we check if detected ip is in our known attacks in arpAttackDict
                    if ip not in self.arpAttackDict.get('ipToMac', {}):
                        self.arpAttackDict['ipToMac'][ip] = details #add new ip entry in our arpAttackDict
                        isNewAttack = True #set new attack to true

                    # we check if detected ip is already in our known attacks in arpAttackDict
                    elif ip in self.arpAttackDict.get('ipToMac', {}):
                        # we check if its a repeated attack from same source, we alert again after some time
                        if NetworkInformation.CompareTimepstemps(self.arpAttackDict['ipToMac'][ip].get('timestamp'), details.get('timestamp'), minutes=self.repeatedAttackTimeout):
                            self.arpAttackDict['ipToMac'][ip]['timestamp'] = details.get('timestamp') #update timestamp with new attack time
                            isNewAttack = True #set new attack to true

                        # else we check if there is a new mac addresses associated with ip
                        else:
                            # represents new mac addresses we found in arp spoofing attack
                            details['srcMac'] = details.get('srcMac', set()) - self.arpAttackDict['ipToMac'][ip].get('srcMac', set()) #we substract given set from known attacks set to get new macs
                            # if true we update our arpAttackDict according to new macs we found
                            if details.get('srcMac', set()):
                                self.arpAttackDict['ipToMac'][ip]['srcMac'].update(details.get('srcMac', set())) #update our known macs in arpAttackDict in ip index
                                isNewAttack = True #set new attack to true

                    # if attack is new we update tables in gui and add to database
                    if isNewAttack:
                        # iterate over each mac in given set and add it to our tables
                        for mac in details.get('srcMac', set()):
                            self.AddAlert('ARP Spoofing', details.get('srcIp'), mac, details.get('dstIp'), details.get('dstMac'), details.get('protocol'), details.get('timestamp'))
                            self.SendLogDict(f'Main_Thread: New ipToMac ARP Spoofing attack detected from IP {ip}: srcIp: {details.get('srcIp')}, srcMac: {mac}, dstIp: {details.get('dstIp')}, dstMac: {details.get('dstMac')}, protocol: {details.get('protocol')}', 'ALERT') #log alert event

            # handle Mac to Ip anomalies we found in arp spoofing attack (including initialization)
            if type in (2, 3):
                # represents the macDict of arp spoofing, for type 3 its nested under 'macToIp'
                macDict = attackDict if type == 2 else attackDict.get('macToIp', {})
                for mac, details in macDict.items():
                    isNewAttack = False #represents a flag for indicating if attack is new or not

                    # we check if detected mac is in our known attacks in arpAttackDict
                    if mac not in self.arpAttackDict.get('macToIp', {}):
                        self.arpAttackDict['macToIp'][mac] = details #add new mac entry in our arpAttackDict
                        isNewAttack = True #set new attack to true

                    # we check if detected mac is already in our known attacks in arpAttackDict
                    elif mac in self.arpAttackDict.get('macToIp', {}):
                        # we check if its a repeated attack from same source, we alert again after some time
                        if NetworkInformation.CompareTimepstemps(self.arpAttackDict['macToIp'][mac].get('timestamp'), details.get('timestamp'), minutes=self.repeatedAttackTimeout):
                            self.arpAttackDict['macToIp'][mac]['timestamp'] = details.get('timestamp') #update timestamp with new attack time
                            isNewAttack = True #set new attack to true

                        # else we check if there is a new ip addresses associated with mac
                        else:
                            # represents new mac addresses we found in arp spoofing attack
                            details['srcIp'] = details.get('srcIp', set()) - self.arpAttackDict['macToIp'][mac].get('srcIp', set()) #we substract given set from known attacks set to get new ips
                            # if true we update our arpAttackDict according to new ips we found
                            if details.get('srcIp', set()):
                                self.arpAttackDict['macToIp'][mac]['srcIp'].update(details.get('srcIp', set())) #update our known ips in arpAttackDict in mac index
                                isNewAttack = True #set new attack to true

                    # if attack is new we update tables in gui and add to database
                    if isNewAttack:
                        # iterate over each ip in given set and add it to our tables
                        for ip in details.get('srcIp', set()):
                            self.AddAlert('ARP Spoofing', ip, details.get('srcMac'), details.get('dstIp'), details.get('dstMac'), details.get('protocol'), details.get('timestamp'))
                            self.SendLogDict(f'Main_Thread: New macToIp ARP Spoofing attack detected from MAC {mac}: srcIp: {ip}, srcMac: {details.get('srcMac')}, dstIp: {details.get('dstIp')}, dstMac: {details.get('dstMac')}, protocol: {details.get('protocol')}', 'ALERT') #log alert event


    # method for analyzing detection result of port scan and dos attacks 
    @Slot(dict)
    def PortScanDosDetectionResult(self, result):
        if result.get('state') == False and result.get('attackDict'):
            type = result.get('type') #represents type of result, 1-PortScan, 2-DoS
            attackDict = result.get('attackDict') #represents attack dictionary with all anomalies found

            # iterate over each flow we found in attacksDict
            for flow, details in attackDict.items():
                isNewAttack = False #represents a flag for indicating if attack is new or not

                # we check if detected flow is in our known attacks in portScanDosAttackDict
                if flow not in self.portScanDosAttackDict:
                    self.portScanDosAttackDict[flow] = details #add new flow entry in our portScanDosAttackDict
                    isNewAttack = True #set new attack to true
                
                # we check if its a repeated attack from same source, we alert again after some time
                elif flow in self.portScanDosAttackDict and NetworkInformation.CompareTimepstemps(self.portScanDosAttackDict[flow].get('timestamp'), details.get('timestamp'), minutes=self.repeatedAttackTimeout):
                    self.portScanDosAttackDict[flow]['timestamp'] = details.get('timestamp') #update timestamp with new attack time
                    isNewAttack = True #set new attack to true
                
                # if attack is new we update tables in gui and add to database
                if isNewAttack:
                    # handle anomalies we found in port scan attack and add them to our tables
                    if type in (1, 3) and flow[5] == 1:
                        self.AddAlert('Port Scan', flow[0], flow[1], flow[2], flow[3], flow[4], details.get('timestamp'))
                        self.SendLogDict(f'Main_Thread: New Port Scan attack detected from IP {flow[0]}: srcIp: {flow[0]}, srcMac: {flow[1]}, dstIp: {flow[2]}, dstMac: {flow[3]}, protocol: {flow[4]}', 'ALERT') #log alert event
                    # handle anomalies we found in DoS attack and add them to our tables
                    if type in (2, 3) and flow[5] == 2:
                        self.AddAlert('DoS', flow[0], flow[1], flow[2], flow[3], flow[4], details.get('timestamp'))
                        self.SendLogDict(f'Main_Thread: New DoS attack detected from IP {flow[0]}: srcIp: {flow[0]}, srcMac: {flow[1]}, dstIp: {flow[2]}, dstMac: {flow[3]}, protocol: {flow[4]}', 'ALERT') #log alert event

    
    # method for analyzing detection result of dns tunneling attack
    @Slot(dict)
    def DnsDetectionResult(self, result):
        if result.get('state') == False and result.get('attackDict'):
            attackDict = result.get('attackDict') #represents attack dictionary with all anomalies found

            # iterate over each flow we found in attacksDict
            for flow, details in attackDict.items():
                isNewAttack = False #represents a flag for indicating if attack is new or not

                # we check if detected flow is in our known attacks in dnsAttackDict
                if flow not in self.dnsAttackDict:
                    self.dnsAttackDict[flow] = details #add new flow entry in our dnsAttackDict
                    isNewAttack = True #set new attack to true
                
                # we check if its a repeated attack from same source, we alert again after some time
                elif flow in self.dnsAttackDict and NetworkInformation.CompareTimepstemps(self.dnsAttackDict[flow].get('timestamp'), details.get('timestamp'), minutes=self.repeatedAttackTimeout):
                    self.dnsAttackDict[flow]['timestamp'] = details.get('timestamp') #update timestamp with new attack time
                    isNewAttack = True #set new attack to true
                
                # if attack is new we update tables in gui and add to database
                if isNewAttack:
                    # handle anomalies we found in dns tunneling attack and add them to our tables
                    self.AddAlert('DNS Tunneling', flow[0], flow[1], flow[2], flow[3], flow[4], details.get('timestamp'))
                    self.SendLogDict(f'Main_Thread: New DNS Tunneling attack detected from IP {flow[0]}: srcIp: {flow[0]}, srcMac: {flow[1]}, dstIp: {flow[2]}, dstMac: {flow[3]}, protocol: {flow[4]}', 'ALERT') #log alert event


    # method for stopping detection or collection and closing threads
    def StopDetection(self):
        if self.isDetection:
            # we check each thread and close it if running
            if self.snifferThread:
                self.snifferThread.StopThread()
            if self.arpThread:
                self.arpThread.StopThread()
            if self.portScanDosThread:
                self.portScanDosThread.StopThread()
            if self.dnsThread:
                self.dnsThread.StopThread()
            if self.dataCollectorThread:
                self.dataCollectorThread.StopThread()
            
            # enable interface combobox and reset our data structures and counters
            self.SendLogDict(f'Main_Thread: Stopping detection. Remaining packets - TCP/UDP: {self.tcpUdpCounter}, DNS: {self.dnsCounter}, ARP: {self.arpCounter}', 'INFO') #log stop event
            UserInterfaceFunctions.ToggleStartStopState(self, False) #change startStop button back to green
            self.ui.networkInterfaceComboBox.setEnabled(True) #enable interfaces combobox
            self.ui.operationModeComboBox.setEnabled(True) #enable operation mode combobox
            self.arpCounter, self.tcpUdpCounter, self.dnsCounter = 0, 0, 0 #reset our counters
            self.arpList, self.portScanDosDict, self.dnsDict = [], {}, {} #reset our packet data structures
            self.arpAttackDict, self.portScanDosAttackDict, self.dnsAttackDict = {'ipToMac': {}, 'macToIp': {}}, {}, {} #reset known attacks


    # method for starting our threads and detect network cyber attacks in real time or collect datasets for training models, depends on user's choice
    def StartDetection(self):
        if not self.snifferThread and not self.arpThread and not self.portScanDosThread and not self.dnsThread and not self.dataCollectorThread:
            # means we start threads for detecting attacks in real time
            if self.ui.operationModeComboBox.currentIndex() == 0:
                # set isDetection flag and disable interface and operation mode comboboxes
                self.isDetection = True #set detection flag
                UserInterfaceFunctions.ToggleStartStopState(self, True) #change startStop button to red for detection
                self.ui.networkInterfaceComboBox.setEnabled(False) #disable interfaces combobox
                self.ui.operationModeComboBox.setEnabled(False) #disable operation mode combobox

                # initialize sniffer thread for real time packet gathering
                self.snifferThread = Sniffing_Thread(self, NetworkInformation.selectedInterface)
                # connect relevant signals for sniffer thread
                self.snifferThread.updateTimerSignal.connect(self.UpdateTimer)
                self.snifferThread.updateArpListSignal.connect(self.UpdateArpList)
                self.snifferThread.updatePortScanDosDictSignal.connect(self.UpdatePortScanDosDict)
                self.snifferThread.updateDnsDictSignal.connect(self.UpdateDnsDict)
                self.snifferThread.finishSignal.connect(self.CloseSnifferThread)

                # initialize arp thread for arp spoofing detection
                self.arpThread = Arp_Thread(self)
                # connect relevant signals for arp thread
                self.arpThread.detectionResultSignal.connect(self.ArpDetectionResult)
                self.arpThread.finishSignal.connect(self.CloseArpThread)

                # initialize portScanDos thread for port scan and dos detection
                self.portScanDosThread = PortScanDos_Thread(self)
                # connect relevant signals for portScanDos thread
                self.portScanDosThread.detectionResultSignal.connect(self.PortScanDosDetectionResult)
                self.portScanDosThread.finishSignal.connect(self.ClosePortScanDosThread)

                # initialize dns thread for dns tunneling detection
                self.dnsThread = Dns_Thread(self)
                # connect relevant signals for dns thread
                self.dnsThread.detectionResultSignal.connect(self.DnsDetectionResult)
                self.dnsThread.finishSignal.connect(self.CloseDnsThread)

                # start our threads for detection
                self.snifferThread.start()
                self.arpThread.start()
                self.portScanDosThread.start()
                self.dnsThread.start()

                # log initializing of threads
                self.SendLogDict('Sniffer_Thread: Starting Network Scan.', 'INFO') #log sniffer start event
                self.SendLogDict('Arp_Thread: Starting Arp thread.', 'INFO') #log arp start event
                self.SendLogDict('PortScanDos_Thread: Starting portScanDos thread.', 'INFO') #log portScanDos start event
                self.SendLogDict('Dns_Thread: Starting Dns thread.', 'INFO') #log dns start event

            # else it means we start threads for data collection
            else:
                # set default selected data to be PortScanDos for collecting TCP/UDP flows
                fileName, selectedData = 'port_scan_dos_benign_dataset.csv', 'PortScanDos'

                # if user selected DNS we set selected data to be DNSTunneling for collecting DNS flows
                if self.ui.operationModeComboBox.currentIndex() == 2:
                    fileName, selectedData = 'dns_benign_dataset.csv', 'DNSTunneling'

                # get desired path for data collection from file dialog
                filePath = self.GetPathFromFileDialog('Save Dataset', fileName, 'CSV Files (*.csv)')

                # if user chose a path we generate csv dataset with our thread
                if filePath:
                    # set isDetection flag and disable interface and operation mode comboboxes
                    self.isDetection = True #set detection flag
                    UserInterfaceFunctions.ToggleStartStopState(self, True) #change startStop button to red for collection
                    self.ui.networkInterfaceComboBox.setEnabled(False) #disable interfaces combobox
                    self.ui.operationModeComboBox.setEnabled(False) #disable operation mode combobox

                    # initialize sniffer thread for real time packet gathering
                    self.snifferThread = Sniffing_Thread(self, NetworkInformation.selectedInterface)
                    # connect relevant signals for sniffer thread
                    self.snifferThread.updateTimerSignal.connect(self.UpdateTimer)
                    self.snifferThread.updateArpListSignal.connect(self.UpdateArpList)
                    self.snifferThread.updatePortScanDosDictSignal.connect(self.UpdatePortScanDosDict)
                    self.snifferThread.updateDnsDictSignal.connect(self.UpdateDnsDict)
                    self.snifferThread.finishSignal.connect(self.CloseSnifferThread)

                    # initialize data collector thread for collecting datasets for training models
                    self.dataCollectorThread = Data_Collector_Thread(self, filePath, selectedData)
                    # connect relevant signals for data collector thread
                    self.dataCollectorThread.collectionResultSignal.connect(self.CollectionResult)
                    self.dataCollectorThread.finishSignal.connect(self.CloseDataCollectorThread)

                    # start our threads for data collection
                    self.snifferThread.start()
                    self.dataCollectorThread.start()

                    # log initializing of threads
                    self.SendLogDict('Sniffer_Thread: Starting Network Scan.', 'INFO') #log sniffer start event
                    self.SendLogDict('Data_Collector_Thread: Starting data collector thread.', 'INFO') #log data collector start event

        else:
            self.SendLogDict('Main_Thread: One of the threads is still in process, cannot start new scan.', 'INFO') #log event
            UserInterfaceFunctions.ShowMessageBox('Error Starting Scan', 'One of the threads is still in process, cannot start new scan.', 'Warning')


    # method for startStop button for starting or stopping detection or collection
    def StartStopButtonClicked(self):
        # if isDetection is not set it means we start a new detection or collection
        if not self.isDetection:
            self.StartDetection() #call method to start detection or collecction
        # else we had a detection or collection running, we stop current process
        else:
            self.StopDetection() #call method to stop detection or collecction

    #-----------------------------------------------CLICKED-METHODS----------------------------------------------#

    # method for loggin into user's account and intialize our userData dictionary
    def LoginButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowMessageBox('Error In Login', 'Please stop network scan before attempting to log in.', 'Information')
            # means both fields are empty
            elif not self.ui.loginUsernameLineEdit.text() and not self.ui.loginPasswordLineEdit.text():
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.loginErrorMessageLabel, 'Please enter your username and password.')
            # means username field empty
            elif not self.ui.loginUsernameLineEdit.text():
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.loginErrorMessageLabel, 'Please enter your username.')
            # means password field empty
            elif not self.ui.loginPasswordLineEdit.text():
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.loginErrorMessageLabel, 'Please enter your password.')
            # else we process the login request to our sql thread
            else:
                self.sqlThread.Login(self.ui.loginUsernameLineEdit.text(), NetSpect.ToSHA256(self.ui.loginPasswordLineEdit.text()))


    # method for loggin out of user's account and clear user interface
    def LogoutButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowMessageBox('Error In Logout', 'Please stop network scan before attempting to log out.', 'Information')
            # else we log out and clear interface
            else:
                # check if report thread is active, if so we stop thread
                if self.reportThread:
                    self.reportThread.StopThread(True)
                self.ChangeUserState(False) #call our method to log out and clear interface


    # method for registering new user and adding him to our application
    def RegisterButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowMessageBox('Error In Registration', 'Please stop network scan before attempting to register.', 'Information')
            # else we register new user
            else:
                # get user's email, username and passowrd from line edits and get validator results
                email = self.ui.registerEmailLineEdit.text()
                emailState = self.emailValidator.validate(email, 0)[0]
                username = self.ui.registerUsernameLineEdit.text()
                usernameState = self.usernameValidator.validate(username, 0)[0]
                password = self.ui.registerPasswordLineEdit.text()
                passwordState = self.ValidatePassword(password)
                confirmPassword = self.ui.registerConfirmPasswordLineEdit.text()
                confirmPasswordState = self.ValidatePassword(confirmPassword)

                # means user didnt fill in all the fields
                if not email or not username or not password or not confirmPassword:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please fill in all the fields.')
                # means email, username and password fields are invalid
                elif emailState != QValidator.Acceptable and usernameState != QValidator.Acceptable and (not passwordState or not confirmPasswordState):
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please enter a valid email address, username and passowrd into the fields.')
                # means email and username fields are invalid
                elif emailState != QValidator.Acceptable and usernameState != QValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please enter a valid email address and username into the fields.')
                # means email and password fields are invalid
                elif emailState != QValidator.Acceptable and (not passwordState or not confirmPasswordState):
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please enter a valid email address and password into the fields.')
                # means username and password fields are invalid
                elif usernameState != QValidator.Acceptable and (not passwordState or not confirmPasswordState):
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please enter a valid username and password into the fields.')
                # means email address field is invalid
                elif emailState != QValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please enter a valid email address into the field.')
                # means username field is invalid
                elif usernameState != QValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please enter a valid username into the field.')
                # means password field is invalid
                elif not passwordState or not confirmPasswordState:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please enter a valid password into the field.')
                # means password and confirm password do not match
                elif password != confirmPassword:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, 'Please make sure password and confirmation match.')
                # else we process the register request to our sql thread
                else:
                    self.sqlThread.Register(email, username, NetSpect.ToSHA256(password))


    # method for sending a reset password code the user's email to reset the password
    def SendCodeButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowMessageBox('Error In Reset Password', 'Please stop network scan before receiving a reset code.', 'Information')
            # else we continue with reset password for user
            else:
                # get user's email from line edit and get validator result
                email = self.ui.resetPasswordEmailLineEdit.text()
                emailState = self.emailValidator.validate(email, 0)[0]
                
                # check if email field is not empty
                if not email:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.resetPasswordEmailErrorMessageLabel, 'Please fill in the email field for receiving a reset code.')
                # check if user entered valid email
                elif emailState != QValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.resetPasswordEmailErrorMessageLabel, 'Please enter a valid email address into the field before receiving a reset code.')
                # else we process the reset password request
                else:
                    # generate a 16-character reset code, timestamp and 8-character password for user and save them in resetPasswordValidator
                    self.resetPasswordValidator.update({'resetCode': NetSpect.GetResetCode(length=16), 'timestamp': NetworkInformation.GetCurrentTimestamp(), 'newPassword': NetSpect.GetPassword(length=8)})
                    self.SendLogDict(f'Main_Thread: Reset code for email {email} successfully generated.', 'INFO') #log reset code generation event
                    # send reset code to user's email
                    self.sqlThread.SendResetPasswordCode(email, self.resetPasswordValidator.get('resetCode'))


    # method for verifying the reset password code from the user's email to reset the password
    def VerifyCodeButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowMessageBox('Error In Reset Code Verification', 'Please stop network scan before verifing reset code.', 'Information')
            # else we continue verifing reset code for user
            else:
                # get user's email and reset code from line edits
                email = self.ui.resetPasswordEmailLineEdit.text()
                receivedResetCode = self.ui.resetPasswordCodeLineEdit.text()

                # check if reset code field is not empty
                if not receivedResetCode:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.resetPasswordCodeErrorMessageLabel, 'Please fill in the reset code field for verifying your identity.')
                # check if reset code expired, if so we show message
                elif NetworkInformation.CompareTimepstemps(self.resetPasswordValidator.get('timestamp'), NetworkInformation.GetCurrentTimestamp(), minutes=5):
                    UserInterfaceFunctions.AccountIconClicked(self)
                    self.resetPasswordValidator.update({'resetCode': None, 'timestamp': None, 'newPassword': None}) #reset our resetPasswordValidator
                    self.SendLogDict(f'Main_Thread: Reset code for email {email} has expired.', 'INFO') #log reset code expiration event
                    UserInterfaceFunctions.ShowMessageBox('Reset Code Expired', 'The password reset code has expired, it was valid for 5 minutes. Try resetting password again.', 'Information')
                # check if reset code does'nt match stored code
                elif receivedResetCode != self.resetPasswordValidator.get('resetCode'):
                    UserInterfaceFunctions.ChangeErrorMessageText(self.ui.resetPasswordCodeErrorMessageLabel, 'Your given reset code is incorrect, try again.')
                # else we process the reset password request to our sql thread
                else:
                    self.sqlThread.ResetPassword(email, NetSpect.ToSHA256(self.resetPasswordValidator.get('newPassword')))


    # method for deleting user account from database when user clicks the delete account button in settings page
    def DeleteAccoutButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowMessageBox('Error Deleting Account', 'Please stop network scan before attempting to delete account.', 'Information')
            # else we emit signal to sql thread to delete account from database
            else:
                result = UserInterfaceFunctions.ShowMessageBox('Delete Account Confirmation', 'Deleting your account will permanently remove all your data. Do you want to proceed?', 'Question')
                # if true we proceed and delete user's account
                if result:
                    self.sqlThread.DeleteAccount(self.userData.get('userId'))


    # method for adding alert to tables and also to database if user is logged in
    def AddAlert(self, attackType, srcIp, srcMac, dstIp, dstMac, protocol, timestamp):
        # we add alert only if it does not associated with black listed mac address
        if self.userData and srcMac not in self.userData.get('blackList'):
            # add alert as a dictionary into our alertList and tables
            alert = {
                'interface': NetworkInformation.selectedInterface,
                'attackType': attackType,
                'srcIp': srcIp,
                'srcMac': srcMac,
                'dstIp': dstIp,
                'dstMac': dstMac,
                'protocol': protocol,
                'osType': NetworkInformation.systemInfo.get('osType'),
                'timestamp': timestamp
            }
            self.userData.setdefault('alertList', []).append(alert)

            # add alert to our history and report tables in user interface, update counter and show tray message
            self.UpdateNumberOfDetectionsCounterLabel(1, True) #increment the number of detections counter
            UserInterfaceFunctions.UpdatePieChartAfterAttack(self, attackType) #increment attack type in pie chart
            UserInterfaceFunctions.UpdateHistogramChartAfterAttack(self, attackType) #increment attack type in histogram chart
            UserInterfaceFunctions.UpdateBarChartAfterAttack(self, attackType) #increment attack type in horizontal bar chart
            UserInterfaceFunctions.UpdateDataInCardsAfterAttack(self) #update the data in each card in analytics page
            UserInterfaceFunctions.ShowTrayMessage(self, 'Security Alert', f'Potential {alert.get('attackType')} attack detected from IP: {alert.get('srcIp')}. Immediate action recommended.', 'Warning')
            self.AddRowToHistoryTable(alert.get('srcIp'), alert.get('srcMac'), alert.get('dstIp'), alert.get('dstMac'), alert.get('attackType'), alert.get('timestamp'))
            self.AddRowToReportTable(alert.get('interface'), alert.get('attackType'), alert.get('srcIp'), alert.get('srcMac'), alert.get('dstIp'), alert.get('dstMac'), 
                                            alert.get('protocol'), alert.get('osType'), alert.get('timestamp'))
            
            # add alert to database if user is logged in
            if self.sqlThread and self.userData.get('userId'):
                self.sqlThread.AddAlert(self.userData.get('userId'), alert.get('interface'), alert.get('attackType'), alert.get('srcIp'), alert.get('srcMac'), alert.get('dstIp'),
                                            alert.get('dstMac'), alert.get('protocol'), alert.get('osType'), alert.get('timestamp'))


    # method for deleting all previous detected alerts of user and also updating database if user is logged in
    def DeleteAlertsButtonClicked(self):
        if self.isDetection:
            UserInterfaceFunctions.ShowMessageBox('Error Deleting Alerts', 'Please stop network scan before attempting to delete alerts history.', 'Information')
        else:
            # check that alert list has alerts and not empty
            if self.userData and self.userData.get('alertList'):
                result = UserInterfaceFunctions.ShowMessageBox('Delete Alerts Confirmation', 'Deleting your alerts will permanently remove all your detection history data. Do you want to proceed?', 'Question')
                # if true we proceed and delete user's alerts
                if result:
                    # clear history and report tables and also reset alertsList and user interface counter
                    self.userData['alertList'] = [] #clear alertsList in userData
                    self.userData['pieChartData'] = {} #clear pieChartData in userData
                    self.userData['analyticsChartData'] = {} #clear analyticsChartData in userData
                    self.InitUserData(self.userData) #intialize userData again with empty data for charts for initializing default state
                    self.UpdateNumberOfDetectionsCounterLabel(0) #reset the number of detections counter in user interface
                    UserInterfaceFunctions.ResetPieChartToDefault(self) #reset our pie chart
                    UserInterfaceFunctions.ResetHistogramChartToDefault(self) #reset our histogram chart
                    UserInterfaceFunctions.ResetBarChartToDefault(self) #reset our bar chart
                    UserInterfaceFunctions.ResertDataInCards(self) #reset our cards
                    self.ui.historyTableWidget.setRowCount(0) #clear history table
                    self.ui.reportPreviewTableModel.ClearRows() #clear report table

                    # delete alerts from database if user is logged in
                    if self.sqlThread and self.userData.get('userId'):
                        self.sqlThread.DeleteAlerts(self.userData.get('userId'))
                    else:
                        self.SendLogDict(f'Main_Thread: User Deleted all alerts history data.', 'INFO') #log delete alerts event
                        UserInterfaceFunctions.ShowMessageBox('Alerts Deletion Successful', 'Deleted all alerts history for previously detected attacks.', 'Information')
            else:
                UserInterfaceFunctions.ShowMessageBox('No Alerts Found', 'Your alert history is empty. There are no alerts to delete at this time.', 'Information')


    # method for adding an item to the mac address blacklist when user clicks the add button in settings page
    def AddMacAddressButtonClicked(self):
        # get user's mac address from line edit and get validator result
        newMacAddress = self.ui.macAddressLineEdit.text().lower() #convert characters to lower case for ease of use
        newMacAddressState = self.macValidator.validate(newMacAddress, 0)[0]

        # check if mac address field is not empty
        if not newMacAddress:
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.macAddressBlacklistErrorMessageLabel, 'Please fill in the MAC address field before adding to blacklist.')
        # check if user entered a valid mac address
        elif newMacAddressState != QValidator.Acceptable:
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.macAddressBlacklistErrorMessageLabel, 'Please enter a valid MAC address.')
        # check if given mac address already exists in blacklist
        elif newMacAddress in self.userData.get('blackList'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.macAddressBlacklistErrorMessageLabel, 'This MAC address already exists in blacklist.')
        # else its a new mac address, we add it to blacklist
        else:
            UserInterfaceFunctions.ClearErrorMessageText(self.ui.macAddressBlacklistErrorMessageLabel)
            # add mac address to database if user is logged in
            if self.sqlThread and self.userData.get('userId'):
                self.sqlThread.AddBlacklistMac(self.userData.get('userId'), newMacAddress)
            else:
                self.ui.macAddressListWidget.addItem(newMacAddress)
                self.ui.macAddressLineEdit.clear()
                self.userData.setdefault('blackList', []).append(newMacAddress)
                self.SendLogDict(f'Main_Thread: User has added a new mac address to mac blacklist successfully.', 'INFO') #log add mac event


    # method for removing an item from the mac address blacklist when the user clicks the 'delete' button in the contex menu of the list widget
    def DeleteMacAddressButtonClicked(self, item):
        self.seletecItemForDelete = item #represents item for deletion

        # delete mac address from database if user is logged in
        if self.sqlThread and self.userData.get('userId'):
            self.sqlThread.DeleteBlacklistMac(self.userData.get('userId'), item.text())
        else:
            self.ui.macAddressListWidget.takeItem(self.ui.macAddressListWidget.row(self.seletecItemForDelete))
            self.userData.setdefault('blackList', []).remove(self.seletecItemForDelete.text())
            self.SendLogDict(f'Main_Thread: User has removed mac address from mac blacklist successfully.', 'INFO') #log remove mac event


    # method for saving and updating the user's email address after user clicks save button in settings page
    def SaveEmailButtonClicked(self):
        if self.sqlThread and self.userData.get('userId'):
            # get user's new email address from line edit and get validator result
            newEmail = self.ui.emailLineEdit.text()
            newEmailState = self.emailValidator.validate(newEmail, 0)[0]

            # check if email address field is not empty
            if not newEmail:
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.saveEmailErrorMessageLabel, 'Please fill in the email address field before changing email address.')
            # check if new email address is invaild
            elif newEmailState != QValidator.Acceptable:
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.saveEmailErrorMessageLabel ,'Please enter a valid email address into the field.')
            # check if new email address is current email
            elif newEmail == self.userData.get('email'):
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.saveEmailErrorMessageLabel ,'New email address is the same as the current email address, please enter a different email address.')
            # else we process the change email address request to our sql thread
            else:
                self.sqlThread.ChangeEmail(self.userData.get('userId'), newEmail)


    # method for saving and updating the user's username after user clicks save button in settings page
    def SaveUsernameButtonClicked(self):
        if self.sqlThread and self.userData.get('userId'):
            # get user's new username from line edit and get validator result
            newUsername = self.ui.usernameLineEdit.text()
            newUsernameState = self.usernameValidator.validate(newUsername, 0)[0]

            # check if username field is not empty
            if not newUsername:
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.saveUsernameErrorMessageLabel, 'Please fill in the username field before changing username.')
            # check if new username is invalild
            elif newUsernameState != QValidator.Acceptable:
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.saveUsernameErrorMessageLabel ,'Please enter a valid username into the field.')
            # check if new username is current username
            elif newUsername == self.userData.get('userName'):
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.saveUsernameErrorMessageLabel ,'New username is the same as the current username, please enter a different username.')
            # else we process the change username request to our sql thread
            else:
                self.sqlThread.ChangeUserName(self.userData.get('userId'), newUsername)


    # method for saving and updating the user's password after user clicks save button in settings page
    def SavePasswordButtonClicked(self):
        if self.sqlThread and self.userData.get('userId'):
            # get user's current and new password from line edits and get validator results
            currentPassword = self.ui.currentPasswordLineEdit.text()
            currectPasswordState = self.ValidatePassword(currentPassword)
            newPassword = self.ui.newPasswordLineEdit.text()
            newPasswordState = self.ValidatePassword(newPassword)
            confirmPassword = self.ui.confirmPasswordLineEdit.text()
            confirmPasswordState = self.ValidatePassword(confirmPassword)

            # means user didnt fill in all the password fields
            if not currentPassword or not newPassword or not confirmPassword:
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.savePasswordErrorMessageLabel ,'Please fill in all the password fields before changing password.')
            # means current passowrd is not correct
            elif not currectPasswordState:
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.savePasswordErrorMessageLabel ,'Please enter the correct current password.')
            # means new password or confirmation are not correct
            elif not newPasswordState or not confirmPasswordState:
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.savePasswordErrorMessageLabel ,'Please enter a valid new password.')
            # means new password and confirmation do not match
            elif newPassword != confirmPassword:
                UserInterfaceFunctions.ChangeErrorMessageText(self.ui.savePasswordErrorMessageLabel , 'Please make sure new password and confirmation match.')
            # else we process the change password request to our sql thread
            else:
                self.sqlThread.ChangePassword(self.userData.get('userId'), NetSpect.ToSHA256(newPassword), NetSpect.ToSHA256(currentPassword))


    # method for changing the UI color mode
    def ChangeColorMode(self):
        # update the ui based on the users selection
        UserInterfaceFunctions.ToggleColorMode(self)

        # change the value of lightMode in the database for the current user
        if self.sqlThread and self.userData.get('userId'):
            self.sqlThread.UpdateLightMode(self.userData.get('userId'), self.userData.get('lightMode'))
        else:
            self.SendLogDict(f'Main_Thread: User has changed the UI color preference to "{self.ui.colorModeComboBox.currentText()}".', 'INFO') #log change color mode event


    # method for changing the operation mode of application, detection or collection
    def ChangeOperationMode(self):
        # means we had detection active
        if self.isDetection:
            UserInterfaceFunctions.ShowMessageBox('Error Changing Operation Mode', 'Please stop network scan before attempting to change operation mode.', 'Information')
        # else we continue changing operation mode
        else:
            # update the ui based on the users selection
            UserInterfaceFunctions.ToggleOperationMode(self)

            # change the value of operationMode in the database for the current user
            if self.sqlThread and self.userData.get('userId'):
                self.sqlThread.UpdateOperationMode(self.userData.get('userId'), self.userData.get('operationMode'))
            else:
                self.SendLogDict(f'Main_Thread: User has changed the operation mode preference to "{self.ui.operationModeComboBox.currentText()}".', 'INFO') #log change operation mode event


    # method for changing the current year in analytics page for showing detection information for given year
    def ChangeAnalyticsYear(self):
        # get current year chosen in combobox
        currentYear = self.ui.analyticsYearComboBox.currentText()

        # ensures that the we initialize the combobox year values only when year is set
        if currentYear:
            # send a log that the user has changed the analytics year selection
            self.SendLogDict(f'Main_Thread: {'User ' + self.userData.get('userName') if self.userData.get('userId') else 'User'} has changed the analytics year to "{currentYear}".', 'INFO')

            # update the histogram chart based on the selected year, first clear the current chart if it exists then create a new one
            if any(attackCount > 0 for attackCount in self.userData.get('analyticsChartData').get('barChartData').get(currentYear).values()):
                # reset both histogram chart and horizontal bar chart
                UserInterfaceFunctions.ResetHistogramChartToDefault(self, hideChart=False)
                UserInterfaceFunctions.ResetBarChartToDefault(self, hideChart=False)

                # initialize both histogram chart and bar chart based on the selected year
                UserInterfaceFunctions.CreateHistogramChartData(self, self.userData.get('analyticsChartData').get('histogramChartData', {}))
                UserInterfaceFunctions.CreateBarChartData(self, self.userData.get('analyticsChartData').get('barChartData', {}))
                UserInterfaceFunctions.SetDataIntoCards(self)
            else:
                # reset both histogram chart and horizontal bar chart and hide charts
                UserInterfaceFunctions.ResetHistogramChartToDefault(self)
                UserInterfaceFunctions.ResetBarChartToDefault(self)
                UserInterfaceFunctions.ResertDataInCards(self)


    # method for creating alerts report for user in desired format, txt or csv
    def DownloadReportButtonClicked(self):
        if not self.reportThread:
            # get system info and filtered alert list
            systemInfo = NetworkInformation.systemInfo if self.ui.machineInfoCheckBox.isChecked() else None
            alertList = UserInterfaceFunctions.GetFilteredAlerts(self)

            # if alertList is empty, we show message
            if not alertList:
                UserInterfaceFunctions.ShowMessageBox('No Detection History', 'There are no detected alerts available for report generation.', 'Information')
            # else we proceed
            else:
                # get desired path for report from file dialog
                filePath = self.GetPathFromFileDialog('Download Report', 'alerts_report.txt', 'Text Files (*.txt);;CSV Files (*.csv)')

                # if user chose a path we generate a report with our thread
                if filePath:
                    # toggle report interface to be shown
                    UserInterfaceFunctions.ToggleReportInterface(self, True)
                    # create report thread with our parameters and create report in specified format
                    self.reportThread = Report_Thread(self, filePath, alertList, systemInfo)
                    # connect relevant signals for report thread
                    self.reportThread.updateProgressBarSignal.connect(self.UpdateReportProgressBar)
                    self.reportThread.finishSignal.connect(self.CloseReportThread)
                    # start report thread
                    self.reportThread.start()
                    # log initialization of report thread
                    self.SendLogDict('Report_Thread: Starting report thread.', 'INFO') #log report start event


    # method for canceling report generation and stopping report thread
    def CancelReportButtonClicked(self):
        # check if report thread is active, if so we stop it
        if self.reportThread:
            self.reportThread.StopThread()

    #---------------------------------------------CLICKED-METHODS-END--------------------------------------------#

    #----------------------------------------------SQL-RESULT-SLOTS----------------------------------------------#

    # method for showing login result from sql thread and process user's data
    @Slot(dict)
    def LoginResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error loggin into user account due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error In Login', 'Error loggin into user account due to server error, please try again later.', 'Critical')
        # means failed loggin in, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.loginErrorMessageLabel, resultDict.get('message'))
        # means we successfully logged in
        elif resultDict.get('state') and resultDict.get('result'):
            self.ChangeUserState(True, resultDict.get('result')) #call our method to log into account


    # method for showing register result from sql thread and process user's data
    @Slot(dict)
    def RegisterResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error registering new user due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error In Register', 'Error registering new user due to server error, please try again later.', 'Critical')
        # means failed registering user, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.registerErrorMessageLabel, resultDict.get('message'))
        # means we successfully registered user, we process a login request to our sql thread to log into his new account
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: Registered new user with email {self.ui.registerUsernameLineEdit.text()}.', 'INFO') #log register event
            self.sqlThread.Login(self.ui.registerUsernameLineEdit.text(), NetSpect.ToSHA256(self.ui.registerPasswordLineEdit.text())) #call login method to login new user
            UserInterfaceFunctions.ShowMessageBox('Registration Successful', 'You have successfully registered. Logged into your account automatically.', 'Information')


    # method for showing send reset password code result from sql thread
    @Slot(dict)
    def SendCodeResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error sending reset password code due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Sending Code', 'Error sending reset password code due to server error, please try again later.', 'Critical')
            self.resetPasswordValidator.update({'resetCode': None, 'timestamp': None, 'newPassword': None}) #reset our resetPasswordValidator
        # means failed sending code, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.resetPasswordEmailErrorMessageLabel, resultDict.get('message'))
            self.resetPasswordValidator.update({'resetCode': None, 'timestamp': None, 'newPassword': None}) #reset our resetPasswordValidator
        # means we successfully sent reset password code
        elif resultDict.get('state'):
            # change to the reset password page
            self.SendLogDict(f'Main_Thread: Sent reset password code to user with email {self.ui.resetPasswordEmailLineEdit.text()} successfully.', 'INFO') #log send code event
            UserInterfaceFunctions.ToggleBetweenEmailAndCodeResetPassword(self, False)


    # method for showing results to the user after resetting password
    @Slot(dict)
    def VerifyCodeResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error changing password due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Changing Password', 'Error changing password due to server error, please try again later.', 'Critical')
        # means failed changing password, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.resetPasswordCodeErrorMessageLabel, resultDict.get('message'))
        # means we successfully changed password for user
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: Password for email {self.ui.resetPasswordEmailLineEdit.text()} successfully changed.', 'INFO') #log change password event
            UserInterfaceFunctions.AccountIconClicked(self)
            UserInterfaceFunctions.ShowMessageBox('Changed Password Successfully', f'Your new password is: {self.resetPasswordValidator.get('newPassword')}\nUse it to log in and change it if necessary.', 'Information', isSelectable=True)
            self.resetPasswordValidator.update({'resetCode': None, 'timestamp': None, 'newPassword': None}) #reset our resetPasswordValidator


    # method for showing delete account result from sql thread
    @Slot(dict)
    def DeleteAccountResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error deleting account due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Deleting Account', 'Error deleting account due to server error, please try again later.', 'Critical')
        # means failed deleting account, we show error message
        elif not resultDict.get('state'):
            self.SendLogDict('Main_Thread: Failed deleting account due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Failed Deleting Account', 'Failed deleting account due to server error, please try again later.', 'Critical')
        # means we successfully deleted account, we logout of previous user account
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')}\'s account has been deleted successfully.', 'INFO') #log delete user event
            self.LogoutButtonClicked() #call our method to log out of previous account
            UserInterfaceFunctions.ShowMessageBox('User Account Deletion Successful', 'Your account has been deleted successfully. Sorry to see you go.', 'Information')


    # method for showing add alert result from sql thread
    @Slot(dict)
    def AddAlertResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error adding alert due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Adding Alert', 'Error adding alert due to server error.', 'Critical')
        # means failed adding alert, we show error message
        elif not resultDict.get('state'):
            self.SendLogDict('Main_Thread: Failed adding alert due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Failed Adding Alert', 'Failed adding alert due to server error.', 'Critical')


    # method for showing delete alerts result from sql thread
    @Slot(dict)
    def DeleteAlertsResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error deleting alerts history due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Deleting Alerts', 'Error deleting alerts history due to server error, please try again later.', 'Critical')
        # means failed deleting alerts, we show error message
        elif not resultDict.get('state'):
            self.SendLogDict('Main_Thread: Failed deleting alerts history due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Failed Deleting Alerts', 'Failed deleting alerts history due to server error, please try again later.', 'Critical')
        # means we successfully deleted alerts
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')}\'s alerts history has been deleted successfully.', 'INFO') #log delete alerts event
            UserInterfaceFunctions.ShowMessageBox('Alerts Deletion Successful', 'Deleted all alerts history for previously detected attacks.', 'Information')


    # method for showing results to the user after adding a mac address to blacklist
    @Slot(dict)
    def AddMacToBlackListResult(self, resultDict):
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error adding an item to the blacklist due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Adding To Blacklist', 'Error adding an item to the blacklist due to server error, please try again later.', 'Critical')
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.macAddressBlacklistErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            newMacAddress = self.ui.macAddressLineEdit.text().lower() #convert characters to lower case for ease of use
            self.ui.macAddressListWidget.addItem(newMacAddress)
            self.ui.macAddressLineEdit.clear()
            self.userData.setdefault('blackList', []).append(newMacAddress)
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has added a new mac address to mac blacklist successfully.', 'INFO') #log add mac event


    # method for showing results to the user after removing a mac address from blacklist 
    @Slot(dict)
    def DeleteMacFromBlackListResult(self, resultDict):
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error removing an item from the blacklist due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Removing From Blacklist', 'Error removing an item from the blacklist due to server error, please try again later.', 'Critical')
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.macAddressBlacklistErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.ui.macAddressListWidget.takeItem(self.ui.macAddressListWidget.row(self.seletecItemForDelete))
            self.userData.setdefault('blackList', []).remove(self.seletecItemForDelete.text())
            self.seletecItemForDelete = None
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has removed mac address from mac blacklist successfully.', 'INFO') #log remove mac event


    # method for showing results to the user after changing email
    @Slot(dict)
    def SaveEmailResult(self, resultDict):
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error saving email due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Saving Email', 'Error saving email due to server error, please try again later.', 'Critical')
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.saveEmailErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has changed email successfully.', 'INFO') #log change email event
            self.ui.saveEmailErrorMessageLabel.clear()
            self.userData['email'] = self.ui.emailLineEdit.text()
            UserInterfaceFunctions.ShowMessageBox('Email Changed Successfullly', 'Your email has changed successfully.', 'Information')


    # method for showing results to the user after changing username
    @Slot(dict)
    def SaveUsernameResult(self, resultDict):
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error saving username due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Saving Username', 'Error saving username due to server error, please try again later.', 'Critical')
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.saveUsernameErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has changed username to {self.ui.usernameLineEdit.text()} successfully.', 'INFO') #log change username event
            self.ui.saveUsernameErrorMessageLabel.clear()
            self.userData['userName'] = self.ui.usernameLineEdit.text()
            self.ui.welcomeLabel.setText(f'Welcome {self.ui.usernameLineEdit.text()}')
            UserInterfaceFunctions.ShowMessageBox('Username Changed Successfullly', 'Your username has changed successfully.', 'Information')


    # method for showing results to the user after changing password
    @Slot(dict)
    def SavePasswordResult(self, resultDict):
        if resultDict.get('error'):
            self.SendLogDict('Main_Thread: Error saving password due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Saving Password', 'Error saving password due to server error, please try again later.', 'Critical')
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.ui.savePasswordErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has changed password successfully.', 'INFO') #log change password event
            # clear the password input fields
            self.ui.savePasswordErrorMessageLabel.clear()
            self.ui.currentPasswordLineEdit.clear()
            self.ui.newPasswordLineEdit.clear()
            self.ui.confirmPasswordLineEdit.clear()

            # for each password input field we want to and reset the border to light gray
            self.ui.currentPasswordLineEdit.setStyleSheet(UserInterfaceFunctions.GetDefaultStyleSheetSettingsLineEdits(self, 'currentPasswordLineEdit'))
            self.ui.newPasswordLineEdit.setStyleSheet(UserInterfaceFunctions.GetDefaultStyleSheetSettingsLineEdits(self, 'newPasswordLineEdit'))
            self.ui.confirmPasswordLineEdit.setStyleSheet(UserInterfaceFunctions.GetDefaultStyleSheetSettingsLineEdits(self, 'confirmPasswordLineEdit'))
            UserInterfaceFunctions.ShowMessageBox('Password Changed Successfullly', 'Your password has changed successfully.', 'Information')


    # method for showing results for update color mode after changing UI color
    @Slot(dict)
    def UpdateColorModeResult(self, resultDict):
        if resultDict.get('error'):
            self.SendLogDict(f'Main_Thread: Error saving color preference due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Saving Color Preference', 'Error saving color preference due to server error, please try again later.', 'Critical')
        elif not resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: Error Updating Color Preference. {resultDict.get('message')}', 'ERROR') #log change color mode event
            UserInterfaceFunctions.ShowMessageBox('Error Updating Color Preference', resultDict.get('message'))
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has changed the UI color preference to "{self.ui.colorModeComboBox.currentText()}".', 'INFO') #log change color mode event
    

    # method for showing results for update operation mode after changing operation mode in GUI
    @Slot(dict)
    def UpdateOperationModeResult(self, resultDict):
        if resultDict.get('error'):
            self.SendLogDict(f'Main_Thread: Error saving operation mode preference due to server error.', 'ERROR') #log error event
            UserInterfaceFunctions.ShowMessageBox('Error Saving Operation Mode Preference', 'Error saving coperation mode preference due to server error, please try again later.', 'Critical')
        elif not resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: Error Updating Operation Mode Preference. {resultDict.get('message')}', 'ERROR') #log change operation mode event
            UserInterfaceFunctions.ShowMessageBox('Error Updating Operation Mode Preference', resultDict.get('message'))
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has changed the operation mode preference to "{self.ui.operationModeComboBox.currentText()}".', 'INFO') #log change operation mode event

    #--------------------------------------------SQL-RESULT-SLOTS-END--------------------------------------------#

#------------------------------------------------------NetSpect-CLASS-END-------------------------------------------------------#

#-------------------------------------------------------SNIFFING-THREAD---------------------------------------------------------#
# thread for sniffing packets in real time for gathering network flows
class Sniffing_Thread(QThread):
    captureDictionary = None #represents the dictionary with packet types and their init methods

    # define signals for interacting with main gui thread
    updateTimerSignal = Signal(bool)
    updateArpListSignal = Signal(ARP_Packet)
    updatePortScanDosDictSignal = Signal(tuple, Default_Packet)
    updateDnsDictSignal = Signal(tuple, DNS_Packet)
    finishSignal = Signal(dict)

    # constructor of sniffing thread
    def __init__(self, parent=None, selectedInterface=None):
        super().__init__(parent)
        self.parent = parent #represents the main thread
        # initalize capture dictionary with packet types and their init methods
        self.captureDictionary = {TCP: self.InitTCP, UDP: self.InitUDP, DNS: self.InitDNS, ARP: self.InitARP}
        self.interface = selectedInterface #initialize the interface with selectedInterface
        self.sniffer = None #represents our sniffer scapy object for sniffing packets
        self.stopFlag = False #represents stop flag for indicating when to stop the sniffer


    # method for stopping sniffer thread
    @Slot()
    def StopThread(self):
        try:
            self.stopFlag = True #set stop flag
            # we check if sniffer is still running, if so we stop it
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop() #stop async sniffer
        except Exception as e:
            # emit finish signal to GUI with failed status due to permission errors
            self.finishSignal.emit({'state': False, 'message': 'Permission denied. Please run again with administrative privileges.'})
        finally:
            self.quit() #exit main loop and end task
            self.wait() #we wait to ensure thread cleanup


    # method for checking when to stop sniffing packets, stop condition
    def StopScan(self, packet):
        return self.stopFlag #return state of stop flag


    # method for capturing specific packets for later analysis
    def PacketCapture(self, packet):
        # iterate over capture dictionary and find coresponding InitPacket method for each packet
        for packetType, InitPacket in self.captureDictionary.items():
            if packet.haslayer(packetType): #if we found matching packet we call its InitPacket method
                InitPacket(packet) #call InitPacket method of each packet


    # run method for initialing a packet scan on desired network interface
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            # emit signal to start timer to determin when to initiate each attack defence
            self.updateTimerSignal.emit(True)

            # create scapy AsyncSniffer object with desired interface and sniff network packets asynchronously
            self.sniffer = AsyncSniffer(iface=self.interface, prn=self.PacketCapture, stop_filter=self.StopScan, store=False)
            self.sniffer.start() #start our async sniffing
            self.exec() #execute sniffer process
        except PermissionError: #if user didn't run with administrative privileges
            stateDict.update({'state': False, 'message': 'Permission denied. Please run again with administrative privileges.'})
        except Exception as e: #we catch an exception if something happend while sniffing
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
        finally:
            self.updateTimerSignal.emit(False) #emit signal to stop timer for defance
            self.finishSignal.emit(stateDict) #emit finish signal to main thread


    #------------------------------------------INIT-PACKET-METHODS-----------------------------------------------#

    # method that initialize TCP packets
    def InitTCP(self, packet):
        TCP_Object = TCP_Packet(packet) #create a new object for packet
        flowTuple = TCP_Object.GetFlowTuple() #get flow representation of packet
        self.updatePortScanDosDictSignal.emit(flowTuple, TCP_Object) #emit signal to update our portScanDosDict


    # method that initialize UDP packets
    def InitUDP(self, packet):
        UDP_Object = UDP_Packet(packet) #create a new object for packet
        flowTuple = UDP_Object.GetFlowTuple() #get flow representation of packet
        self.updatePortScanDosDictSignal.emit(flowTuple, UDP_Object) #emit signal to update our portScanDosDict


    # method that initialize DNS packets
    def InitDNS(self, packet):
        DNS_Object = DNS_Packet(packet) #create a new object for packet
        flowTuple = DNS_Object.GetFlowTuple() #get flow representation of packet
        self.updateDnsDictSignal.emit(flowTuple, DNS_Object) #emit signal to update our dnsDict
    
    # method that initialize ARP packets
    def InitARP(self, packet):
        ARP_Object = ARP_Packet(packet) #create a new object for packet
        self.updateArpListSignal.emit(ARP_Object) #emit signal to update our arpList

    #-----------------------------------------INIT-PACKET-METHODS-END--------------------------------------------#

#-----------------------------------------------------SNIFFING-THREAD-END-------------------------------------------------------#

#---------------------------------------------------------ARP-THREAD------------------------------------------------------------#
# thread for analyzing arp traffic and detecting arp spoofing attacks
class Arp_Thread(QThread):
    # define signals for interacting with main gui thread
    detectionResultSignal = Signal(dict)
    finishSignal = Signal(dict)

    # constructor of arp thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for indicating when we should end analysis
        self.arpBatch = None #represents arp list batch of packets for us to analyzie for anomalies
        self.mutex = QMutex() #shared mutex for thread safe operations with wait condition
        self.waitCondition = QWaitCondition() #wait condition for thread to wait for received packet batch from main thread
    

    # method for receiving arp batch from main thread
    @Slot(dict)
    def ReceiveArpBatch(self, arpList):
        with QMutexLocker(self.mutex):
            self.arpBatch = arpList #set our arp list batch received from main thread
            self.waitCondition.wakeAll() #wake thread and process arp batch


    # method for stopping arp thread
    @Slot()
    def StopThread(self):
        self.stopFlag = True #set stop flag
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating arp traffic analysis and detecting arp spoofing
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            # initialize all of our static arp tables and check for arp spoofing presence
            result = ArpSpoofing.InitAllArpTables() #call our function to initialize arp tables
            self.detectionResultSignal.emit(result) #send result of arp initialization to main thread

            # process arp packets until stop condition received
            while not self.stopFlag:
                # wait until we receive the arp batch using wait condition
                self.mutex.lock()
                while not self.arpBatch and not self.stopFlag:
                    self.waitCondition.wait(self.mutex)

                # if true we exit and finish threads work
                if self.stopFlag:
                    self.mutex.unlock()
                    break

                # retrieve the arp list batch and reset for next iteration
                localArpList = self.arpBatch
                self.arpBatch = None
                self.mutex.unlock()

                # process the received arp list batch
                result = ArpSpoofing.ProcessARP(localArpList) #call our function for cheching arp traffic
                self.detectionResultSignal.emit(result) #send result of scan to main thread

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
        finally:
            self.finishSignal.emit(stateDict) #send finish signal to main thread

#--------------------------------------------------------ARP-THREAD-END---------------------------------------------------------#

#------------------------------------------------------PortScanDos-THREAD-------------------------------------------------------#
# thread for analyzing tcp and udp traffic and detecting port scanning and dos attacks
class PortScanDos_Thread(QThread):
    # define signals for interacting with main gui thread
    detectionResultSignal = Signal(dict)
    finishSignal = Signal(dict)

    # constructor of portScanDos thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for indicating when we should end analysis
        self.portScanDosBatch = None #represents portScanDos dict batch of packets for us to analyzie for anomalies
        self.mutex = QMutex() #shared mutex for thread safe operations with wait condition
        self.waitCondition = QWaitCondition() #wait condition for thread to wait for received packet batch from main thread
    

    # method for receiving portScanDos batch from main thread
    @Slot(dict)
    def ReceivePortScanDosBatch(self, portScanDosDict):
        with QMutexLocker(self.mutex):
            self.portScanDosBatch = portScanDosDict #set our portScanDos dict batch received from main thread
            self.waitCondition.wakeAll() #wake thread and process portScanDos batch


    # method for stopping portScanDos thread
    @Slot()
    def StopThread(self):
        self.stopFlag = True #set stop flag
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating tcp and udp traffic analysis and detecting port scan and dos attacks
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            # process tcp and udp packets until stop condition received
            while not self.stopFlag:
                # wait until we receive the portScanDos batch using wait condition
                self.mutex.lock()
                while not self.portScanDosBatch and not self.stopFlag:
                    self.waitCondition.wait(self.mutex)

                # if true we exit and finish threads work
                if self.stopFlag:
                    self.mutex.unlock()
                    break

                # retrieve the portScanDos dict batch and reset for next iteration
                localPortScanDosDict = self.portScanDosBatch
                self.portScanDosBatch = None
                self.mutex.unlock()

                # process the received portScanDos dict batch
                flowDict = PortScanDoS.ProcessFlows(localPortScanDosDict) #call our function for getting flows dict
                result = PortScanDoS.PredictPortDoS(flowDict) #call predict and send flows to classifier
                self.detectionResultSignal.emit(result) #send result of scan to main thread

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
        finally:
            self.finishSignal.emit(stateDict) #send finish signal to main thread

#-----------------------------------------------------PortScanDos-THREAD-END----------------------------------------------------#

#----------------------------------------------------------DNS-THREAD-----------------------------------------------------------#
# thread for analyzing dns traffic and detecting dns tunneling attacks
class Dns_Thread(QThread):
    # define signals for interacting with main gui thread
    detectionResultSignal = Signal(dict)
    finishSignal = Signal(dict)

    # constructor of dns thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for indicating when we should end analysis
        self.dnsBatch = None #represents dns dict batch of packets for us to analyzie for anomalies
        self.mutex = QMutex() #shared mutex for thread safe operations with wait condition
        self.waitCondition = QWaitCondition() #wait condition for thread to wait for received packet batch from main thread
    

    # method for receiving dns batch from main thread
    @Slot(dict)
    def ReceiveDnsBatch(self, dnsDict):
        with QMutexLocker(self.mutex):
            self.dnsBatch = dnsDict #set our dns dict batch received from main thread
            self.waitCondition.wakeAll() #wake thread and process dns batch


    # method for stopping dns thread
    @Slot()
    def StopThread(self):
        self.stopFlag = True #set stop flag
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating dns traffic analysis and detecting dns tunneling attacks
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            # process dns packets until stop condition received
            while not self.stopFlag:
                # wait until we receive the dns batch using wait condition
                self.mutex.lock()
                while not self.dnsBatch and not self.stopFlag:
                    self.waitCondition.wait(self.mutex)

                # if true we exit and finish threads work
                if self.stopFlag:
                    self.mutex.unlock()
                    break

                # retrieve the dns dict batch and reset for next iteration
                localDnsDict = self.dnsBatch
                self.dnsBatch = None
                self.mutex.unlock()

                # process the received dns dict batch
                flowDict = DNSTunneling.ProcessFlows(localDnsDict) #call our function for getting flows dict
                result = DNSTunneling.PredictDNS(flowDict) #call predict and send flows to classifier
                self.detectionResultSignal.emit(result) #send result of scan to main thread

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
        finally:
            self.finishSignal.emit(stateDict) #send finish signal to main thread

#--------------------------------------------------------DNS-THREAD-END---------------------------------------------------------#

#--------------------------------------------------------REPORT-THREAD----------------------------------------------------------#
# thread for creating alert report for user, in txt format or csv format
class Report_Thread(QThread):
    # represents our system info and table headers
    systemInfoHeaders = {'osType': 'OS Type:', 'osVersion': 'OS Version:', 
                         'architecture': 'Architecture:', 'hostName': 'Host Name:'}
    
    tableHeaders = ['Interface', 'Attack Type', 'Source IP', 'Source MAC', 'Destination IP',
                     'Destination MAC', 'Protocol', 'OS Type', 'Timestamp']
    
    # represents our system info and table formats
    systemInfoFormat = '{:<15} {:<50}\n'
    
    tableFormat = '{:<13} {:<15} {:<40} {:<20} {:<40} {:<20} {:<10} {:<13} {}\n'

    # define signals for interacting with main gui thread
    updateProgressBarSignal = Signal(int)
    finishSignal = Signal(dict, bool)

    # constructor of report thread
    def __init__(self, parent=None, filePath=None, alertList=None, systemInfo=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for canceling process
        self.isClosing = False #represents close flag for popup messages
        self.filePath = filePath #represents file path
        self.alertList = alertList #represents alerts list
        self.systemInfo = systemInfo #represents system info dict
        self.progressStep = 100 / len(self.alertList) if self.alertList else 100 #represents progress step

    
    # method for stopping dns thread
    @Slot()
    def StopThread(self, isClosing=False):
        self.stopFlag = True #set stop flag
        self.isClosing = isClosing #set close flag


    # run method for creating alerts report for user
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            # if file ends with .txt we create a txt report
            if self.filePath.endswith('.txt'):
                self.GenerateTxtReport()
            # if file ends with .csv we create a csv report
            elif self.filePath.endswith('.csv'):
                self.GenerateCsvReport()
            # else we received unsupported file format
            else:
                stateDict.update({'state': False, 'message': 'Failed creating report, file format not supported.'})
            
            # check if stop flag set, if so we update message
            if self.stopFlag:
                stateDict.update({'state': True, 'message': 'Canceled report generation successfully.'})

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
        finally:
            # we check if failed and file was partially written, if so delete it
            if not stateDict.get('state') and os.path.exists(self.filePath):
                os.remove(self.filePath) #remove our file
            self.finishSignal.emit(stateDict, self.isClosing) #send finish signal to main thread


    # method for writing detection report into a text file
    def GenerateTxtReport(self):
        # open file for writing in desired path
        with open(self.filePath, 'w', encoding='utf-8') as file:
            # if system info given we write system info into txt file
            if self.systemInfo:
                # write system info header
                file.write('System Information:\n')
                file.write('=' * 40 + '\n')
                
                # write system info with predefined headers
                for key, value in self.systemInfo.items():
                    file.write(self.systemInfoFormat.format(self.systemInfoHeaders[key], value))
            
            # if alert list given we write our detection history into txt file
            if self.alertList:
                # write detection history header
                file.write('\nDetection History:\n')
                file.write('=' * 40 + '\n\n')

                # write table headers
                file.write(self.tableFormat.format(*self.tableHeaders))
                file.write('=' * 196 + '\n')
                
                # iterate over alert list and add each alert into txt file
                for i, alert in enumerate(self.alertList, start=1):
                    # check stop flag before writing
                    if self.stopFlag:
                        return
                    
                    # write line into file and emit a signal to update progress bar
                    file.write(self.tableFormat.format(*alert.values()))
                    self.updateProgressBarSignal.emit(int(i * self.progressStep))


    # method for writing detection report into a csv file
    def GenerateCsvReport(self):
        # open file for writing in desired path
        with open(self.filePath, 'w', newline='', encoding='utf-8') as file:
            # create writer for csv
            writer = csv.writer(file)

            # if system info given we write system info into csv file
            if self.systemInfo:
                # write system info header
                writer.writerow(['System Information'])  

                # write a blank row to separate system info header from info
                writer.writerow([])

                # write system info with predefined headers
                for key, value in self.systemInfo.items():
                    writer.writerow([self.systemInfoHeaders[key], value])

                # write a blank row to separate system info from alerts
                writer.writerow([])

            # if alert list given we write our detection history into csv file
            if self.alertList:
                # write detection history header
                writer.writerow(['Detection History'])

                # write a blank row to separate header from alerts
                writer.writerow([])

                # write table headers
                writer.writerow(self.tableHeaders)

                # iterate over alert list and add each alert into csv file
                for i, alert in enumerate(self.alertList, start=1):
                     # check stop flag before writing
                    if self.stopFlag:
                        return
                    
                    # write line into file and emit a signal to update progress bar
                    writer.writerow(alert.values())
                    self.updateProgressBarSignal.emit(int(i * self.progressStep))

#------------------------------------------------------REPORT-THREAD-END--------------------------------------------------------#

#-------------------------------------------------------LOGGER-THREAD-----------------------------------------------------------#
# thread for logging alerts and application events into a log file
class Logger_Thread(QThread):
    # define signals for interacting with main gui thread
    finishSignal = Signal(dict)

    # constructor of logger thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for indicating when we should end logger
        self.logFile = None #represents log file for writing logs
        self.logFilePath = currentDir.parent / 'logs' / 'NetSpect.log' #represents log file path
        self.logQueue = [] #represents log queue for received logs for writing into log file
        self.mutex = QMutex() #shared mutex for thread safe operations with wait condition
        self.waitCondition = QWaitCondition() #wait condition for thread to wait for received log from main thread
    

    # method for receiving log from main thread
    @Slot(dict)
    def ReceiveLog(self, logDict):
        with QMutexLocker(self.mutex):
            self.logQueue.append(logDict) #append log into log queue
            self.waitCondition.wakeAll() #wake thread and process dns batch


    # method for stopping logger thread
    @Slot()
    def StopThread(self):
        self.stopFlag = True #set stop flag
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating logger process and write given logs into log file
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            # open log file in append mode
            self.logFile = open(self.logFilePath, 'a')

            # process logs until stop condition received
            while not self.stopFlag:
                # wait until we receive log using wait condition
                self.mutex.lock()
                while not self.logQueue and not self.stopFlag:
                    self.waitCondition.wait(self.mutex)

                # if true we exit and finish threads work
                if not self.logQueue and self.stopFlag:
                    self.mutex.unlock()
                    break
                
                # pop log dict and process it
                logDict = self.logQueue.pop(0)
                self.mutex.unlock()

                # write log entry into log file
                self.WriteLog(logDict)

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
            logDict = {'timestamp': NetworkInformation.GetCurrentTimestamp(), 'level': 'ERROR', 'message': f'Logger_Thread: {stateDict.get('message')}'}
            self.WriteLog(logDict)
        finally:
            self.finishSignal.emit(stateDict) #send finish signal to main thread
            # write exit message to log file and close it
            if self.logFile:
                logDict = {'timestamp': NetworkInformation.GetCurrentTimestamp(), 'level': 'INFO', 'message': 'Logger_Thread: Finsihed processing logs.'}
                self.WriteLog(logDict)
                logDict.update({'message': 'Main_Thread: Closed Application.'})
                self.WriteLog(logDict)
                self.logFile.close()


    # method to write log entry into log file and also print it into console
    def WriteLog(self, logDict):
        # we check if log file is closed or deleted, if so reopen it
        if not self.logFile or not Path(self.logFilePath).exists():
            self.logFile = open(self.logFilePath, 'a')
        
        # check if logFile is open and write log into file
        if self.logFile:
            logLine = f'{logDict.get('timestamp')} [{logDict.get('level')}] {logDict.get('message')}\n'
            self.logFile.write(logLine)
            self.logFile.flush()
            print(logLine, end='')

#------------------------------------------------------LOGGER-THREAD-END--------------------------------------------------------#

#-----------------------------------------------------DATA-COLLECTOR-THREAD-----------------------------------------------------#
# thread for collecting benign traffic for port scan, dos and dns tunneling
class Data_Collector_Thread(QThread):
    # define signals for interacting with main gui thread
    collectionResultSignal = Signal(int)
    finishSignal = Signal(dict)

    # constructor of data collector thread
    def __init__(self, parent=None, filePath='port_scan_dos_benign_dataset.csv', selectedData='PortScanDos'):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for indicating when we should end analysis
        self.packetBatch = None #represents packet dict batch of adding it to our dataset
        self.filePath = filePath #represents file path of benign dataset
        self.selectedData = selectedData #represents selected data to gather can be PortScanDos or DNSTunneling
        self.mutex = QMutex() #shared mutex for thread safe operations with wait condition
        self.waitCondition = QWaitCondition() #wait condition for thread to wait for received packet batch from main thread
    

    # method for receiving packet batch from main thread
    @Slot(dict)
    def ReceivePacketBatch(self, packetDict):
        with QMutexLocker(self.mutex):
            self.packetBatch = packetDict #set our packet dict batch received from main thread
            self.waitCondition.wakeAll() #wake thread and process packet batch


    # method for stopping data collector thread
    @Slot()
    def StopThread(self):
        self.stopFlag = True #set stop flag
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for gathering begnin traffic data for various attacks
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            # process packets until stop condition received
            while not self.stopFlag:
                # start the dns process for generating dns data
                # import subprocess, gc
                # dnsProcess = subprocess.Popen(['python', currentDir.parent / 'utility' / 'generateDNS.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # wait until we receive the packet batch using wait condition
                self.mutex.lock()
                while not self.packetBatch and not self.stopFlag:
                    self.waitCondition.wait(self.mutex)

                # if true we exit and finish threads work
                if self.stopFlag:
                    self.mutex.unlock()
                    break

                # retrieve the packet dict batch and reset for next iteration
                localPacketDict = self.packetBatch
                self.packetBatch = None
                self.mutex.unlock()

                # means we process TCP/UDP flows and save them for portScanDos dataset
                if self.selectedData == 'PortScanDos':
                    portScanDosFlows = PortScanDoS.ProcessFlows(localPacketDict) #call our port scan dos process flows
                    collectedRows = SaveData.SaveCollectedData(portScanDosFlows, self.filePath, PortScanDoS.selectedColumns) #save TCP/UDP flows in CSV format
                    self.collectionResultSignal.emit(collectedRows) #emit number of rows added to main thread
                # else we process DNS flows and save them for DNS Tunneling dataset
                elif self.selectedData == 'DNSTunneling':
                    dnsFlows = DNSTunneling.ProcessFlows(localPacketDict) #call our dns tunneling process flows
                    collectedRows = SaveData.SaveCollectedData(dnsFlows, self.filePath, DNSTunneling.selectedColumns) #save DNS flows in CSV format
                    self.collectionResultSignal.emit(collectedRows) #emit number of rows added to main thread

                # check if dns process still running
                # if not dnsProcess.poll():
                #     dnsProcess.terminate() #stop our dns process
                #     dnsProcess.wait() #wait for process to finish
                # gc.collect() #call garbage collector for cleaning memory

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
        finally:
            self.finishSignal.emit(stateDict) #send finish signal to main thread

#----------------------------------------------------DATA-COLLECTOR-THREAD-END--------------------------------------------------#

#------------------------------------------------------------MAIN---------------------------------------------------------------#

if __name__ == '__main__':
    #start NetSpect application
    app = QApplication(sys.argv)
    netSpect = NetSpect()
    try:
        sys.exit(app.exec())
    except:
        print('Exiting')

#----------------------------------------------------------MAIN-END-------------------------------------------------------------#