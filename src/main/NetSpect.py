import UserInterfaceFunctions
from PyQt5.QtCore import QTimer, QRegExp, QThread, QMutex, QMutexLocker, QWaitCondition, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import QApplication, QDesktopWidget, QMainWindow, QTableWidgetItem, QFileDialog
from PyQt5.uic import loadUi
from hashlib import sha256
from MainFunctions import *
from SQLHelper import *

#--------------------------------------------------------NetSpect-CLASS---------------------------------------------------------#
# class that represents main app of NetSpect
class NetSpect(QMainWindow):
    userData = {'userId': None, 'email': None, 'userName': None, 'numberOfDetections': 0, 'lightMode': 0, 'alertList': [], 'pieChartData': {}, 'blackList': []} #represents user data in interface
    isDetection = False #represents flag for indicating if detection is active
    usernameValidator, passwordValidator, finalPasswordPattern, emailValidator = None, None, None, None #represents the validators that hold regexes for various input fields in the program
    totalTimer, arpTimer, portScanDosTimer, dnsTimer = None, None, None, None #represents timer for each thread for evaluating when to send data
    totalTimeout, arpTimeout, portScanDosTimout, dnsTimout = 1000, 40000, 40000, 40000 #represents timeout for each timer
    arpThreshold, portScanDosThreshold, dnsThreshold = 20, 10000, 350 #represents thresholds for each thread
    repeatedAttackTimeout = 2 #represents timeout for repeated attacks, we alert again for attacks from same source after few minutes
    timeElapsed = timedelta() #initialize a timedelta object to track elapsed time
    arpList = [] #represents list of packets related to arp spoofing
    portScanDosDict = {} #represents dict of {(flow tuple) - [packet list]} related to port scanning and dos
    dnsDict = {} #represents dict of {(flow tuple) - [packet list]} related to dns tunneling
    arpCounter, tcpUdpCounter, dnsCounter = 0, 0, 0 #represents counters for our packet data structures for arp, portDos and dns
    sqlThread, snifferThread, arpThread, portScanDosThread, dnsThread = None, None, None, None, None #represents our worker threads for SQL queries, sniffing and detecting network cyber attacks
    reportThread, loggerThread = None, None #represents our report thread for creating report and logger thread for logging app events into logging file
    arpMutex, portScanDosMutex, dnsMutex = QMutex(), QMutex(), QMutex() #represents mutex objects for thread safe operations on our dictionaries
    arpAttackDict, portScanDosAttackDict, dnsAttackDict = {'ipToMac': {}, 'macToIp': {}}, {}, {} #represents attack dictionaries for each attack we previously detected

    # constructor of main gui application
    def __init__(self):
        super(NetSpect, self).__init__()
        uiFile = currentDir.parent / 'interface' / 'NetSpect.ui'
        loadUi(uiFile, self) #load the ui file
        self.initUI() #call init method
        
    
    # method to initialize GUI methods and events
    def initUI(self):
        self.setWindowTitle('NetSpect') #set title of window
        # connect timers for detection
        self.totalTimer, self.arpTimer, self.portScanDosTimer, self.dnsTimer = QTimer(self), QTimer(self), QTimer(self), QTimer(self) #initailize our timers
        self.totalTimer.timeout.connect(self.UpdateRunningTimeCounterLabel) #connect timeout event for total timer
        self.arpTimer.timeout.connect(self.SendArpList) #connect timeout event for arp timer
        self.portScanDosTimer.timeout.connect(self.SendPortScanDosDict) #connect timeout event for portScanDos timer
        self.dnsTimer.timeout.connect(self.SendDnsDict) #connect timeout event for dns timer

        # connect interface buttons to their methods
        self.startStopButton.clicked.connect(self.StartStopButtonClicked)
        self.loginPushButton.clicked.connect(self.LoginButtonClicked)
        self.registerPushButton.clicked.connect(self.RegisterButtonClicked)
        self.deleteAccoutPushButton.clicked.connect(self.DeleteAccoutButtonClicked)
        self.clearHistoryPushButton.clicked.connect(self.DeleteAlertsButtonClicked)
        self.addMacAddressPushButton.clicked.connect(self.AddMacAddressButtonClicked)
        self.emailPushButton.clicked.connect(self.SaveEmailButtonClicked)
        self.usernamePushButton.clicked.connect(self.SaveUsernameButtonClicked)
        self.passwordPushButton.clicked.connect(self.SavePasswordButtonClicked)
        self.downloadReportPushButton.clicked.connect(self.DownloadReportButtonClicked)
        self.cancelReportPushButton.clicked.connect(self.CancelReportButtonClicked)

        # connect interface labels to their methods
        self.accountIcon.mousePressEvent = lambda event: UserInterfaceFunctions.AccountIconClicked(self)
        self.moveToRegisterLabel.mousePressEvent = lambda event: UserInterfaceFunctions.SwitchBetweenLoginAndRegister(self)
        self.moveToLoginLabel.mousePressEvent = lambda event: UserInterfaceFunctions.SwitchBetweenLoginAndRegister(self, False)
        self.menuIcon.mousePressEvent = lambda event: UserInterfaceFunctions.OpenSideFrame(self)
        self.closeMenuIcon.mousePressEvent = lambda event: UserInterfaceFunctions.CloseSideFrame(self)
        self.homePageIconHorizontalFrame.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 0) #switch to Home Page
        self.reportIconHorizontalFrame.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 1) #switch to Report Page
        self.infoIconHorizontalFrame.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 2) #switch to Information Page
        self.settingsIcon.mousePressEvent = lambda event: UserInterfaceFunctions.ChangePageIndex(self, 3) #switch to Settings Page
        self.logoutIcon.mousePressEvent = lambda event: self.LogoutButtonClicked() #log out of user's account and clear interface

        # connect comboboxes and checkboxes to their methods
        self.arpSpoofingCheckBox.stateChanged.connect(lambda: UserInterfaceFunctions.ReportCheckboxToggled(self))
        self.portScanningCheckBox.stateChanged.connect(lambda: UserInterfaceFunctions.ReportCheckboxToggled(self))
        self.denialOfServiceCheckBox.stateChanged.connect(lambda: UserInterfaceFunctions.ReportCheckboxToggled(self))
        self.dnsTunnelingCheckBox.stateChanged.connect(lambda: UserInterfaceFunctions.ReportCheckboxToggled(self))
        self.reportDurationComboBox.currentIndexChanged.connect(lambda: UserInterfaceFunctions.ReportDurationComboboxChanged(self))
        self.networkInterfaceComboBox.clear() #clear interfaces combobox
        self.networkInterfaceComboBox.addItems(NetworkInformation.InitNetworkInfo()) #intialize our interfaces combobox with host network info
        self.networkInterfaceComboBox.currentIndexChanged.connect(self.ChangeNetworkInterface) #connect interfaces combobox to its method
        self.ChangeNetworkInterface() #set default network interface from combobox

        # initialize other interface components and show interface
        UserInterfaceFunctions.InitAnimationsUI(self) # setup left sidebar elements and login/register popup frame
        self.InitSystemInfo(NetworkInformation.GetSystemInformation()) #initialize the system information in the info page (machine name, version, etc.)
        self.InitValidators() #initialize the network information in the info page (interface name, mac address, ips, etc.)
        self.UpdateNumberOfDetectionsCounterLabel(0) #reset number of detections counter label
        self.ChangeLoginRegisterErrorMessage() #reset the login popup error message
        self.ChangeLoginRegisterErrorMessage(isLogin=False) #reset the register popup error message
        self.InitLoggerThread() #call init method for logger thread
        self.InitSQLThread() #call init method for sql thread
        self.center() #make the app open in center of screen
        self.show() #show the application


    # method for making the app open in the center of screen
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
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
        self.sqlThread.deleteAccountResultSignal.connect(self.DeleteAccountResult)
        self.sqlThread.addAlertResultSignal.connect(self.AddAlertResult)
        self.sqlThread.deleteAlertsResultSignal.connect(self.DeleteAlertsResult)
        self.sqlThread.addBlacklistMacResultSignal.connect(self.AddMacToBlackListResult)
        self.sqlThread.deleteBlacklistMacResultSignal.connect(self.DeleteMacFromBlackListResult)
        self.sqlThread.connectionResultSignal.connect(self.ConnectionResult)
        self.sqlThread.finishSignal.connect(self.CloseSQLThread)
        # start sql thread
        self.sqlThread.start()
        # log initializing sql thread
        self.SendLogDict('SQL_Thread: Starting SQL thread.', 'INFO')
    

    # method for setting input validators on line edits in gui
    def InitValidators(self):
        # create regex expressions and validators
        self.usernameValidator = QRegExpValidator(QRegExp('^[A-Za-z0-9]{4,16}$'))
        self.passwordValidator = QRegExpValidator(QRegExp('[A-Za-z\\d$&?@#|.^*()%!]{6,20}')) 
        self.finalPasswordValidator = QRegExpValidator(QRegExp('^(?=.*[A-Z])(?=.*\\d)[A-Za-z\\d$&?@#|.^*()%!]{6,20}$'))
        self.emailValidator = QRegExpValidator(QRegExp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'))

        # set validaotrs for username, password and email line edits in the register popup and settings page
        self.registerEmailLineEdit.setValidator(self.emailValidator)
        self.registerUsernameLineEdit.setValidator(self.usernameValidator)
        self.registerPasswordLineEdit.setValidator(self.passwordValidator)
        self.emailLineEdit.setValidator(self.emailValidator)
        self.usernameLineEdit.setValidator(self.usernameValidator)
        self.oldPasswordLineEdit.setValidator(self.passwordValidator)
        self.newPasswordLineEdit.setValidator(self.passwordValidator)
        self.confirmPasswordLineEdit.setValidator(self.passwordValidator)
    
        # connect the textChanged signal to the function that checks validation, this adds borders to the line edits if the text does not match the regex
        self.loginUsernameLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.ClearErrorMessageText(self.loginErrorMessageLabel))
        self.loginPasswordLineEdit.textChanged.connect(lambda : UserInterfaceFunctions.ClearErrorMessageText(self.loginErrorMessageLabel))
        self.registerEmailLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEdit(self.registerEmailLineEdit, 'registerEmailLineEdit', self.registerErrorMessageLabel))
        self.registerUsernameLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEdit(self.registerUsernameLineEdit, 'registerUsernameLineEdit', self.registerErrorMessageLabel))
        self.registerPasswordLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEdit(self.registerPasswordLineEdit, 'registerPasswordLineEdit', self.registerErrorMessageLabel))
        self.emailLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEditSettings(self.emailLineEdit, 'emailLineEdit', self.saveEmailErrorMessageLabel))
        self.usernameLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEditSettings(self.usernameLineEdit, 'usernameLineEdit', self.saveUsernameErrorMessageLabel))
        self.oldPasswordLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEditSettings(self.oldPasswordLineEdit, 'oldPasswordLineEdit', self.savePasswordErrorMessageLabel))
        self.newPasswordLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEditSettings(self.newPasswordLineEdit, 'newPasswordLineEdit', self.savePasswordErrorMessageLabel))
        self.confirmPasswordLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEditSettings(self.confirmPasswordLineEdit, 'confirmPasswordLineEdit', self.savePasswordErrorMessageLabel))


    # method for setting the text in the error message in login and register popups
    def ChangeLoginRegisterErrorMessage(self, message='', isLogin=True):
        if isLogin:
            self.loginErrorMessageLabel.setText(message)
            if message == '':
                self.loginErrorMessageLabel.hide()
        else:
            self.registerErrorMessageLabel.setText(message)
            if message == '':
                self.registerErrorMessageLabel.hide()


    # method for changing the styles of a line edit when it does not match the regex
    def NotifyInvalidLineEdit(self, lineEditWidget, lineEditName, errorMessageLabel=None):
        currentStylesheet = f''' 
            #{lineEditName} {{
                background-color: #f0f0f0;
                border: 2px solid lightgray;
                border-radius: 10px;
                padding: 5px;
                color: black;
                {'margin: 0px 5px 0px 5px;' if ('Password' in lineEditName) else 'margin: 0px 5px 10px 5px;'}
            }}
        '''
        # set initial styles
        lineEditWidget.setStyleSheet(currentStylesheet)

        # clear error message and hide error message label if given
        if errorMessageLabel:
            UserInterfaceFunctions.ClearErrorMessageText(errorMessageLabel)

        # check if the input matches the regex, if not update the border style to red (invalid input)
        if not lineEditWidget.hasAcceptableInput():
            lineEditWidget.setStyleSheet(currentStylesheet.replace('border: 2px solid lightgray;', 'border: 2px solid #D84F4F;'))


    # method for changing the styles of a line edit when it does not match the regex
    def NotifyInvalidLineEditSettings(self, lineEditWidget, lineEditName, errorMessageLabel=None):
        # Getting the current stylesheet by object name for the given line edit in settings page
        defaultStylesheet = UserInterfaceFunctions.GetDefaultStyleSheetSettingsLineEdits(lineEditName)

        # set initial styles
        lineEditWidget.setStyleSheet(defaultStylesheet)

        # clear error message and hide error message label if given
        if errorMessageLabel:
            UserInterfaceFunctions.ClearErrorMessageText(errorMessageLabel)

        # check if the input matches the regex, if not update the border style to red (invalid input)
        if not lineEditWidget.hasAcceptableInput():
            lineEditWidget.setStyleSheet(defaultStylesheet.replace('border: 2px solid lightgray;', 'border: 2px solid #D84F4F;'))


    # method that validates that a given password matches the password validator regex
    def ValidatePassword(self, password, errorLabelObject=None, errorMessage=None):
        simpleValidatorState, _, _ = self.passwordValidator.validate(password, 0)
        complexValidatorState, _, _ = self.finalPasswordValidator.validate(password, 0)
        if (simpleValidatorState != self.passwordValidator.Acceptable) or (complexValidatorState != self.finalPasswordValidator.Acceptable):
            if errorLabelObject and errorMessage:
                UserInterfaceFunctions.ChangeErrorMessageText(errorLabelObject, errorMessage)
            return False
        return True


    # method that sets the text in the info page with the system information of the users machine
    def InitSystemInfo(self, systemDict):
        # initialize system information section (left side)
        self.OSTypeInfoLabel.setText(systemDict.get('osType'))
        self.OSVersionInfoLabel.setText(systemDict.get('osVersion'))
        self.architectureInfoLabel.setText(systemDict.get('architecture'))
        self.hostNameInfoLabel.setText(systemDict.get('hostName'))


    # method for updating network interface from combobox in gui
    def ChangeNetworkInterface(self):
        # set selected interface to chosen interfaces selected in combobox in gui
        NetworkInformation.selectedInterface = self.networkInterfaceComboBox.currentText()
        print(f'Selected interface: {NetworkInformation.selectedInterface}')

        # initialize network information section (right side)
        selectedInterface = NetworkInformation.networkInfo.get(NetworkInformation.selectedInterface)
        self.connectedInterfaceInfoLabel.setText(selectedInterface.get('name'))
        self.maxAddressInfoLabel.setText(selectedInterface.get('mac'))
        self.descriptionInfoLabel.setText(selectedInterface.get('description'))
        self.maxSpeedInfoLabel.setText(str(selectedInterface.get('maxSpeed')))
        self.maxTransmitionUnitInfoLabel.setText(str(selectedInterface.get('maxTransmitionUnit')))
        self.ipAddressesListWidget.clear()
        self.ipAddressesListWidget.addItems(selectedInterface.get('ipv4Addrs') + selectedInterface.get('ipv6Addrs'))
        UserInterfaceFunctions.DisableSelectionIpListWidget(self)


    # method for showing file dialog for user to choose his desired path and file name
    def GetPathFromReportFileDialog(self):
        options = QFileDialog.Options()
        filePath, _ = QFileDialog.getSaveFileName(
            None, #represents parent window
            'Download Report', #represents dialog title
            'alerts_report.txt', #represents default filename
            'Text Files (*.txt);;CSV Files (*.csv)',
            options=options
        )
        return filePath
    

    # method for initializing mac addresses blacklist in gui
    def InitMacAddresses(self, macBlacklist):
        self.macAddressListWidget.clear() #clear mac addresses list
        self.macAddressListWidget.addItems(macBlacklist) #add all mac addresses to our blacklist


    # method for initializing history table widget in gui
    def InitHistoryTable(self, alertList):
        self.historyTableWidget.setRowCount(0) #clear history table

        #iterate over each alert in list and add it to our table
        for alert in alertList:
            self.AddRowToHistoryTable(alert.get('srcIp'), alert.get('srcMac'), alert.get('dstIp'),
                                       alert.get('dstMac'), alert.get('attackType'), alert.get('timestamp'))
            

    # method for initializing report table widget in gui
    def InitReportTable(self, alertList):
        self.reportPreviewTableModel.ClearReportTable() #clear report table

        #iterate over each alert in list and add it to our table
        for alert in alertList:
            self.AddRowToReportTable(alert.get('interface'), alert.get('attackType'), alert.get('srcIp'), alert.get('srcMac'), alert.get('dstIp'), 
                                       alert.get('dstMac'), alert.get('protocol'), alert.get('osType'), alert.get('timestamp'))
    

    # method for adding row to history table widget in gui
    def AddRowToHistoryTable(self, srcIp, srcMac, dstIp, dstMac, attackType, timestamp):
        if srcIp and srcMac and dstIp and dstMac and attackType and timestamp:
            currentRow = 0 #add new row in the beginning of table
            # add our items into row for showing detected attack
            self.historyTableWidget.insertRow(currentRow)
            self.historyTableWidget.setItem(currentRow, 0, QTableWidgetItem(srcIp))
            self.historyTableWidget.setItem(currentRow, 1, QTableWidgetItem(srcMac))
            self.historyTableWidget.setItem(currentRow, 2, QTableWidgetItem(dstIp))
            self.historyTableWidget.setItem(currentRow, 3, QTableWidgetItem(dstMac))
            self.historyTableWidget.setItem(currentRow, 4, QTableWidgetItem(attackType))
            self.historyTableWidget.setItem(currentRow, 5, QTableWidgetItem(timestamp))
            # center the text of the last row after adding it
            UserInterfaceFunctions.CenterSpecificTableRowText(self.historyTableWidget)
    

    # method for adding row to report preview table widget in gui
    def AddRowToReportTable(self, interface, attackType, srcIp, srcMac, dstIp, dstMac, protocol, osType, timestamp):
        if interface and attackType and srcIp and srcMac and dstIp and dstMac and protocol and timestamp:
            newRow = self.reportPreviewTableModel.AddRowToReportTable() #create a new row add all the values into it by index
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 0, interface)
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 1, attackType)
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 2, srcIp)
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 3, srcMac)
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 4, dstIp)
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 5, dstMac)
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 6, protocol)
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 7, timestamp)
            self.reportPreviewTableModel.SetRowItemReportTable(newRow, 8, osType)
            UserInterfaceFunctions.ReportDurationComboboxChanged(self) #trigger default sort for duration combobox
            UserInterfaceFunctions.ReportCheckboxToggled(self) #trigger default sort for checkboxes


    # method for setting user interface to logged in or logged out state 
    def ChangeUserState(self, state, userData=None):
        # check if detection is off
        if not self.isDetection:
            # means we need to set user interface for logged in user
            if state and userData:
                self.userData = userData #save user data dictionary for logged in user
                UserInterfaceFunctions.AccountIconClicked(self) #close login popup
                UserInterfaceFunctions.ToggleUserInterface(self, True) #toggle user interface
                self.welcomeLabel.setText(f'Welcome {self.userData.get('userName')}')
                self.UpdateNumberOfDetectionsCounterLabel(self.userData.get('numberOfDetections')) #set num of detections counter
                self.emailLineEdit.setText(self.userData.get('email')) #set email of user in settings page
                self.usernameLineEdit.setText(self.userData.get('userName')) #set username of user in settings page
                self.InitHistoryTable(self.userData.get('alertList')) #initialize our history table
                self.InitReportTable(self.userData.get('alertList')) #initialize our report table
                self.InitMacAddresses(self.userData.get('blackList')) #intialize our mac address black list
                UserInterfaceFunctions.ReportDurationComboboxChanged(self) #trigger default sort for duration combobox
                UserInterfaceFunctions.ReportCheckboxToggled(self) #trigger default sort for checkboxes
                UserInterfaceFunctions.UpdateChartAfterLogin(self, self.userData.get('pieChartData')) #initialize pie chart
                self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has logged in.', 'INFO') #log login event

            # means we set user interface for logged out user
            else:
                self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has logged out.', 'INFO') #log logout event
                self.userData = {'userId': None, 'email': None, 'userName': None, 'numberOfDetections': 0,
                                  'lightMode': 0, 'alertList': [], 'pieChartData': {}, 'blackList': []} #reset our user data dictionary
                UserInterfaceFunctions.ToggleUserInterface(self, False) #reset our user interface


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
            self.numberOfDetectionsCounter.setText(str(self.userData.get('numberOfDetections')))


    # method for sending logs to logger thread for writing logs
    @pyqtSlot(str, str)
    def SendLogDict(self, message, level='INFO'):
        # if logger thread active we send logs
        if self.loggerThread:
            logDict = {'timestamp': NetworkInformation.GetCurrentTimestamp(), 'level': level, 'message': message}
            self.loggerThread.ReceiveLog(logDict)


    # method for updating report progress bar in gui
    @pyqtSlot(int)
    def UpdateReportProgressBar(self, value):
         self.reportProgressBar.setValue(value)


    # method for updating running time label in gui
    @pyqtSlot()
    def UpdateRunningTimeCounterLabel(self):
        # increment timer by 1 second
        self.timeElapsed += timedelta(seconds=1)
        # extract hours, minutes, seconds directly from the timedelta object
        totalSeconds = int(self.timeElapsed.total_seconds())
        hours = totalSeconds // 3600 #get the number of full hours
        minutes = (totalSeconds % 3600) // 60 #get the remaining minutes
        seconds = totalSeconds % 60 #get the remaining seconds
        formattedTime = f'{hours}:{minutes:02}:{seconds:02}'
        # update label with formatted time
        self.runningTimeCounter.setText(formattedTime)


    # method for updating timer in main thread
    @pyqtSlot(bool)
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
            self.runningTimeCounter.setText('0:00:00')

    
    # method for updating arp list in main thread
    @pyqtSlot(ARP_Packet)
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
    @pyqtSlot(tuple, Default_Packet)
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
    @pyqtSlot(tuple, DNS_Packet)
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
    @pyqtSlot()
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
                self.arpThread.ReceiveArpBatch(arpBatch) #send batch to arp thread
                self.SendLogDict('Main_Thread: Sent arp list for analysis.', 'INFO') #log send event


    # method for extracting packet batches from portScanDos dict and sending to thread for analysis from main thread
    @pyqtSlot()
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
                self.portScanDosThread.ReceivePortScanDosBatch(portScanDosBatch) #send batch to portScanDos thread
                self.SendLogDict('Main_Thread: Sent portScanDos list for analysis.', 'INFO') #log send event


    # method for extracting packet batches from dns dict and sending to thread for analysis from main thread
    @pyqtSlot()
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
                self.dnsThread.ReceiveDnsBatch(dnsBatch) #send batch to dns thread
                self.SendLogDict('Main_Thread: Sent dns list for analysis.', 'INFO') #log send event


    # method for closing SQL thread and setting it back to none
    @pyqtSlot(dict)
    def CloseSQLThread(self, stateDict):
        self.sqlThread = None #set thread to none
        # in case of an error we show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            UserInterfaceFunctions.ShowPopup('Database Connection Failed', stateDict.get('message'), 'Critical')
            self.SendLogDict(f'SQL_Thread: {stateDict.get('message')}', 'ERROR') #log error event
        self.SendLogDict('SQL_Thread: Finsihed database tasks.', 'INFO') #log finish event


    # method for closing report thread and setting it back to none
    @pyqtSlot(dict, bool)
    def CloseReportThread(self, stateDict, isClosing=False):
        self.reportThread = None #set thread to none
        # toggle report interface to be hidden
        UserInterfaceFunctions.ToggleReportInterface(self, False)
        # only show popup messages if isClosing flag is not set
        if not isClosing:
            # in case of an error we show error message
            if stateDict.get('state') == False and stateDict.get('message'):
                UserInterfaceFunctions.ShowPopup('Error Occurred', stateDict.get('message'), 'Critical')
                self.SendLogDict(f'Report_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            # in case of cancelation, we show cancelation messsage
            elif stateDict.get('state') == True and stateDict.get('message'):
                UserInterfaceFunctions.ShowPopup('Canceled Report Generation', stateDict.get('message'), 'Information')
                self.SendLogDict(f'Report_Thread: {stateDict.get('message')}', 'ERROR') #log error event
            # else we show success message
            else:
                UserInterfaceFunctions.ShowPopup('Generated Report Successfully', 'Generated report in desired format successfully.', 'Information')
        self.SendLogDict('Report_Thread: Finsihed Creating Report.', 'INFO') #log finish event


    # method for closing logger thread and setting it back to none
    @pyqtSlot(dict)
    def CloseLoggerThread(self, stateDict):
        self.loggerThread = None #set thread to none
        # in case of an error we show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            UserInterfaceFunctions.ShowPopup('Error Occurred', stateDict.get('message'), 'Critical')


    # method for closing sniffer thread and setting it back to none
    @pyqtSlot(dict)
    def CloseSnifferThread(self, stateDict):
        self.snifferThread = None #set thread to none for next detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.arpThread and not self.portScanDosThread and not self.dnsThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            UserInterfaceFunctions.ShowPopup('Error Occurred', stateDict.get('message'), 'Critical')
            self.SendLogDict(f'Sniffer_Thread: {stateDict.get('message')}', 'ERROR') #log error event
        self.SendLogDict('Sniffer_Thread: Finsihed network scan.', 'INFO') #log finish event


    # method for closing arp thread and setting it back to none
    @pyqtSlot(dict)
    def CloseArpThread(self, stateDict):
        self.arpThread = None #set thread to none for next detection
        ArpSpoofing.isArpTables = False #set our initialized flag to false for arp detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.snifferThread and not self.portScanDosThread and not self.dnsThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            UserInterfaceFunctions.ShowPopup('Error Occurred', stateDict.get('message'), 'Critical')
            self.SendLogDict(f'Arp_Thread: {stateDict.get('message')}', 'ERROR') #log error event
        self.SendLogDict('Arp_Thread: Finsihed analysis of traffic.', 'INFO') #log finish event


    # method for closing portScanDos thread and setting it back to none
    @pyqtSlot(dict)
    def ClosePortScanDosThread(self, stateDict):
        self.portScanDosThread = None #set thread to none for next detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.snifferThread and not self.arpThread and not self.dnsThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            UserInterfaceFunctions.ShowPopup('Error Occurred', stateDict.get('message'), 'Critical')
            self.SendLogDict(f'PortScanDos_Thread: {stateDict.get('message')}', 'ERROR') #log error event
        self.SendLogDict('PortScanDos_Thread: Finsihed analysis of traffic.', 'INFO') #log finish event


    # method for closing dns thread and setting it back to none
    @pyqtSlot(dict)
    def CloseDnsThread(self, stateDict):
        self.dnsThread = None #set thread to none for next detection
        # we check if it was the last thread, if so we set isDetection flag
        if not self.snifferThread and not self.arpThread and not self.portScanDosThread:
            self.isDetection = False
        # in case of an error we stop detection and show error message
        if stateDict.get('state') == False and stateDict.get('message'):
            self.StopDetection() #stop detection and stop running threads
            UserInterfaceFunctions.ShowPopup('Error Occurred', stateDict.get('message'), 'Critical')
            self.SendLogDict(f'Dns_Thread: {stateDict.get('message')}', 'ERROR') #log error event
        self.SendLogDict('Dns_Thread: Finsihed analysis of traffic.', 'INFO') #log finish event


    # method for receiving database connection result
    @pyqtSlot(dict)
    def ConnectionResult(self, stateDict):
        # we check if connected to database succcessfully
        if stateDict.get('state') == True and stateDict.get('message'):
            self.SendLogDict(f'SQL_Thread: {stateDict.get('message')}', 'INFO') #log connection event


    # method for analyzing detection result of arp spoofing attack
    @pyqtSlot(dict)
    def ArpDetectionResult(self, result):
        # check if ARP tables are being initialized (type 3)
        if result.get('type') == 3:
            ArpSpoofing.isArpTables = True #set isArpTable to true indicating we can sniff arp packets
            self.SendLogDict('Arp_Thread: Initialized ARP tables successfully.', 'INFO') #log arp tables initialization event

        # process only if an attack is detected state is false and an attackDict provided
        if result.get('state') is False and result.get('attackDict'):
            type = result.get('type') #represents type of result, 1-ipToMac, 2-macToIp, 3-Both
            attackDict = result.get('attackDict') #represents attack dictionary with all anomalies found
            
            # handle Ip to Mac anomalies we found in arp spoofing attack (including initialization)
            if type in (1, 3):
                # represents the ipDict of arp spoofing, for type 3 its nested under 'ipToMac'
                ipDict = attackDict if type == 1 else attackDict.get('ipToMac', {})
                for ip, details in ipDict.items():
                    isNewAttack = False #represents a flag for indicating if attack is new or not

                    # we check if detected ip is in our known attacks in arpAttackDict
                    if ip not in self.arpAttackDict['ipToMac']:
                        self.arpAttackDict['ipToMac'][ip] = details #add new ip entry in our arpAttackDict
                        isNewAttack = True #set new attack to true
                    
                    # we check if detected ip is already in our known attacks in arpAttackDict
                    elif ip in self.arpAttackDict['ipToMac']:
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
                    if mac not in self.arpAttackDict['macToIp']:
                        self.arpAttackDict['macToIp'][mac] = details #add new mac entry in our arpAttackDict
                        isNewAttack = True #set new attack to true
                    
                    # we check if detected mac is already in our known attacks in arpAttackDict
                    elif mac in self.arpAttackDict['macToIp']:
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
    @pyqtSlot(dict)
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
    @pyqtSlot(dict)
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


    # method for stopping detection and closing threads
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
            
            # enable interface combobox and reset our data structures and counters
            self.SendLogDict(f'Main_Thread: Stopping detection. Remaining packets - TCP/UDP: {self.tcpUdpCounter}, ARP: {self.arpCounter}, DNS: {self.dnsCounter}', 'INFO') #log stop event
            self.networkInterfaceComboBox.setEnabled(True) #enable interface changes
            self.opperationModeComboBox.setEnabled(True) #disable interface changes
            self.arpCounter, self.tcpUdpCounter, self.dnsCounter = 0, 0, 0 #reset our counters
            self.arpList, self.portScanDosDict, self.dnsDict = [], {}, {} #reset our packet data structures
            self.arpAttackDict, self.portScanDosAttackDict, self.dnsAttackDict = {'ipToMac': {}, 'macToIp': {}}, {}, {} #reset known attacks


    # method for starting our threads and detect network cyber attacks in real time
    def StartDetection(self):
        if not self.snifferThread and not self.arpThread and not self.portScanDosThread and not self.dnsThread:
            self.isDetection = True #set flag to true indication we started a detection
            self.networkInterfaceComboBox.setEnabled(False) #disable interface changes
            self.opperationModeComboBox.setEnabled(False) #disable interface changes

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

        else:
            UserInterfaceFunctions.ShowPopup('Error Starting Detection', 'One of the threads is still in process, cannot start new detection.', 'Warning')
            self.SendLogDict('Main_Thread: One of the threads is still in process, cannot start new detection.', 'INFO') #log event

    
    # method for startStop button for starting or stopping detection
    def StartStopButtonClicked(self):
        # get the correct styles based on the button text (start / stop)
        currentStyleSheet = f'''
            #startStopButton {{
                border-radius: 60px;
                {'background-color: #3A8E32;' if self.startStopButton.text() == 'STOP' else 'background-color: #D84F4F;'}
                border: 1px solid black;
                color: black;
                font-weight: bold;
            }}

            #startStopButton:hover {{
                {'background-color: #4D9946;' if self.startStopButton.text() == 'STOP' else 'background-color: #DB6060;'}
            }}

            #startStopButton:pressed {{
                {'background-color: #2E7128;' if self.startStopButton.text() == 'STOP' else 'background-color: #AC3f3F;'}
            }}
        '''
        # apply the correct style sheet to the button
        self.startStopButton.setStyleSheet(currentStyleSheet)

        # start and stop the sniffer and change the button text correctly
        if self.startStopButton.text() == 'START':
            self.startStopButton.setText('STOP')
            self.StartDetection()
        else:
            self.startStopButton.setText('START')
            self.StopDetection()

    #-----------------------------------------------CLICKED-METHODS----------------------------------------------#

    # method for loggin into user's account and intialize our userData dictionary
    def LoginButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowPopup('Error In Login', 'Please stop detection before attempting to log in.', 'Information')
            # means both fields are empty
            elif not self.loginUsernameLineEdit.text() and not self.loginPasswordLineEdit.text():
                UserInterfaceFunctions.ChangeErrorMessageText(self.loginErrorMessageLabel, 'Please enter username and password.')
            # means username field empty
            elif not self.loginUsernameLineEdit.text():
                UserInterfaceFunctions.ChangeErrorMessageText(self.loginErrorMessageLabel, 'Please enter your username.')
            # means password field empty
            elif not self.loginPasswordLineEdit.text():
                UserInterfaceFunctions.ChangeErrorMessageText(self.loginErrorMessageLabel, 'Please enter your password.')
            # else we process the login request to our sql thread
            else:
                self.sqlThread.Login(self.loginUsernameLineEdit.text(), NetSpect.ToSHA256(self.loginPasswordLineEdit.text()))

    
    # method for loggin out of user's account and clear user interface
    def LogoutButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowPopup('Error In Logout', 'Please stop detection before attempting to log out.', 'Information')
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
                UserInterfaceFunctions.ShowPopup('Error In Registration', 'Please stop detection before attempting to register.', 'Information')
            # else we register new user
            else:
                email = self.registerEmailLineEdit.text()
                emailState, _, _ = self.emailValidator.validate(email, 0)
                username = self.registerUsernameLineEdit.text()
                usernameState, _, _ = self.usernameValidator.validate(username, 0)
                password = self.registerPasswordLineEdit.text()
                passwordState = self.ValidatePassword(password)

                # means email, username and password fields are invalid
                if emailState != self.emailValidator.Acceptable and usernameState != self.usernameValidator.Acceptable and not passwordState:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.registerErrorMessageLabel, 'Please enter a valid email address, username and passowrd into the fields.')
                # means email and username fields are invalid
                elif emailState != self.emailValidator.Acceptable and usernameState != self.usernameValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.registerErrorMessageLabel, 'Please enter a valid email address and username into the fields.')
                # means email and password fields are invalid
                elif emailState != self.emailValidator.Acceptable and not passwordState:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.registerErrorMessageLabel, 'Please enter a valid email address and password into the fields.')
                # means username and password fields are invalid
                elif usernameState != self.usernameValidator.Acceptable and not passwordState:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.registerErrorMessageLabel, 'Please enter a valid username and password into the fields.')
                # means email address field is invalid
                elif emailState != self.emailValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.registerErrorMessageLabel, 'Please enter a valid email address into the field.')
                # means username field is invalid
                elif usernameState != self.usernameValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.registerErrorMessageLabel, 'Please enter a valid username into the field.')
                # means password field is invalid
                elif not passwordState:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.registerErrorMessageLabel, 'Please enter a valid password into the field.')
                # else we process the register request to our sql thread
                else:
                    self.sqlThread.Register(email, username, NetSpect.ToSHA256(password))


    # method for deleting user account from database when user clicks the delete account button in settings page
    def DeleteAccoutButtonClicked(self):
        if self.sqlThread:
            # means we had detection active
            if self.isDetection:
                UserInterfaceFunctions.ShowPopup('Error Deleting Account', 'Please stop detection before attempting to delete account.', 'Information')
            # else we emit signal to sql thread to delete account from database
            else:
                result = UserInterfaceFunctions.ShowPopup('Delete Account Confirmation', 'Deleting your account will permanently remove all your data. Do you want to proceed?', 'Question')
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
            UserInterfaceFunctions.UpdateChartAfterAttack(self, attackType) #increment attack type in pie chart
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
            UserInterfaceFunctions.ShowPopup('Error Deleting Alerts', 'Please stop detection before attempting to delete alerts history.', 'Information')
        else:
            if self.userData:
                # clear history and report tables and also reset alertsList and user interface counter
                self.userData['alertList'] = [] #clear alertsList in userData
                self.userData['pieChartData'] = {} #clear pieChartData in userData
                self.userData['blackList'] = [] #clear blackList in userData
                self.UpdateNumberOfDetectionsCounterLabel(0) #reset the number of detections counter in user interface
                UserInterfaceFunctions.ResetChartToDefault(self) #reset our pie chart
                self.historyTableWidget.setRowCount(0) #clear history table
                self.reportPreviewTableModel.ClearReportTable() #clear report table

                # delete alerts from database if user is logged in
                if self.sqlThread and self.userData.get('userId'):
                    self.sqlThread.DeleteAlerts(self.userData.get('userId'))
                else:
                    UserInterfaceFunctions.ShowPopup('Alerts Deletion Successful', 'Deleted all alerts history for previously detected attacks.', 'Information')


    # method for adding an item to the mac address blacklist when user clicks the add button in settings page
    def AddMacAddressButtonClicked(self):
        if self.isDetection:
            UserInterfaceFunctions.ShowPopup('Error Adding To Blacklist', 'Please stop detection before attempting to add an item to the blacklist.', 'Information')
        else:
            newMacAddress = self.macAddressLineEdit.text().lower() #convert characters to lower case for ease of use
            listOfMacAddresses = [self.macAddressListWidget.item(i).text() for i in range(self.macAddressListWidget.count())]
            if not QRegExp(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$').exactMatch(newMacAddress):
                UserInterfaceFunctions.ChangeErrorMessageText(self.macAddressBlacklistErrorMessageLabel, 'Please enter a valid MAC address')
            elif (len(listOfMacAddresses) > 0) and (newMacAddress in listOfMacAddresses):
                UserInterfaceFunctions.ChangeErrorMessageText(self.macAddressBlacklistErrorMessageLabel, 'This MAC address already exists in blacklist')
            else: #means that this mac address is NOT already in the list
                UserInterfaceFunctions.ClearErrorMessageText(self.macAddressBlacklistErrorMessageLabel)
                if self.sqlThread and self.userData.get('userId'):
                    self.sqlThread.AddBlacklistMac(self.userData.get('userId'), newMacAddress)
                else:
                    self.macAddressListWidget.addItem(newMacAddress)
                    self.macAddressLineEdit.clear()
                    self.userData.setdefault('blackList', []).append(newMacAddress)
                    self.SendLogDict(f'Main_Thread: User has added a new mac address to mac blacklist successfully.', 'INFO') #log add mac event


    # method for removing an item from the mac address blacklist when the user clicks the 'delete' button in the contex menu of the list widget
    def DeleteMacAddressButtonClicked(self, item): 
        if self.isDetection:
            UserInterfaceFunctions.ShowPopup('Error Deleting From Blacklist', 'Please stop detection before attempting to delete an item from the blacklist.', 'Information')
        else:
            self.seletecItemForDelete = item
            if self.sqlThread and self.userData.get('userId'):
                self.sqlThread.DeleteBlacklistMac(self.userData.get('userId'), item.text())
            else:
                self.macAddressListWidget.takeItem(self.macAddressListWidget.row(self.seletecItemForDelete))
                self.userData.setdefault('blackList', []).remove(self.seletecItemForDelete.text())
                self.SendLogDict(f'Main_Thread: User has removed mac address from mac blacklist successfully.', 'INFO') #log remove mac event


    # method for saving and updating the user's email after user clicks save button in settings page
    def SaveEmailButtonClicked(self):
        if self.sqlThread:
            if self.userData.get('userId') != None:
                newEmail = self.emailLineEdit.text()
                state, _, _ = self.emailValidator.validate(newEmail, 0)
                if newEmail == self.userData.get('email'):
                    UserInterfaceFunctions.ChangeErrorMessageText(self.saveEmailErrorMessageLabel ,'You\'r new email is the same as the current email, please enter a different email before clicking the save button.')
                elif state != self.emailValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.saveEmailErrorMessageLabel ,'Please enter a valid email address into the field before clicking the save button.')
                else:
                    self.sqlThread.ChangeEmail(self.userData.get('userId'), newEmail)


    # method for saving and updating the user's username after user clicks save button in settings page
    def SaveUsernameButtonClicked(self):
        if self.sqlThread:
            if self.userData.get('userId') != None:
                newUsername = self.usernameLineEdit.text()
                state, _, _ = self.usernameValidator.validate(newUsername, 0)
                if newUsername == self.userData.get('username'):
                    UserInterfaceFunctions.ChangeErrorMessageText(self.saveUsernameErrorMessageLabel ,'You\'r new username is the same as the current username, please enter a different username before clicking the save button.')
                elif state != self.usernameValidator.Acceptable:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.saveUsernameErrorMessageLabel ,'Please enter a valid username into the field before clicking the save button.')
                else:
                    self.sqlThread.ChangeUserName(self.userData.get('userId'), newUsername)


    # method for saving and updating the user's password after user clicks save button in settings page
    def SavePasswordButtonClicked(self):
        if self.sqlThread:
            if self.userData.get('userId') != None:
                oldPassword = self.oldPasswordLineEdit.text()
                newPassword = self.newPasswordLineEdit.text()
                confirmPassword = self.confirmPasswordLineEdit.text()
                if (len(oldPassword) == 0) or (len(newPassword) == 0) or (len(confirmPassword) == 0):
                    UserInterfaceFunctions.ChangeErrorMessageText(self.savePasswordErrorMessageLabel ,'Please fill in all password fields before clicking the save button.')
                elif newPassword != confirmPassword:
                    UserInterfaceFunctions.ChangeErrorMessageText(self.savePasswordErrorMessageLabel ,'Please confirm your new password, the password in the second and third fields must be the same before clicking the save button.')
                else:
                    if self.ValidatePassword(oldPassword, self.savePasswordErrorMessageLabel, 'You have entered an invalid password in the first field, please enter the correct current password before clicking the save button.'):
                        if self.ValidatePassword(newPassword, self.savePasswordErrorMessageLabel, 'You have entered an invalid password in the second field, please enter a valid new password before clicking the save button.'):
                            if self.ValidatePassword(confirmPassword, self.savePasswordErrorMessageLabel, 'You have entered an invalid password in the third field, please enter a valid new password before clicking the save button.'):
                                self.sqlThread.ChangePassword(self.userData.get('userId'), NetSpect.ToSHA256(newPassword), NetSpect.ToSHA256(oldPassword))


    # method for creating alerts report for user in desired format, txt or csv
    def DownloadReportButtonClicked(self):
        if not self.reportThread:
            # get system info and filtered alert list
            systemInfo = NetworkInformation.systemInfo if self.machineInfoCheckBox.isChecked() else None
            alertList = UserInterfaceFunctions.GetFilteredAlerts(self)

            # if alertList is empty, we show message
            if not alertList:
                UserInterfaceFunctions.ShowPopup('No Detection History', 'There are no detected alerts available for report generation.', 'Information')
            # else we proceed
            else:
                # get desired path for report from file dialog
                filePath = self.GetPathFromReportFileDialog()
                
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
        if self.reportThread:
            self.reportThread.StopThread()

    #---------------------------------------------CLICKED-METHODS-END--------------------------------------------#

    #----------------------------------------------SQL-RESULT-SLOTS----------------------------------------------#

    # method for showing login result from sql thread and process user's data
    @pyqtSlot(dict)
    def LoginResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error In Login', 'Error loggin into user account due to server error, please try again later.', 'Critical')
        # means failed loggin in, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.loginErrorMessageLabel, resultDict.get('message'))
        # means we successfully logged in
        elif resultDict.get('state') and resultDict.get('result'):
            self.ChangeUserState(True, resultDict.get('result')) #call our method to log into account

    
    # method for showing register result from sql thread and process user's data
    @pyqtSlot(dict)
    def RegisterResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error In Register', 'Error registering new user due to server error, please try again later.', 'Critical')
        # means failed registering user, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.registerErrorMessageLabel, resultDict.get('message'))
        # means we successfully registered user, we process a login request to our sql thread to log into his new account
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: Registered new user with email {self.registerUsernameLineEdit.text()}.', 'INFO') #log register event
            self.sqlThread.Login(self.registerUsernameLineEdit.text(), NetSpect.ToSHA256(self.registerPasswordLineEdit.text())) #call login method to login new user
            UserInterfaceFunctions.ShowPopup('Registration Successful', 'You have successfully registered. Logged into your account automatically.', 'Information')


    # method for showing delete account result from sql thread
    @pyqtSlot(dict)
    def DeleteAccountResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error Deleting Account', 'Error deleting account due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Error deleting account due to server error.', 'ERROR') #log error event
        # means failed deleting account, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ShowPopup('Failed Deleting Account', 'Failed deleting account due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Failed deleting account due to server error.', 'ERROR') #log error event
        # means we successfully deleted account, we logout of previous user account
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')}\'s account has been deleted successfully.', 'INFO') #log delete user event
            self.LogoutButtonClicked() #call our method to log out of previous account
            UserInterfaceFunctions.ShowPopup('User Account Deletion Successful', 'Your account has been deleted successfully. Sorry to see you go.', 'Information')
        

    # method for showing add alert result from sql thread
    @pyqtSlot(dict)
    def AddAlertResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error Adding Alert', 'Error adding alert due to server error.', 'Critical')
            self.SendLogDict('Main_Thread: Error adding alert due to server error.', 'ERROR') #log error event
        # means failed adding alert, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ShowPopup('Failed Adding Alert', 'Failed adding alert due to server error.', 'Critical')
            self.SendLogDict('Main_Thread: Failed adding alert due to server error.', 'ERROR') #log error event


    # method for showing delete alerts result from sql thread
    @pyqtSlot(dict)
    def DeleteAlertsResult(self, resultDict):
        # means error occured, we show error pop up
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error Deleting Alerts', 'Error deleting alerts history due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Error deleting alerts history due to server error.', 'ERROR') #log error event
        # means failed deleting alerts, we show error message
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ShowPopup('Failed Deleting Alerts', 'Failed deleting alerts history due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Failed deleting alerts history due to server error.', 'ERROR') #log error event
        # means we successfully deleted alerts
        elif resultDict.get('state'):
            UserInterfaceFunctions.ShowPopup('Alerts Deletion Successful', 'Deleted all alerts history for previously detected attacks.', 'Information')
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')}\'s alerts history has been deleted successfully.', 'INFO') #log delete alerts event


    # method for showing results to the user after adding a mac address to blacklist
    @pyqtSlot(dict)
    def AddMacToBlackListResult(self, resultDict):
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error Adding To Blacklist', 'Error adding an item to the blacklist due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Error adding an item to the blacklist due to server error.', 'ERROR') #log error event
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.macAddressBlacklistErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.macAddressListWidget.addItem(self.macAddressLineEdit.text())
            self.userData.setdefault('blackList', []).append(self.macAddressLineEdit.text())
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has added a new mac address to mac blacklist successfully.', 'INFO') #log add mac event
        self.macAddressLineEdit.clear()


    # method for showing results to the user after removing a mac address from blacklist 
    @pyqtSlot(dict)
    def DeleteMacFromBlackListResult(self, resultDict):
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error Removing From Blacklist', 'Error removing an item from the blacklist due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Error removing an item from the blacklist due to server error.', 'ERROR') #log error event
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.macAddressBlacklistErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.macAddressListWidget.takeItem(self.macAddressListWidget.row(self.seletecItemForDelete))
            self.userData.setdefault('blackList', []).remove(self.seletecItemForDelete.text())
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has removed mac address from mac blacklist successfully.', 'INFO') #log remove mac event
        self.seletecItemForDelete = None


    # method for showing results to the user after removing a mac address from blacklist 
    @pyqtSlot(dict)
    def SaveEmailResult(self, resultDict):
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error Saving Email', 'Error saving email due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Error saving email due to server error.', 'ERROR') #log error event
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.saveEmailErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has changed email successfully.', 'INFO') #log change email event
            self.saveEmailErrorMessageLabel.clear()
            self.userData['email'] = self.emailLineEdit.text()
            UserInterfaceFunctions.ShowPopup('Email Changed Successfullly', 'You\'r email has changed successfully.', 'Information')


    # method for showing results to the user after removing a mac address from blacklist 
    @pyqtSlot(dict)
    def SaveUsernameResult(self, resultDict):
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error Saving Username', 'Error saving username due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Error saving username due to server error.', 'ERROR') #log error event
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.saveUsernameErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has changed username to {self.usernameLineEdit.text()} successfully.', 'INFO') #log change username event
            self.saveUsernameErrorMessageLabel.clear()
            self.userData['userName'] = self.usernameLineEdit.text()
            self.welcomeLabel.setText(f'Welcome {self.usernameLineEdit.text()}')
            UserInterfaceFunctions.ShowPopup('Username Changed Successfullly', 'You\'r username has changed successfully.', 'Information')


    # method for showing results to the user after removing a mac address from blacklist 
    @pyqtSlot(dict)
    def SavePasswordResult(self, resultDict):
        if resultDict.get('error'):
            UserInterfaceFunctions.ShowPopup('Error Saving Password', 'Error saving password due to server error, please try again later.', 'Critical')
            self.SendLogDict('Main_Thread: Error saving password due to server error.', 'ERROR') #log error event
        elif not resultDict.get('state'):
            UserInterfaceFunctions.ChangeErrorMessageText(self.savePasswordErrorMessageLabel, resultDict.get('message'))
        elif resultDict.get('state'):
            self.SendLogDict(f'Main_Thread: User {self.userData.get('userName')} has changed password successfully.', 'INFO') #log change password event
            # clear the password input fields
            self.savePasswordErrorMessageLabel.clear()
            self.oldPasswordLineEdit.clear()
            self.newPasswordLineEdit.clear()
            self.confirmPasswordLineEdit.clear()

            # for each password input field we want to and reset the border to light gray
            self.oldPasswordLineEdit.setStyleSheet(UserInterfaceFunctions.GetDefaultStyleSheetSettingsLineEdits('oldPasswordLineEdit'))
            self.newPasswordLineEdit.setStyleSheet(UserInterfaceFunctions.GetDefaultStyleSheetSettingsLineEdits('newPasswordLineEdit'))
            self.confirmPasswordLineEdit.setStyleSheet(UserInterfaceFunctions.GetDefaultStyleSheetSettingsLineEdits('confirmPasswordLineEdit'))
            UserInterfaceFunctions.ShowPopup('Password Changed Successfullly', 'You\'r password has changed successfully.', 'Information')

    #--------------------------------------------SQL-RESULT-SLOTS-END--------------------------------------------#

#------------------------------------------------------NetSpect-CLASS-END-------------------------------------------------------#

#--------------------------------------------------------SNIFFING-THREAD--------------------------------------------------------#
# thread for sniffing packets in real time for gathering network flows
class Sniffing_Thread(QThread):
    # define signals for interacting with main gui thread
    updateTimerSignal = pyqtSignal(bool)
    updateArpListSignal = pyqtSignal(ARP_Packet)
    updatePortScanDosDictSignal = pyqtSignal(tuple, Default_Packet)
    updateDnsDictSignal = pyqtSignal(tuple, DNS_Packet)
    finishSignal = pyqtSignal(dict)

    # constructor of sniffing thread
    def __init__(self, parent=None, selectedInterface=None):
        super().__init__(parent)
        self.parent = parent #represents the main thread
        self.interface = selectedInterface #initialize the interface with selectedInterface
        self.sniffer = None #represents our sniffer scapy object for sniffing packets
        self.stopFlag = False #represents stop flag for indicating when to stop the sniffer
    

    # method for stopping sniffer thread
    @pyqtSlot()
    def StopThread(self):
        self.stopFlag = True #set stop flag
        # we check if sniffer is still running, if so we stop it
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop() #stop async sniffer
            self.quit() #exit main loop and end task
            self.wait() #we wait to ensure thread cleanup


    # method for checking when to stop sniffing packets, stop condition
    def StopScan(self, packet):
        return self.stopFlag #return state of stop flag


    # method for capturing specific packets for later analysis
    def PacketCapture(self, packet):
        captureDict = {TCP: self.handleTCP, UDP: self.handleUDP, DNS: self.handleDNS, ARP: self.handleARP} #represents dict with packet type and handler func
        # iterate over capture dict and find coresponding handler function for each packet
        for packetType, handler in captureDict.items():
            if packet.haslayer(packetType): #if we found matching packet we call its handle method
                handler(packet) #call handler method of each packet


    # run method for initialing a packet scan on desired network interface
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            #starting timer to determin when to initiate each attack defence
            self.updateTimerSignal.emit(True)

            # create scapy AsyncSniffer object with desired interface and sniff network packets asynchronously
            self.sniffer = AsyncSniffer(iface=self.interface, prn=self.PacketCapture, stop_filter=self.StopScan, store=0)
            self.sniffer.start() #start our async sniffing
            self.exec_() #execute sniffer process
        except PermissionError: #if user didn't run with administrative privileges
            stateDict.update({'state': False, 'message': 'Permission denied. Please run again with administrative privileges.'})
        except Exception as e: #we catch an exception if something happend while sniffing
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
        finally:
            self.updateTimerSignal.emit(False)
            self.finishSignal.emit(stateDict) #send finish signal to main thread


    #--------------------------------------------HANDLE-FUNCTIONS------------------------------------------------#

    # method that handles ARP packets
    def handleARP(self, packet):
        ARP_Object = ARP_Packet(packet) #create a new object for packet
        self.updateArpListSignal.emit(ARP_Object) #emit signal to update our arpList


    # method that handles TCP packets
    def handleTCP(self, packet):
        if packet.haslayer(DNS): #if we found a dns packet we also call dns handler
            self.handleDNS(packet) #call our handleDNS func
        TCP_Object = TCP_Packet(packet) #create a new object for packet
        flowTuple = TCP_Object.GetFlowTuple() #get flow representation of packet
        self.updatePortScanDosDictSignal.emit(flowTuple, TCP_Object) #emit signal to update our portScanDosDict


    # method that handles UDP packets
    def handleUDP(self, packet):
        if packet.haslayer(DNS): #if we found a dns packet we also call dns handler
            self.handleDNS(packet) #call our handleDNS func
        UDP_Object = UDP_Packet(packet) #create a new object for packet
        flowTuple = UDP_Object.GetFlowTuple() #get flow representation of packet
        self.updatePortScanDosDictSignal.emit(flowTuple, UDP_Object) #emit signal to update our portScanDosDict


    # method that handles DNS packets
    def handleDNS(self, packet):
        DNS_Object = DNS_Packet(packet) #create a new object for packet
        flowTuple = DNS_Object.GetFlowTuple() #get flow representation of packet
        self.updateDnsDictSignal.emit(flowTuple, DNS_Object) #emit signal to update our dnsDict

    #------------------------------------------HANDLE-FUNCTIONS-END----------------------------------------------#

#-----------------------------------------------------SNIFFING-THREAD-END-------------------------------------------------------#

#---------------------------------------------------------ARP-THREAD------------------------------------------------------------#
# thread for analyzing arp traffic and detecting arp spoofing attacks
class Arp_Thread(QThread):
    # define signals for interacting with main gui thread
    detectionResultSignal = pyqtSignal(dict)
    finishSignal = pyqtSignal(dict)

    # constructor of arp thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for indicating when we should end analysis
        self.arpBatch = None #represents arp list batch of packets for us to analyzie for anomalies
        self.mutex = QMutex() #shared mutex for thread safe operations with wait condition
        self.waitCondition = QWaitCondition() #wait condition for thread to wait for received packet batch from main thread
    

    # method for receiving arp batch from main thread
    @pyqtSlot(dict)
    def ReceiveArpBatch(self, arpList):
        with QMutexLocker(self.mutex):
            self.arpBatch = arpList #set our arp list batch received from main thread
            self.waitCondition.wakeAll() #wake thread and process arp batch


    # method for stopping arp thread
    @pyqtSlot()
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
    detectionResultSignal = pyqtSignal(dict)
    finishSignal = pyqtSignal(dict)

    # constructor of portScanDos thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for indicating when we should end analysis
        self.portScanDosBatch = None #represents portScanDos dict batch of packets for us to analyzie for anomalies
        self.mutex = QMutex() #shared mutex for thread safe operations with wait condition
        self.waitCondition = QWaitCondition() #wait condition for thread to wait for received packet batch from main thread
    

    # method for receiving portScanDos batch from main thread
    @pyqtSlot(dict)
    def ReceivePortScanDosBatch(self, portScanDosDict):
        with QMutexLocker(self.mutex):
            self.portScanDosBatch = portScanDosDict #set our portScanDos dict batch received from main thread
            self.waitCondition.wakeAll() #wake thread and process portScanDos batch


    # method for stopping portScanDos thread
    @pyqtSlot()
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
    detectionResultSignal = pyqtSignal(dict)
    finishSignal = pyqtSignal(dict)

    # constructor of dns thread
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent #represents main thread
        self.stopFlag = False #represents stop flag for indicating when we should end analysis
        self.dnsBatch = None #represents dns dict batch of packets for us to analyzie for anomalies
        self.mutex = QMutex() #shared mutex for thread safe operations with wait condition
        self.waitCondition = QWaitCondition() #wait condition for thread to wait for received packet batch from main thread
    

    # method for receiving dns batch from main thread
    @pyqtSlot(dict)
    def ReceiveDnsBatch(self, dnsDict):
        with QMutexLocker(self.mutex):
            self.dnsBatch = dnsDict #set our dns dict batch received from main thread
            self.waitCondition.wakeAll() #wake thread and process dns batch


    # method for stopping dns thread
    @pyqtSlot()
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
    updateProgressBarSignal = pyqtSignal(int)
    finishSignal = pyqtSignal(dict, bool)

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
    @pyqtSlot()
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
    finishSignal = pyqtSignal(dict)

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
    @pyqtSlot(dict)
    def ReceiveLog(self, logDict):
        with QMutexLocker(self.mutex):
            self.logQueue.append(logDict) #append log into log queue
            self.waitCondition.wakeAll() #wake thread and process dns batch


    # method for stopping logger thread
    @pyqtSlot()
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

#------------------------------------------------------------MAIN---------------------------------------------------------------#

if __name__ == '__main__':
    #start NetSpect application
    app = QApplication(sys.argv)
    netSpect = NetSpect()
    try:
        sys.exit(app.exec_())
    except:
        print('Exiting')