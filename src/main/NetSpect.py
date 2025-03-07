import sys, pyodbc
import InterfaceAnimations
from PyQt5.QtCore import QTimer, QRegExp, QThread, QMutex, QMutexLocker, QWaitCondition, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import QApplication, QDesktopWidget, QMainWindow
from PyQt5.uic import loadUi
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from datetime import timedelta
from MainFunctions import *

#--------------------------------------------------------NetSpect-CLASS---------------------------------------------------------#
# class that represents main app of NetSpect
class NetSpect(QMainWindow):
    dbConn = None #represents our database connection
    userId = None #represents user id
    isDetection = False #represents flag for indicating if detection is active
    totalTimer, arpTimer, portScanDosTimer, dnsTimer = None, None, None, None #represents timer for each thread for evaluating when to send data
    totalTimeout, arpTimeout, portScanDosTimout, dnsTimout = 1000, 40000, 40000, 40000 #represents timeout for each timer
    arpThreshold, portScanDosThreshold, dnsThreshold = 20, 10000, 350 #represents thresholds for each thread
    timeElapsed = timedelta() #initialize a timedelta object to track elapsed time
    arpList = [] #represents list of packets related to arp spoofing
    portScanDosDict = {} #represents dict of {(flow tuple) - [packet list]} related to port scanning and dos
    dnsDict = {} #represents dict of {(flow tuple) - [packet list]} related to dns tunneling
    arpCounter, tcpUdpCounter, dnsCounter = 0, 0, 0 #represents counters for our packet data structures for arp, portDos and dns
    snifferThread, arpThread, portScanDosThread, dnsThread = None, None, None, None #represents our worker threads for sniffing and detecting network cyber attacks
    arpMutex, portScanDosMutex, dnsMutex = QMutex(), QMutex(), QMutex() #represents mutex objects for thread safe operations on our dictionaries

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
        # self.dnsTimer.timeout.connect(self.SendDnsDict) #connect timeout event for dns timer

        # connect interface buttons to their methods
        self.startStopButton.clicked.connect(self.StartStopButtonClicked)

        # connect interface labels to their methods
        self.accountIcon.mousePressEvent = lambda event: InterfaceAnimations.AccountIconClicked(self)
        self.moveToRegisterLabel.mousePressEvent = lambda event: InterfaceAnimations.SwitchBetweenLoginAndRegister(self)
        self.moveToLoginLabel.mousePressEvent = lambda event: InterfaceAnimations.SwitchBetweenLoginAndRegister(self, False)
        self.menuIcon.mousePressEvent = lambda event: InterfaceAnimations.OpenSideFrame(self)
        self.closeMenuIcon.mousePressEvent = lambda event: InterfaceAnimations.CloseSideFrame(self)
        self.workstationIconHorizontalFrame.mousePressEvent = lambda event: InterfaceAnimations.ChangePageIndex(self, 0) #switch to Home Page
        self.reportIconHorizontalFrame.mousePressEvent = lambda event: InterfaceAnimations.ChangePageIndex(self, 1) #switch to Report Page
        self.infoIconHorizontalFrame.mousePressEvent = lambda event: InterfaceAnimations.ChangePageIndex(self, 2) #switch to Information Page
        self.settingsIcon.mousePressEvent = lambda event: InterfaceAnimations.ChangePageIndex(self, 3) #switch to Settings Page

        # connect comboboxes to their methods
        self.networkInterfaceComboBox.clear() #clear interfaces combobox
        self.networkInterfaceComboBox.addItems(NetworkInformation.InitNetworkInfo()) #intialize our interfaces combobox with host network info
        self.networkInterfaceComboBox.currentIndexChanged.connect(self.ChangeNetworkInterface) #connect interfaces combobox to its method
        self.ChangeNetworkInterface() #set default network interface from combobox 

        # initialize other interface components and show interface
        InterfaceAnimations.InitAnimationsUI(self) # setup left sidebar elements and login/register popup frame
        self.InitSystemInfo(NetworkInformation.GetSystemInformation()) #initialize the system information in the info page (machine name, version, etc.)
        self.InitValidators() #initialize the network information in the info page (interface name, mac address, ips, etc.)
        self.ChangeLoginRegisterErrorMessage() #reset the login popup error message
        self.ChangeLoginRegisterErrorMessage(isLogin=False) #reset the register popup error message
        # self.initDBConnection() #call init db method
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
        event.accept() #accept the close event


    # method for initializing database connection
    # def initDBConnection(self):
    #     self.dbConn = SQLHelper.GetDBConnection()
    #     if not self.dbConn:
    #         self.UpdateInfoLabel('Couldn\'t connect to database, try again later.')
    #         return False
    #     return True

    
    # method for setting input validators on line edits in gui
    def InitValidators(self):
        # create regex expressions and validators
        usernameValidator = QRegExpValidator(QRegExp('^[A-Za-z0-9]{4,16}$'))
        passwordValidator = QRegExpValidator(QRegExp('[A-Za-z\\d$&?@#|.^*()%!]{6,20}')) 
        finalPasswordPattern = '^(?=.*[A-Z])(?=.*\\d)[A-Za-z\\d$&?@#|.^*()%!]{6,20}$'
        emailValidator = QRegExpValidator(QRegExp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'))

        # set validaotrs for username, password and email line edits in the login and register popups
        self.loginUsernameLineEdit.setValidator(usernameValidator)
        self.loginPasswordLineEdit.setValidator(passwordValidator)
        self.registerEmailLineEdit.setValidator(emailValidator)
        self.registerUsernameLineEdit.setValidator(usernameValidator)
        self.registerPasswordLineEdit.setValidator(passwordValidator)

        # connect the textChanged signal to the function that checks validation, this adds borders to the line edits if the text does not match the regex
        self.loginUsernameLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEdit(self.loginUsernameLineEdit, 'loginUsernameLineEdit'))
        self.loginPasswordLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEdit(self.loginPasswordLineEdit, 'loginPasswordLineEdit'))
        self.registerEmailLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEdit(self.registerEmailLineEdit, 'registerEmailLineEdit'))
        self.registerUsernameLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEdit(self.registerUsernameLineEdit, 'registerUsernameLineEdit'))
        self.registerPasswordLineEdit.textChanged.connect(lambda : self.NotifyInvalidLineEdit(self.registerPasswordLineEdit, 'registerPasswordLineEdit'))


    # function to convert to bytes
    @staticmethod
    def ToByte(message):
        if isinstance(message, int):
            # convert and ensure a minimum of 1 byte to avoid issues with zero or small numbers
            return message.to_bytes((message.bit_length() + 7) // 8 or 1, 'big')
        elif isinstance(message, str):
            # convert the string to bytes using encode
            return message.encode()
        else:
            return message
        

    # function that returns sha-256 hash of given message
    @staticmethod
    def ToSHA256(message, toHex=False):
        if not isinstance(message, bytes): #ensure the message is byte array
            message = NetSpect.ToByte(message) #convert to string and then to bytes to ensure its bytes
        digest = Hash(SHA256()) #create a SHA256 hash object
        digest.update(message) #update the hash object with the message bytes
        return digest.finalize() if not toHex else digest.finalize().hex() #return sha-256 hash of message
    

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
    def NotifyInvalidLineEdit(self, lineEditWidget, lineEditName):
        currentStylesheet = f''' 
            #{lineEditName} {{
                background-color: #f0f0f0; 
                border: 2px solid lightgray;  
                border-radius: 10px;         
                padding: 5px;              
                font-size: 14px;            
                color: black;             
                {'margin: 0px 5px 0px 5px;' if ('Password' in lineEditName) else 'margin: 0px 5px 10px 5px;'}
            }}
        '''
        # set initial styles
        lineEditWidget.setStyleSheet(currentStylesheet)

        # check if the input matches the regex, if not update the border style to red (invalid input)
        if not lineEditWidget.hasAcceptableInput():
            lineEditWidget.setStyleSheet(currentStylesheet.replace('border: 2px solid lightgray;', 'border: 2px solid #D84F4F;'))


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
            print(arpPacket)

    
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
        # print(packet)


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
            #self.SendDnsDict() #call our method to send packets for analysis
        # print(dnsPacket)

    
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
                self.arpList = self.arpList[batchSize:] #remove the first batchSize packets from arp list

                # Send the extracted batch to the worker thread
                self.arpCounter -= len(arpBatch) #update arp counter
                self.arpThread.ReceiveArpBatch(arpBatch) #send batch to arp thread
                print('Sent Arp list for analysis..')


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
                print('Sent portScanDos dict for analysis..')


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
                print('Sent dns dict for analysis..')


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
            #! show message box
            print('Error')
    

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
            #! show message box
            print('Error')


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
            #! show message box
            print('Error')


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
            #! show message box
            print('Error')
    

    # method for analyzing detection result of arp spoofing attack
    @pyqtSlot(dict)
    def ArpDetectionResult(self, result):
        # we check if type is 3, means arp tables initialized
        if result.get('type') == 3:
            ArpSpoofing.isArpTables = True #set our initialized flag to true for arp detection
        if result.get('state') == False and result.get('attackDict'):
            #! show message box
            print('Detected Arp Spoofing!')
        print('No Arp Spoofing is present.')


    # method for analyzing detection result of port scan and dos attacks 
    @pyqtSlot(dict)
    def PortScanDosDetectionResult(self, result):
        if result.get('state') == False and result.get('attackDict'):
            #! show message box
            print('Detected Port Scan / Dos attack!')
        print('No Port Scan / Dos are present.')

    
    # method for analyzing detection result of dns tunneling attack
    @pyqtSlot(dict)
    def DnsDetectionResult(self, result):
        if result.get('state') == False and result.get('attackDict'):
            #! show message box
            print('Detected DNS Tunneling attack!')
        print('No DNS Tunneling is present.')


    # method for stopping detection and closing threads
    def StopDetection(self):
        if self.isDetection:
            # we check each thread and close it if running
            if self.snifferThread:
                self.snifferThread.SetStopFlag(True)
            if self.arpThread:
                self.arpThread.SetStopFlag(True)
            if self.portScanDosThread:
                self.portScanDosThread.SetStopFlag(True)
            # if self.dnsThread:
            #     self.dnsThread.SetStopFlag(True)
            print(f'updtcp: {self.tcpUdpCounter}, arp: {self.arpCounter}, dns: {self.dnsCounter}')
            self.arpCounter, self.tcpUdpCounter, self.dnsCounter = 0, 0, 0 #reset our counters
            self.arpList, self.portScanDosDict, self.dnsDict = [], {}, {} #reset our packet data structures


    # method for starting our threads and detect network cyber attacks in real time
    def StartDetection(self):
        if not self.snifferThread and not self.arpThread and not self.portScanDosThread and not self.dnsThread:
            self.isDetection = True #set flag to true indication we started a detection

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

            # # initialize dns thread for dns tunneling detection
            # self.dnsThread = Dns_Thread(self)
            # # connect relevant signals for portScanDos thread
            # self.dnsThread.detectionResultSignal.connect(self.DnsDetectionResult)
            # self.dnsThread.finishSignal.connect(self.CloseDnsThread)

            # start our threads for detection
            self.snifferThread.start()
            self.arpThread.start()
            self.portScanDosThread.start()
            # self.dnsThread.start()

        else:
            #! show message box
            print('One of the threads is still in process, cannot start new detection.')

    
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
    

    # method for updating state of stop flag
    @pyqtSlot(bool)
    def SetStopFlag(self, state):
        self.stopFlag = state #set stop flag
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
            print('Sniffer_Thread: Starting Network Scan...')
            #starting timer to determin when to initiate each attack defence
            self.updateTimerSignal.emit(True)

            # create scapy AsyncSniffer object with desired interface and sniff network packets asynchronously
            self.sniffer = AsyncSniffer(iface=self.interface, prn=self.PacketCapture, stop_filter=self.StopScan, store=0)
            self.sniffer.start() #start our async sniffing
            self.exec_() #execute sniffer process
        except PermissionError: #if user didn't run with administrative privileges
            stateDict.update({'state': False, 'message': 'Permission denied. Please run again with administrative privileges.'})
            print(f'Sniffer_Thread: {stateDict['message']}') #print permission error message in terminal
        except Exception as e: #we catch an exception if something happend while sniffing
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
            print(f'Sniffer_Thread: {stateDict['message']}') #print error message in terminal
        finally:
            self.updateTimerSignal.emit(False)
            self.finishSignal.emit(stateDict) #send finish signal to main thread
            print('Sniffer_Thread: Finsihed Network Scan.\n')


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


    # method for updating state of stop flag
    @pyqtSlot(bool)
    def SetStopFlag(self, state):
        self.stopFlag = state #set stop flag
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating arp traffic analysis and detecting arp spoofing
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            #initialize all of our static arp tables and check for arp spoofing presence
            result = ArpSpoofing.InitAllArpTables() #call our function to initialize arp tables
            self.detectionResultSignal.emit(result) #send result of arp initialization to main thread
            print('Arp_Thread: Initialized ARP tables successfully.')

            while not self.stopFlag:
                # wait until the batch is received
                self.mutex.lock()
                while self.arpBatch is None and not self.stopFlag:
                    self.waitCondition.wait(self.mutex) #wait until we receive the arp batch using wait condition
                if self.stopFlag: #if true we exit and finish threads work
                    self.mutex.unlock()
                    break

                # retrieve the arp list batch and reset for next iteration
                localArpList = self.arpBatch
                self.arpBatch = None
                self.mutex.unlock()

                # process the received arp list batch
                result = ArpSpoofing.ProcessARP(localArpList) #call our function for cheching arp traffic
                self.detectionResultSignal.emit(result) #send result of scan to main thread
                print('Arp_Thread: Sent result to main thread.')

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
            print(f'Arp_Thread: {stateDict['message']}') #print error message in terminal
        finally:
            self.finishSignal.emit(stateDict) #send finish signal to main thread
            print('Arp_Thread: Finsihed analysis of traffic.\n')

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


    # method for updating state of stop flag
    @pyqtSlot(bool)
    def SetStopFlag(self, state):
        self.stopFlag = state #set stop flag
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating tcp and udp traffic analysis and detecting port scan and dos attacks
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            while not self.stopFlag:
                # wait until the batch is received
                self.mutex.lock()
                while self.portScanDosBatch is None and not self.stopFlag:
                    self.waitCondition.wait(self.mutex) #wait until we receive the portScanDos batch using wait condition
                if self.stopFlag: #if true we exit and finish threads work
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
                print('PortScanDos_Thread: Sent result to main thread.')

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
            print(f'PortScanDos_Thread: {stateDict['message']}') #print error message in terminal
        finally:
            self.finishSignal.emit(stateDict) #send finish signal to main thread
            print('PortScanDos_Thread: Finsihed analysis of traffic.\n')

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


    # method for updating state of stop flag
    @pyqtSlot(bool)
    def SetStopFlag(self, state):
        self.stopFlag = state #set stop flag
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating dns traffic analysis and detecting dns tunneling attacks
    def run(self):
        stateDict = {'state': True, 'message': ''} #represents state of thread when finishes
        try:
            while not self.stopFlag:
                # wait until the batch is received
                self.mutex.lock()
                while self.dnsBatch is None and not self.stopFlag:
                    self.waitCondition.wait(self.mutex) #wait until we receive the dns batch using wait condition
                if self.stopFlag: #if true we exit and finish threads work
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
                print('Dns_Thread: Sent result to main thread.')

        except Exception as e: #we catch an exception if error occured
            stateDict.update({'state': False, 'message': f'An error occurred: {e}.'})
            print(f'Dns_Thread: {stateDict['message']}') #print error message in terminal
        finally:
            self.finishSignal.emit(stateDict) #send finish signal to main thread
            print('Dns_Thread: Finsihed analysis of traffic.\n')

#--------------------------------------------------------DNS-THREAD-END---------------------------------------------------------#

#------------------------------------------------------------MAIN---------------------------------------------------------------#

if __name__ == '__main__':
    #start NetSpect application
    app = QApplication(sys.argv)
    netSpect = NetSpect()
    try:
        sys.exit(app.exec_())
    except:
        print('Exiting')