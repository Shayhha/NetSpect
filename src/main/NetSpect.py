import sys, pyodbc
from PyQt5.QtCore import QTimer, QRegExp, QThread, QMutex, QMutexLocker, QWaitCondition, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import QApplication, QDesktopWidget, QMainWindow
from PyQt5.uic import loadUi
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from datetime import timedelta
from baseFunctions import *


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
        ui_file = r'C:\Users\shayh\Documents\Visual Studio Code\NetSpect\src\interface\NetSpect.ui' #!remember to fix this
        loadUi(ui_file, self) #load the ui file
        self.initUI() #call init method
        
    
    # method to initialize GUI methods and events
    def initUI(self):
        self.setWindowTitle('NetSpect') #set title of window
        self.totalTimer, self.arpTimer, self.portScanDosTimer, self.dnsTimer = QTimer(self), QTimer(self), QTimer(self), QTimer(self) #initailize our timers
        self.totalTimer.timeout.connect(self.UpdateRunningTimeCounterLabel) #connect timeout event for total timer
        self.arpTimer.timeout.connect(self.SendArpList) #connect timeout event for arp timer
        self.portScanDosTimer.timeout.connect(self.SendPortScanDosDict) #connect timeout event for portScanDos timer
        # self.dnsTimer.timeout.connect(self.SendDnsDict) #connect timeout event for dns timer
        self.startStopButton.clicked.connect(self.StartStopButtonClicked)
        NetworkInformation.InitNetworkInfo()
        NetworkInformation.selectedInterface = 'Ethernet'
        ArpSpoofing.InitAllArpTables(NetworkInformation.networkInfo.get(NetworkInformation.selectedInterface)) #initialize all of our static arp tables with subnets
        ArpSpoofing.printArpTables() #print static arp tables
        # self.CancelButton.clicked.connect(self.ShowMainWindow)
        # self.SubmitButton.clicked.connect(self.AddVoterToApp)
        # self.addVoterButton.clicked.connect(self.ShowVoterSubmit)
        # self.verifyButton.clicked.connect(self.VerifyVoter)
        # self.initValidators()
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
    def initValidators(self):
        # regex expressions for validation
        idRegex = QRegExp(r'^\d{9}$') #id must be 9 digits
        passRegex = QRegExp(r'^.{6,16}$') #password at least 6 characters
        infoRegex = QRegExp(r'^[A-Za-z\s]{2,20}$') #info at least 2 characters
        addressRegex = QRegExp(r'^[A-Za-z0-9\s,.-]{2,20}$') # address also includes special chars

        # set validaotrs for id and password in main screen
        self.idLineEdit.setValidator(QRegExpValidator(idRegex))
        self.passLineEdit.setValidator(QRegExpValidator(passRegex))
        # set validators for form in voter submit
        self.FirstNameLineEdit.setValidator(QRegExpValidator(infoRegex))
        self.LastNameLineEdit.setValidator(QRegExpValidator(infoRegex))
        self.AddressLineEdit.setValidator(QRegExpValidator(addressRegex))
        self.CityLineEdit.setValidator(QRegExpValidator(infoRegex))
        self.StateLineEdit.setValidator(QRegExpValidator(infoRegex))
        self.IdLineEdit.setValidator(QRegExpValidator(idRegex))
        self.PassLineEdit.setValidator(QRegExpValidator(passRegex))


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
    

    # method for updating running time label in gui
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

            # loop through the dict and try to get 10,000 packets if possible
            while self.portScanDosDict and totalPackets < 10000:
                emptyFlows = [] #we track empty flows for cleanup

                # iterate over each flow in dict
                for flow, packetList in self.portScanDosDict.items():
                    if totalPackets >= 10000: #means we have enough packets
                        break

                    if len(packetList) == 0: #means flow empty
                        emptyFlows.append(flow) #add flow to our emptyFlows dict for removal
                        continue

                    # calculate the batch size for each flow and add it to our batch
                    batchSize = min(10000 - totalPackets, len(packetList), 500) #max packets in each iteration is 500
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

            # loop through the dict and try to get 10,000 packets if possible
            while self.dnsDict and totalPackets < 10000:
                emptyFlows = [] #we track empty flows for cleanup

                # iterate over each flow in dict
                for flow, packetList in self.dnsDict.items():
                    if totalPackets >= 10000: #means we have enough packets
                        break

                    if len(packetList) == 0: #means flow empty
                        emptyFlows.append(flow) #add flow to our emptyFlows dict for removal
                        continue

                    # calculate the batch size for each flow and add it to our batch
                    batchSize = min(10000 - totalPackets, len(packetList), 500) #max packets in each iteration is 500
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
    @pyqtSlot(tuple)
    def CloseSnifferThread(self, state):
        self.snifferThread = None
        if not self.arpThread and not self.portScanDosThread and not self.dnsThread:
            self.isDetection = False
        if state[0] == False and state[1]:
            #! show message box
            print('Error')
    

    # method for closing arp thread and setting it back to none 
    @pyqtSlot(tuple)
    def CloseArpThread(self, state):
        self.arpThread = None
        if not self.snifferThread and not self.portScanDosThread and not self.dnsThread:
            self.isDetection = False
        if state[0] == False and state[1]:
            #! show message box
            print('Error')


    # method for closing portScanDos thread and setting it back to none 
    @pyqtSlot(tuple)
    def ClosePortScanDosThread(self, state):
        self.portScanDosThread = None
        if not self.snifferThread and not self.arpThread and not self.dnsThread:
            self.isDetection = False
        if state[0] == False and state[1]:
            #! show message box
            print('Error')


    # method for closing dns thread and setting it back to none 
    @pyqtSlot(tuple)
    def CloseDnsThread(self, state):
        self.DnsThread = None
        if not self.snifferThread and not self.arpThread and not self.portScanDosThread:
            self.isDetection = False
        if state[0] == False and state[1]:
            #! show message box
            print('Error')
    

    # method for analyzing detection result of arp spoofing attack
    @pyqtSlot(tuple)
    def ArpDetectionResult(self, result):
        if result[0] == False and result[1]:
            #! show message box
            print('Detected Arp Spoofing!')
        print('No Arp Spoofing is present.')

    # method for analyzing detection result of port scan and dos attacks 
    @pyqtSlot(tuple)
    def PortScanDosDetectionResult(self, result):
        if result[0] == False and result[1]:
            #! show message box
            print('Detected Port Scan / Dos attack!')
        print('No Port Scan / Dos are present.')

    
    # method for analyzing detection result of dns tunneling attack
    @pyqtSlot(tuple)
    def DnsDetectionResult(self, result):
        if result[0] == False and result[1]:
            #! show message box
            print('Detected DNS Tunneling attack!')
        print('No DNS Tunneling is present.')


    # method for stopping detection and closing threads
    def StopDetection(self):
        if self.isDetection:
            print(f'updtcp: {self.tcpUdpCounter}, arp: {self.arpCounter}, dns: {self.dnsCounter}')
            # we check each thread and close it ifs running
            if self.snifferThread:
                self.snifferThread.SetStopFlag(True)
            if self.arpThread:
                self.arpThread.SetStopFlag(True)
            if self.portScanDosThread:
                self.portScanDosThread.SetStopFlag(True)
            # if self.dnsThread:
            #     self.dnsThread.SetStopFlag(True)
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

            # # initialize portScanDos thread for dns tunneling detection
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
            print('One of the threads is still in process, cannot start new detection.')

    
    # method for startStop button for starting or stopping detection
    def StartStopButtonClicked(self):
        if self.startStopButton.text() == 'START':
            self.startStopButton.setText('STOP')
            stopStyleSheet = '''
                #startStopButton {
                    border-radius: 60px;
                    background-color: #D84F4F;
                    border: 1px solid black;
                    color: black;
                    font-weight: bold;
                }

                #startStopButton:hover {
                    background-color: #DB6060;
                }

                #startStopButton:pressed {
                    background-color: #AC3f3F;
                }
                '''
            self.startStopButton.setStyleSheet(stopStyleSheet)
            self.StartDetection()
        else:
            self.startStopButton.setText('START')
            startStyleSheet = '''
                #startStopButton {
                    border-radius: 60px;
                    background-color: #3A8E32;
                    border: 1px solid black;
                    color: black;
                    font-weight: bold;
                }

                #startStopButton:hover {
                    background-color: #4D9946;
                }

                #startStopButton:pressed {
                    background-color: #2E7128;
                }
                '''
            self.startStopButton.setStyleSheet(startStyleSheet)
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
    finishSignal = pyqtSignal(tuple)

    # constructor of sniffing thread
    def __init__(self, parent=None, selectedInterface=None):
        super().__init__(parent)
        self.parent = parent  #represents the main thread
        self.interface = selectedInterface  #initialize the interface with selectedInterface
        self.stopFlag = False  #represents stop flag for indicating when to end the sniffer
    

    # method for updating state of stop flag
    @pyqtSlot(bool)
    def SetStopFlag(self, state):
        self.stopFlag = state


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
        state = (True, '') #represents state of thread when finishes
        try:
            print('Sniffer_Thread: Starting Network Scan...')
            #starting timer to determin when to initiate each attack defence
            self.updateTimerSignal.emit(True)

            # call scapy sniff function with desired interface and sniff network packets
            sniff(iface=self.interface, prn=self.PacketCapture, stop_filter=self.StopScan, store=0)
        except PermissionError: #if user didn't run with administrative privileges
            state = (False, 'Permission denied. Please run again with administrative privileges.')
            print(f'Sniffer_Thread: {state[1]}') #print permission error message in terminal
        except Exception as e: #we catch an exception if something happend while sniffing
            state = (False, f'An error occurred while sniffing: {e}.')
            print(f'Sniffer_Thread: {state[1]}') #print error message in terminal
        finally:
            self.updateTimerSignal.emit(False)
            self.finishSignal.emit(state) #send finish signal to main thread
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
    detectionResultSignal = pyqtSignal(tuple)
    finishSignal = pyqtSignal(tuple)

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
        self.stopFlag = state
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating arp traffic analysis and detecting arp spoofing
    def run(self):
        state = (True, '') #represents state of thread when finishes
        try:
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
                print('Sent result to main thread - Arp')

        except Exception as e: #we catch an exception if error occured
            state = (False, f'An error occurred while sniffing: {e}.')
            print(f'Arp_Thread: {state[1]}') #print error message in terminal
        finally:
            self.finishSignal.emit(state) #send finish signal to main thread
            print('Arp_Thread: Finsihed analysis of traffic.\n')

#--------------------------------------------------------ARP-THREAD-END---------------------------------------------------------#

#------------------------------------------------------PortScanDos-THREAD-------------------------------------------------------#
# thread for analyzing tcp and udp traffic and detecting port scanning and dos attacks
class PortScanDos_Thread(QThread):
    # define signals for interacting with main gui thread
    detectionResultSignal = pyqtSignal(tuple)
    finishSignal = pyqtSignal(tuple)

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
        self.stopFlag = state
        with QMutexLocker(self.mutex):
            self.waitCondition.wakeAll() #wake thread and finish work


    # run method for initiating tcp and udp traffic analysis and detecting port scan and dos attacks
    def run(self):
        state = (True, '') #represents state of thread when finishes
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
                print('Sent result to main thread - portDos')

        except Exception as e: #we catch an exception if error occured
            state = (False, f'An error occurred while sniffing: {e}.')
            print(f'PortScanDos_Thread: {state[1]}') #print error message in terminal
        finally:
            self.finishSignal.emit(state) #send finish signal to main thread
            print('PortScanDos_Thread: Finsihed analysis of traffic.\n')

#-----------------------------------------------------PortScanDos-THREAD-END----------------------------------------------------#

#------------------------------------------------------------MAIN---------------------------------------------------------------#

if __name__ == '__main__':
    #start NetSpect application
    app = QApplication(sys.argv)
    netSpect = NetSpect()
    try:
        sys.exit(app.exec_())
    except:
        print('Exiting')