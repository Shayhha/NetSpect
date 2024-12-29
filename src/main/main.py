import sys, os, re, logging, socket, joblib, time
import numpy as np
import pandas as pd
from abc import ABC, abstractmethod
import scapy.all as scapy
from scapy.all import sniff, get_if_list, srp, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, Raw
from scapy.layers.dns import DNS
from collections import defaultdict

# dynamically add the src directory to sys.path, this allows us to access all moduls in the project at run time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from src.models import getModelPath

#----------------------------------------------Default_Packet------------------------------------------------#
# abstarct class for default packet
class Default_Packet(ABC):
    protocol = None #represents the packet protocol (TCP, UDP, etc)
    packet = None #represents the packet object itself for our use later
    packetType = None #represents the packet type based on scapy known types
    srcIp = None #represents source ip of packet 
    dstIp = None #represents destination ip of packet
    srcPort = None #represents source port of packet 
    dstPort = None #represents destination port of packet
    ipParam = None #represents IPv4 / IPv6 fields as tuple (ttl, dscp) / (hopLimit, trafficClass)
    packetLen = None #size of packet (including headers)
    payloadLen = None #size of packet (without headers)
    ipHeaderLen = None #size of ip header
    ipFlagDict = {} #represents ip flags
    time = None #timestamp of packet

    # constructor for default packet 
    def __init__(self, protocol=None, packet=None):
        self.protocol = protocol
        self.packet = packet
        self.packetLen = len(self.packet)
        self.payloadLen = len(self.packet[Raw].load) if Raw in self.packet else 0
        self.time = packet.time
        self.IpInfo() #initialize ip info


    # method for ip configuration capture
    def IpInfo(self): 
        if self.packet.haslayer(TCP) or self.packet.haslayer(UDP): #if packet is TCP or UDP it has port
            self.srcPort = self.packet.sport #set source port
            self.dstPort = self.packet.dport #set destination port
        if self.packet.haslayer(IP): #if packet has ip layer
            self.srcIp = self.packet[IP].src #represents the source ip
            self.dstIp = self.packet[IP].dst #represents the destination ip
            ttl = self.packet[IP].ttl #represents ttl parameter in packet
            dscp = self.packet[IP].tos #represents dscp parameter in packet
            self.ipParam = (ttl, dscp) #save both as tuple
            self.ipHeaderLen = len(self.packet[IP]) #save size of ip header
            # we extract the binary number that represents the ipv4 flags
            ipFlags = self.packet[IP].flags #represents flags of ip
            self.ipFlagDict = {
                'RB': (ipFlags & 0x1) != 0, #Reserved Bit flag
                'DF': (ipFlags & 0x2) != 0, #Don't Fragment flag
                'MF': (ipFlags & 0x4) != 0, #More Fragments flag
            }
        elif self.packet.haslayer(IPv6): #if packet has ipv6 layer
            self.srcIp = self.packet[IPv6].src #represents the source ip
            self.dstIp = self.packet[IPv6].dst #represents the destination ip
            hopLimit = self.packet[IPv6].hlim #represents the hop limit parameter in packet
            trafficClass = self.packet[IPv6].tc #represnets the traffic class in packet
            self.ipParam = (hopLimit, trafficClass) #save both as tuple
            self.ipHeaderLen = len(self.packet[IPv6]) #save size of ip header


    # method to return a normalized flow representation of a packet
    def GetFlowTuple(self):
        global networkInfo # tuple (ipAddresses, subnet)
        # extract flow tuple from packet
        srcIp, dstIp, protocol = self.srcIp, self.dstIp, self.protocol

        #we create the flow tuple based on lexicographic order if it does not contain host ip address to ensure consistency
        if dstIp in networkInfo[0]: #check if dst ip is our ip address
            return (srcIp, dstIp, protocol) #return the flow tuple of packet with host ip as dst ip in tuple

        elif (srcIp in networkInfo[0]) or (srcIp > dstIp): #check if tuple src ip is our ip address or if its not normalized 
            return (dstIp, srcIp, protocol) #return tuple in normalized order and also ensure that our ip is dst ip in flow

        return (srcIp, dstIp, protocol) #return the flow tuple of packet

#--------------------------------------------Default_Packet-END----------------------------------------------#

#----------------------------------------------------TCP-----------------------------------------------------#
class TCP_Packet(Default_Packet):
    srcPort = None
    dstPort = None
    seqNum = None
    ackNum = None
    windowSize = None
    flagDict = {}
    optionDict = {}

    # constructor for TCP packet 
    def __init__(self, packet=None):
        super().__init__('TCP', packet) #call parent ctor
        if packet.haslayer(TCP): #checks if packet is TCP
            self.packetType = TCP #specify the packet type
        self.InitTCP() #call method to initialize tcp specific params


    # method for TCP packet information
    def InitTCP(self): 
        if self.packet.haslayer(TCP):
            self.seqNum = self.packet.seq #add sequence number 
            self.ackNum = self.packet.ack #add acknowledgment number 
            self.windowSize = self.packet.window #add window size 

            #TCP has flags, we extract the binary number that represents the flags
            flags = self.packet[self.packetType].flags
            self.flagDict = { #we add to a dictionary all the flags of tcp
                'FIN': (flags & 0x01) != 0, #we extract FIN flag with '&' operator with 0x01(0001 in binary)
                'SYN': (flags & 0x02) != 0, #we extract SYS flag with '&' operator with 0x02(0010 in binary)
                'RST': (flags & 0x04) != 0, #we extract RST flag with '&' operator with 0x04(0100 in binary)
                'PSH': (flags & 0x08) != 0, #we extract PSH flag with '&' operator with 0x08(1000 in binary)
                'ACK': (flags & 0x10) != 0, #we extract ACK flag with '&' operator with 0x10(0001 0000 in binary)
                'URG': (flags & 0x20) != 0, #we extract URG flag with '&' operator with 0x20(0010 0000 in binary)
            }
            
            #add TCP Options (if available)
            if self.packet[self.packetType].options:
                self.optionDict = {} #initialize an empty dictionary to store TCP options
                for option in self.packet[self.packetType].options: #iterate over the options list
                    optionType = option[0]
                    optionValue = option[1]
                    self.optionDict[optionType] = optionValue #add option type with its matcing value to optionDict

#---------------------------------------------------TCP-END--------------------------------------------------#

#-----------------------------------------------------UDP----------------------------------------------------#
class UDP_Packet(Default_Packet):
    def __init__(self, packet=None): #ctor 
        super().__init__('UDP', packet) #call parent ctor
        if packet.haslayer(UDP): #checks if packet is UDP
            self.packetType = UDP #add packet type

#---------------------------------------------------UDP-END--------------------------------------------------#

#----------------------------------------------------DNS-----------------------------------------------------#
class DNS_Packet(Default_Packet):
    dnsId = None
    dnsType = None
    dnsSubType = None
    dnsClass = None
    dnsDomainName = None
    dnsNumOfReqOrRes = None
    dnsData = None

    def __init__(self, packet=None, dnsId=None):
        super().__init__('DNS', packet) #call parent ctor
        if packet.haslayer(DNS): #checks if packet is DNS
            self.packetType = DNS #add packet type
        self.dnsId = dnsId
        self.InitDNS() #call method to initialize dns specific params

    #method for packet information
    def InitDNS(self):
        if self.packet.haslayer(DNS): #if packet has DNS layer
            dnsPacket = self.packet[DNS] #save the dns packet in parameter
            if dnsPacket.qr == 1: #means its a response packet
                if dnsPacket.an: #if dns packet is response packet
                    self.dnsType = 'Response' #add type of packet to output
                    self.dnsDomainName = dnsPacket.an.rrname #add repsonse name 
                    self.dnsSubType = dnsPacket.an.type  #add response type 
                    self.dnsClass = dnsPacket.an.rclass #add response class 
                    self.dnsNumOfReqOrRes = len(dnsPacket.an) #add number of responses 
                    if hasattr(dnsPacket.an, 'rdata'): #check if rdata attribute exists
                        self.dnsData = dnsPacket.an.rdata #specify the rdata parameter
            else: #means its a request packet
                if dnsPacket.qd:
                    self.dnsType = 'Request' #add type of packet to output
                    self.dnsDomainName = dnsPacket.qd.qname #add request name to output
                    self.dnsSubType = dnsPacket.qd.qtype #add request type to output
                    self.dnsClass = dnsPacket.qd.qclass #add request class to output
                    self.dnsNumOfReqOrRes = len(dnsPacket.qd) #add num of requests to output
    
#--------------------------------------------------DNS-END---------------------------------------------------#

# ---------------------------------------------------ARP-----------------------------------------------------#
class ARP_Packet(Default_Packet):
    arpId = None
    srcMac = None
    dstMac = None
    arpType = None
    hwType = None
    pType = None
    hwLen = None
    pLen = None

    def __init__(self, packet=None, arpId=None):
        super().__init__('ARP', packet) #call parent ctor
        if packet.haslayer(ARP): #checks if packet is arp
            self.packetType = ARP #add packet type
        self.arpId = arpId
        self.InitARP() #call method to initialize arp specific params

    # method for ARP packet information
    def InitARP(self):
        if self.packet.haslayer(ARP): #if packet has layer of arp
            self.srcMac = self.packet[ARP].hwsrc #add arp source mac address
            self.dstMac = self.packet[ARP].hwdst #add arp destination mac address
            self.srcIp = self.packet[ARP].psrc #add arp source ip address
            self.dstIp = self.packet[ARP].pdst #add arp destination ip address
            self.arpType = 'Request' if self.packet[ARP].op == 1 else 'Reply' #add the arp type
            self.hwType = self.packet[ARP].hwtype #add the hardware type
            self.pType = self.packet[ARP].ptype #add protocol type to output
            self.hwLen = self.packet[ARP].hwlen #add hardware length to output
            self.pLen = self.packet[ARP].plen #add protocol length to output

#--------------------------------------------------ARP-END---------------------------------------------------#

#--------------------------------------------GLOBAL-PARAMETERS-----------------------------------------------#

networkInfo = (set(), None) #represents tuple of all ipv4 and ipv6 addresses and also host subnet (ipAddresses, subnet)
arpTable = ({}, {}) #represents ARP table that is a tuple (arpTable, invArpTable) with mapping of IP->MAC and MAC->IP in each table in tuple
flowDict = {} #represents dict of {(flow tuple) - [packet list]} related to port scanning and dos
dnsDict = {} #represents dict of packets related to dns tunneling 
arpDict = {} #represents dict of packets related to arp poisoning
dnsCounter = 0 #global counter for dns packets
arpCounter = 0 #global counter for arp packets
tempcounter = 0 #global counter for tcp and udp packets
startTime = None #global variable to capture the start time of the scan
timeoutTime = 40 #global variable that indicates when to stop the scan
threshold = 10000 #global variable the indicates when to stop scanning tcp and udp packets
selectedColumns = [
    'Number of Ports', 'Average Packet Size', 'Packet Length Min', 'Packet Length Max', 
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'Total Length of Fwd Packet', 
    'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Bwd Packet Length Max', 'Bwd Packet Length Mean', 
    'Bwd Packet Length Min', 'Bwd Packet Length Std', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg', 
    'Subflow Fwd Bytes', 'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count', 'Flow Duration', 
    'Packets Per Second', 'IAT Total', 'IAT Max', 'IAT Mean', 'IAT Std'
]

#------------------------------------------GLOBAL-PARAMETERS-END---------------------------------------------#

#--------------------------------------------HANDLE-FUNCTIONS------------------------------------------------#

#method that handles TCP packets
def handleTCP(packet):
    if packet.haslayer(DNS): #if we found a dns packet we also call dns handler
        handleDNS(packet) #call our handleDNS func
    TCP_Object = TCP_Packet(packet) #create a new object for packet
    flowTuple = TCP_Object.GetFlowTuple() #get flow representation of packet
    if flowTuple in flowDict: #if flow tuple exists in dict
        flowDict[flowTuple].append(TCP_Object) #append to list our packet
    else: #else we create new entry with flow tuple
        flowDict[flowTuple] = [TCP_Object] #create new list with packet
    global tempcounter #temporary
    tempcounter += 1


#method that handles UDP packets
def handleUDP(packet):
    if packet.haslayer(DNS): #if we found a dns packet we also call dns handler
        handleDNS(packet) #call our handleDNS func
    UDP_Object = UDP_Packet(packet) #create a new object for packet
    flowTuple = UDP_Object.GetFlowTuple() #get flow representation of packet
    if flowTuple in flowDict: #if flow tuple exists in dict
        flowDict[flowTuple].append(UDP_Object) #append to list our packet
    else: #else we create new entry with flow tuple
        flowDict[flowTuple] = [UDP_Object] #create new list with packet
    global tempcounter #temporary
    tempcounter += 1


#method that handles DNS packets
def handleDNS(packet):
    # DNS_Object = DNS_Packet(packet, dnsCounter) #create a new object for packet
    # dnsDict[DNS_Object.dnsId] = DNS_Object #insert it to packet dictionary
    DNS_Object = DNS_Packet(packet) #create a new object for packet
    flowTuple = DNS_Object.GetFlowTuple() #get flow representation of packet
    if flowTuple in dnsDict: #if flow tuple exists in dict
        dnsDict[flowTuple].append(DNS_Object) #append to list our packet
    else: #else we create new entry with flow tuple
        dnsDict[flowTuple] = [DNS_Object] #create new list with packet
    global dnsCounter
    dnsCounter += 1


#method that handles ARP packets
def handleARP(packet):
    global arpCounter
    ARP_Object = ARP_Packet(packet, arpCounter) #create a new object for packet
    arpDict[ARP_Object.arpId] = ARP_Object #insert it to packet dictionary
    arpCounter += 1 #increase the counter

#------------------------------------------HANDLE-FUNCTIONS-END----------------------------------------------#

#--------------------------------------------HELPER-FUNCTIONS------------------------------------------------#

#method to print all available interfaces
def GetAvailableInterfaces():
    #get a list of all available network interfaces
    interfaces = get_if_list() #call get_if_list method to retrieve the available interfaces
    if interfaces: #if there are interfaces we print them
        print('Available network interfaces:')
        i = 1 #counter for the interfaces 
        for interface in interfaces: #print all availabe interfaces
            if sys.platform.startswith('win32'): #if ran on windows we convert the guid number
                print(f'{i}. {GuidToStr(interface)}')
            else: #else we are on other os so we print the interface 
                print(f'{i}. {interface}')
            i += 1
    else: #else no interfaces were found
        print('No network interfaces found.')


#method for retrieving interface name from GUID number (Windows only)
def GuidToStr(guid):
    try: #we try to import the specific windows method from scapy library
        from scapy.arch.windows import get_windows_if_list
    except ImportError as e: #we catch an import error if occurred
        print(f'Error importing module: {e}') #print the error
        return None #we exit the function
    interfaces = get_windows_if_list() #use the windows method to get list of guid number interfaces
    for interface in interfaces: #iterating over the list of interfaces
        if interface['guid'] == guid: #we find the matching guid number interface
            return interface['name'] #return the name of the interface associated with guid number
    return None #else we didnt find the guid number so we return none


#method for retrieving the network interfaces
def GetNetworkInterfaces():
    networkNames = ['eth', 'wlan', 'en', 'Ethernet', 'Wi-Fi'] #this list represents the usual network interfaces that are available in various platfroms
    interfaces = get_if_list() #get a list of the network interfaces
    if sys.platform.startswith('win32'): #if current os is Windows we convert the guid number to interface name
        temp = [GuidToStr(interface) for interface in interfaces if GuidToStr(interface) is not None] #get a new list of network interfaces with correct names instead of guid numbers
        interfaces = temp #assign the new list to our interfaces variable
    matchedInterfaces = [interface for interface in interfaces if any(interface.startswith(name) for name in networkNames)] #we filter the list to retrieving ethernet and wifi interfaces
    return matchedInterfaces #return the matched interfaces as list'


# function that finds all ipv4 and ipv6 addresses of host and returns tuple of ip's and subnet
def GetNetworkInfo():
    hostname = socket.gethostname() #represents host name
    hostAddresses = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC) #represents host's known network addresses
    addresses = set() #represents set of all known ip addresses of host
    subnet = None #repreents our subnet in network

    # iterate over host addresses list and find all ipv4 and ipv6 addresses
    for address in hostAddresses:
        ip = address[4][0] #get ipv4/ipv6 address
        # check if IPv4 address and not loopback and save subnet
        if subnet == None and '.' in ip and not ip.startswith('127.'):
            subnet = f'{'.'.join(ip.split('.')[:3])}.0/24' #save our subnet for later use
        addresses.add(ip) #appand address to our set
    return addresses, subnet

#-------------------------------------------HELPER-FUNCTIONS-END---------------------------------------------#

#---------------------------------------------SNIFF-FUNCTIONS------------------------------------------------#

# function for checking when to stop sniffing packets, stop condition
def StopScan(packet):
    global start_time, timeoutTime, threshold
    return True if ( ((time.time() - start_time) > timeoutTime) or (tempcounter >= threshold) ) else False


# function for capturing specific packets for later analysis
def PacketCapture(packet):
    captureDict = {TCP: handleTCP, UDP: handleUDP, DNS: handleDNS, ARP: handleARP} #represents dict with packet type and handler func

    # iterate over capture dict and find coresponding handler function for each packet
    for packetType, handler in captureDict.items():
        if packet.haslayer(packetType): #if we found matching packet we call its handle method
            handler(packet) #call handler method of each packet


# function for initialing a packet scan on desired network interface
def ScanNetwork(interface):
    global networkInfo
    global arpTable
    try:
        print('Starting Network Scan...')
        networkInfo = GetNetworkInfo() #initialize our ip addresses set and subnet
        # arpTable = InitArpTable(networkInfo[1]) #initialize our static arp table with subnet

        print(networkInfo) #print host ip addresses
        #print arp table
        # print('ARP Table:')
        # for key, value in arpTable[0].items():
        #     print(f'IP: {key} --> MAC: {value}')
        # print('============================\n')

        global start_time #starting a timer to determin when to stop the sniffer
        start_time = time.time()

        #we call sniff with desired interface 
        sniff(iface=interface, prn=PacketCapture, stop_filter=StopScan, store=0)
    except PermissionError: #if user didn't run with administrative privileges 
        print('Permission denied. Please run again with administrative privileges.') #print permission error message in terminal
    except ArpSpoofingException as e: #if we recived ArpSpoofingException we alert the user
        print(e)
    except Exception as e: #we catch an exception if something happend while sniffing
        print(f'An error occurred while sniffing: {e}') #print error message in terminal
    finally:
        print('Finsihed Network Scan.\n')

#--------------------------------------------SNIFF-FUNCTIONS-END---------------------------------------------#

#-----------------------------------------------ARP-SPOOFING-------------------------------------------------#
class ArpSpoofingException(Exception):
    def __init__(self, message, state, details):
        super().__init__(message)
        self.state = state #represents the state of attack, 1 means we found ip assigned to many macs, 2 means mac assigned to many ips
        self.details = details #represents additional details about the spoofing

    # str representation of arp spoofing exception for showing results
    def __str__(self):
        detailsList = '\n##### ARP SPOOFING ATTACK ######\n'
        detailsList += '\n'.join([f'[*] {key} ==> {", ".join(value)}' for key, value in self.details.items()])
        return f'{self.args[0]}\nDetails:\n{detailsList}\n'


# fucntion that initializes the static arp table for testing IP-MAC pairs 
def InitArpTable(ipRange='192.168.1.0/24'):
    arpTable = {} #represents our arp table dict (ip to mac)
    invArpTable = {} #represents our inverse (mac to ip), used for verification
    attacksDict = {'ipToMac': {}, 'macToIp': {}} #represents attack dict with anomalies
    arpRequest = ARP(pdst=ipRange) #create arp request packet with destination ip range
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')  #create broadcast ethernet frame broadcast
    arpRequestBroadcast = broadcast / arpRequest #combine both arp request and ethernet frame 
     
    # send the ARP request and capture the responses
    # srp function retunes tuple (response packet, received device)
    answeredList = srp(arpRequestBroadcast, timeout=1, verbose=False)[0]
    
    # iterate over all devices that answered to our arp request packet and add them to our table
    for device in answeredList:
        ip, mac = device[1].psrc, device[1].hwsrc #represents ip and mac for given device

        # add ip mac pair to arp table
        if ip not in arpTable: #means ip not in arp table, we add it with its mac address
            arpTable[ip] = mac #set the mac address in ip index
        elif arpTable[ip] != mac: #else mac do not match with known mac in ip index
            attacksDict['ipToMac'].setdefault(ip, set()).update([arpTable[ip], mac]) #add an anomaly: same IP, different MAC

        # add mac ip pair to inverse arp table
        if mac not in invArpTable: #means mac not in inv arp table, we add it with its ip address
            invArpTable[mac] = ip #set the ip address in mac index
        #! remeber that locally shay's arp table is spoofed... (20:1e:88:d8:3a:ce)
        elif invArpTable[mac] != ip and mac != '20:1e:88:d8:3a:ce': #else ip do not match with known ip in mac index
            attacksDict['macToIp'].setdefault(mac, set()).update([invArpTable[mac], ip]) #add an anomaly: same MAC, different IP

    #we check if one of the attack dicts is not empty, means we have an attack
    if attacksDict['ipToMac']: #means we have an ip that has many macs
        #throw an exeption to inform user of its presence
        raise ArpSpoofingException(
            'Detected ARP spoofing incidents: IP-to-MAC anomalies',
            state=1,
            details={ip: list(macs) for ip, macs in attacksDict['ipToMac'].items()}
        )
    elif attacksDict['macToIp']: #means we have a mac that has many ips
        #throw an exeption to inform user of its presence
        raise ArpSpoofingException(
            'Detected ARP spoofing incidents: MAC-to-IP anomalies',
            state=2,
            details={mac: list(ips) for mac, ips in attacksDict['macToIp'].items()}
        )
        
    return arpTable, invArpTable


# function for processing arp packets and check for arp spoofing attacks
def ProcessARP():
    global arpTable
    attacksDict = {} #represents attack dict with anomalies
    try:
        if not arpTable[0]: #check that arpTable is initialzied
            raise RuntimeError('Error, cannot process ARP packets, ARP table is not initalized.')

        # iterate over our arp dictionary and check each packet for inconsistencies
        for packet in arpDict.values():
            # we check that packet has a source ip and also that its not assinged to a temporary ip (0.0.0.0)
            if isinstance(packet, ARP_Packet) and packet.srcIp != None and packet.srcIp != '0.0.0.0':
                if packet.srcIp not in arpTable[0]: #means ip is not present in our arp table
                    # means mac was assinged to different ip, we assume there's a possiblility 
                    # that this device got assigned a new ip from dhcp server
                    if packet.srcMac in arpTable[1]:
                        oldIp = arpTable[1][packet.srcMac] #save old ip that was assigned to this mac
                        del arpTable[0][oldIp] #remove old ip entry from arp table
                        del arpTable[1][packet.srcMac] #remove mac from inverse arp table

                    # we create new temp arp table to check if we got valid response from only one device and that mac's match
                    ipArpTable = InitArpTable(packet.srcIp) #initialize temp ip arp table for specific ip and check if valid
                    if ipArpTable[0]: #we check if there's a reply, if not we dismiss the packet
                        if ipArpTable[0][packet.srcIp] == packet.srcMac: #means macs match, valid 
                            arpTable[0][packet.srcIp] = packet.srcMac #assign the mac address to its ip in our arp table
                        else: #means macs dont match, we alret because differnet device asnwered us
                            ip, macs = packet.srcIp, {ipArpTable[0][packet.srcIp], packet.srcMac} #create the details for exception
                            attacksDict.setdefault(ip, set()).update(macs) #add an anomaly: same IP, different MAC

                else: #means ip is present in our arp table, we check its parameters
                    if arpTable[0][packet.srcIp] != packet.srcMac: #means we have a spoofed mac address
                        ip, macs = packet.srcIp, {arpTable[0][packet.srcIp], packet.srcMac} #create the details for exception
                        attacksDict.setdefault(ip, set()).update(macs) #add an anomaly: same IP, different MAC
        
        if attacksDict: #means we detected an attack
            #throw an exeption to inform user of its presence
            raise ArpSpoofingException(
                'Detected ARP spoofing incidents: IP-to-MAC anomalies',
                state=1,
                details={ip: list(macs) for ip, macs in attacksDict.items()}
            )

    except ArpSpoofingException as e: #if we recived ArpSpoofingException we alert the user
        print(e)
    except Exception as e: #we catch an exception if something happend
        print(f'Error occurred: {e}')
                
#----------------------------------------------ARP-SPOOFING-END----------------------------------------------#

#----------------------------------------------PORT-SCANNING-DoS---------------------------------------------#
class PortScanDoSException(Exception):
    def __init__(self, message, state, flows):
        super().__init__(message)
        self.state = state #represents the state of attack, 1 means we detected PortScan attack, 2 means we detected DoS attack
        self.flows = flows #represents the flow in which the attack was detected

    # str representation of port scan and dos exception for showing results
    def __str__(self):
        attackName = 'PortScan' if self.state == 1 else 'DoS'
        if self.state == 3:
            attackName = 'PortScan and DoS' 

        detailsList = f'\n##### {attackName.upper()} ATTACK ######\n'
        detailsList += '\n'.join([f'[*] Source IP: {flow['Src IP']} , Destination IP: {flow['Dst IP']} , Protocol: {flow['Protocol']} , Attack: {attackName}' for flow in self.flows])
        return f'{self.args[0]}\nDetails:\n{detailsList}\n'
    

# function for processing the flowDict and creating the dataframe that will be passed to classifier
def ProcessFlows(flowDict):
    featuresDict = defaultdict(dict) #represents our features dict where each flow tuple has its corresponding features

    # iterate over our flow dict and calculate features
    for flow, packetList in flowDict.items():
        numOfPorts = 0 #represents number of unique destination ports we found in given flow
        uniquePorts = set() #represents the unique destination ports in flow
        fwdLengths = [] #represents length of forward packets in flow
        bwdLengths = [] #represents length of backward packets in flow
        payloadLengths = [] #represents payload length of all packets in flow
        timestamps = [] #represents timestamps of each packet in flow
        subflowLastPacketTS, subflowCount = -1, 0 #last timestamp of the subflow and the counter of subflows
        synFlags, ackFlags, rstFlags = 0, 0, 0 #counter for tcp flags
        firstSeenPacket, lastSeenPacket = 0, 0 #represnts timestemps for first and last packets

        # iterate over each packet in flow
        for packet in packetList:
            payloadLengths.append(packet.payloadLen) #append payload length to list

            # append each packet timestemp to out list for IAT
            if packet.time:
                timestamps.append(packet.time)
            
                # for calculating flow duration
                if firstSeenPacket == 0:
                    firstSeenPacket = packet.time
                lastSeenPacket = packet.time

            # check if packet is tcp and calculate its specific parameters
            if isinstance(packet, TCP_Packet):
                # check each flag in tcp and increment counter if set
                if 'SYN' in packet.flagDict and packet.flagDict['SYN']:
                    synFlags += 1
                if 'ACK' in packet.flagDict and packet.flagDict['ACK']:
                    ackFlags += 1
                if 'RST' in packet.flagDict and packet.flagDict['RST']:
                    rstFlags += 1

            if packet.srcIp == flow[0]: #means forward packet
                fwdLengths.append(packet.payloadLen)

                # check for unique destination ports and add it if new port
                if packet.dstPort not in uniquePorts:
                    uniquePorts.add(packet.dstPort) #add the port to the set
                    numOfPorts += 1 #increment the counter for unique ports
                
                # count subflows in forward packets using counters and timestamps
                if subflowLastPacketTS == -1:
                    subflowLastPacketTS = packet.time
                if (packet.time - subflowLastPacketTS) > 1.0: #check that timestamp difference is greater than 1 sec
                    subflowCount += 1

            else: #else means backward packets
                bwdLengths.append(packet.payloadLen)


        # inter-arrival time features (IAT) and flow duration
        interArrivalTimes = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
        flowDuration = lastSeenPacket - firstSeenPacket

        # calculate the value dictionary for the current flow and insert it into the featuresDict
        flowParametes = {
            'Number of Ports': numOfPorts,
            'Average Packet Size': np.mean(payloadLengths) if payloadLengths else 0,
            'Packet Length Min': np.min(payloadLengths) if payloadLengths else 0, # packet length features
            'Packet Length Max': np.max(payloadLengths) if payloadLengths else 0,
            'Packet Length Mean': np.mean(payloadLengths) if payloadLengths else 0,
            'Packet Length Std': np.std(payloadLengths) if payloadLengths else 0,
            'Packet Length Variance': np.var(payloadLengths) if payloadLengths else 0,
            'Total Length of Fwd Packet': np.sum(fwdLengths), # total and average size features
            'Fwd Packet Length Max': np.max(fwdLengths) if fwdLengths else 0, # FWD/BWD packet length features
            'Fwd Packet Length Mean': np.mean(fwdLengths) if fwdLengths else 0,
            'Bwd Packet Length Max': np.max(bwdLengths) if bwdLengths else 0,
            'Bwd Packet Length Mean': np.mean(bwdLengths) if bwdLengths else 0,
            'Bwd Packet Length Min': np.min(bwdLengths) if bwdLengths else 0,
            'Bwd Packet Length Std': np.std(bwdLengths) if bwdLengths else 0,
            'Fwd Segment Size Avg': np.mean(fwdLengths) if fwdLengths else 0,
            'Bwd Segment Size Avg': np.mean(bwdLengths) if bwdLengths else 0,
            'Subflow Fwd Bytes': np.sum(fwdLengths) / subflowCount if subflowCount > 0 else 0, # subflow feature
            'SYN Flag Count': synFlags, # SYN, ACK and RST flag counts
            'ACK Flag Count': ackFlags,
            'RST Flag Count': rstFlags,
            'Flow Duration': flowDuration, # flow duration and packets per second in flow
            'Packets Per Second': len(packetList) / flowDuration if flowDuration > 0 else 0,
            'IAT Total': np.sum(interArrivalTimes) if interArrivalTimes else 0, # inter-arrival time features (IAT)
            'IAT Max': np.max(interArrivalTimes) if interArrivalTimes else 0, 
            'IAT Mean': np.mean(interArrivalTimes) if interArrivalTimes else 0,
            'IAT Std': np.std(interArrivalTimes) if interArrivalTimes else 0
        }   
        featuresDict[flow] = flowParametes #save the dictionary of values into the featuresDict
    return dict(featuresDict)


# function for predicting PortScanning and DoS attacks given flow dictionary
def PredictPortDoS(flowDict):
    global selectedColumns

    try: 
        # extract keys and values
        keys = list(flowDict.keys())
        values = list(flowDict.values())
        orderedValues = [[valueDict[col] for col in selectedColumns] for valueDict in values] #reorder the values in the same order that the models were trained on
        
        # create DataFrame for the keys (3-tuple)
        keysDataframe = pd.DataFrame(keys, columns=['Src IP', 'Dst IP', 'Protocol'])

        # create DataFrame for the values (dict), columns ensures that the order of the input matches the order of the classifier
        valuesDataframe = pd.DataFrame(orderedValues, columns=selectedColumns)

        # load the PortScanning and DoS model
        modelPath = getModelPath('new_flows_port_dos_hulk_goldeneye_svm_model.pkl')
        scalerPath = getModelPath('new_flows_port_dos_hulk_goldeneye_scaler.pkl')
        loadedModel = joblib.load(modelPath) 
        loadedScaler = joblib.load(scalerPath) 

        # scale the input data and predict the scaled input
        scaledDataframe = loadedScaler.transform(valuesDataframe)
        valuesDataframe = pd.DataFrame(scaledDataframe, columns=selectedColumns)
        predictions = loadedModel.predict(valuesDataframe)
        keysDataframe['Result'] = predictions

        # check for attacks in model predictions
        if (1 in predictions) and (2 in predictions):#1 and 2 means PortScan and DoS attacks together
            raise PortScanDoSException( #throw an exeption to inform user of its presence
                'Detected PortScan and DoS attack',
                state=3,
                flows=keysDataframe[keysDataframe['Result'] != 0].to_dict(orient='records')
            )

        elif 1 in predictions: #1 means PortScan attack
            raise PortScanDoSException( #throw an exeption to inform user of its presence
                'Detected PortScan attack',
                state=1,
                flows=keysDataframe[keysDataframe['Result'] == 1].to_dict(orient='records')
            )
        
        elif 2 in predictions: #2 means DoS attack
            raise PortScanDoSException( #throw an exeption to inform user of its presence
                'Detected DoS attack',
                state=2,
                flows=keysDataframe[keysDataframe['Result'] == 2].to_dict(orient='records')
            )

        # show results of the prediction
        labelCounts = keysDataframe['Result'].value_counts()
        print(f'Results: {labelCounts}\n')
        print(f'Num of Port Scan ips: {keysDataframe[keysDataframe['Result'] == 1]['Src IP'].unique()}\n')
        print(f'Num of DoS ips: {keysDataframe[keysDataframe['Result'] == 2]['Src IP'].unique()}\n')
        print(f'Number of detected attacks:\n {keysDataframe[keysDataframe['Result'] != 0]}\n')
        print('Predictions:\n', keysDataframe)

        # temporary code for saving false positive if the occure during scans
        if len(keysDataframe[keysDataframe['Result'] != 0]['Src IP'].unique()) != 0:
            import shutil
            shutil.copy('detectedFlows.txt', f'{np.random.randint(1,1000000)}_{"detectedFlows.txt"}')

    except PortScanDoSException as e: #if we recived ArpSpoofingException we alert the user
        print(e)
    except Exception as e: #we catch an exception if something happend
        print(f'Error occurred: {e}')

#--------------------------------------------PORT-SCANNING-DoS-END-------------------------------------------#

#-----------------------------------------------DNS-TUNNELING------------------------------------------------#
def ProcessDNSFlows(dnsFlowDict): 
    featuresDict = defaultdict(dict) #represents our features dict where each flow tuple has its corresponding features

    # iterate over our flow dict and calculate features
    for flow, packetList in dnsFlowDict.items():
        fwdTxtRecord = 0 #represennts number of txt record response packets in flow
        fwdARecord = 0 #represennts number of A record (ipv4) response packets in flow
        fwd4ARecord = 0 #represennts number of AAAA record (ipv6) response packets in flow
        domainNameLengths = [] #represents the domian name lengths
        responseDataLengths = [] #represents the response data lengths
        packetLengths = [] #represents packet lengths
        ipHeaderLengths = [] #represents ip header lengths
        ipRbFlags, ipDfFlags, ipMfFlags = 0, 0, 0 #represents flags of ip header

        # iterate over each packet in flow
        for packet in packetList:
            if isinstance(packet, DNS_Packet):                
                # add packet length and ip header length to lists
                packetLengths.append(packet.packetLen)
                ipHeaderLengths.append(packet.ipHeaderLen)

                # check each flag in ipv4 and increment counter if set
                if 'RB' in packet.ipFlagDict and packet.ipFlagDict['RB']:
                    ipRbFlags += 1
                if 'DF' in packet.ipFlagDict and packet.ipFlagDict['DF']:
                    ipDfFlags += 1
                if 'MF' in packet.ipFlagDict and packet.ipFlagDict['MF']:
                    ipMfFlags += 1
                
                if packet.srcIp == flow[0] and packet.dnsType == 'Response': #means response packet
                    if packet.dnsSubType == 1: #means A record
                        fwdARecord += 1
                    elif packet.dnsSubType == 28: #means AAAA record
                        fwd4ARecord += 1
                    elif packet.dnsSubType == 16: #means TXT record
                        fwdTxtRecord += 1
                    
                    # add response data to response data list
                    if packet.dnsData:
                        if isinstance(packet.dnsData, list): #if data is list we convert it
                            totalLength = np.sum(len(response) for response in packet.dnsData)
                            responseDataLengths.append(totalLength)
                        elif isinstance(packet.dnsData, dict): #if data is dict we convert it
                            totalLength = np.sum(len(value) for value in packet.dnsData.values())
                            responseDataLengths.append(totalLength)
                        else: #else its regular data object
                            responseDataLengths.append(len(packet.dnsData))

                elif packet.srcIp == flow[1] and packet.dnsType == 'Request': #means request packet
                    domainNameLengths.append(len(packet.dnsDomainName)) #add domian name length

        # calculate the value dictionary for the current flow and insert it into the featuresDict
        flowParametes = {
            'Fwd A Record': fwdARecord,
            'Fwd AAAA Record': fwd4ARecord,
            'Fwd TXT Record': fwdTxtRecord,
            'Average Response Data Length': np.mean(responseDataLengths) if responseDataLengths else 0,
            'Min Response Data Length': np.min(responseDataLengths) if responseDataLengths else 0,
            'Max Response Data Length': np.max(responseDataLengths) if responseDataLengths else 0,
            'Average Domain Name Length': np.mean(domainNameLengths) if domainNameLengths else 0,
            'Min Domain Name Length': np.min(domainNameLengths) if domainNameLengths else 0,
            'Max Domain Name Length': np.max(domainNameLengths) if domainNameLengths else 0,
            'Average Packet Length': np.mean(packetLengths) if packetLengths else 0,
            'Min Packet Length': np.min(packetLengths) if packetLengths else 0,
            'Max Packet Length': np.max(packetLengths) if packetLengths else 0,
            'Average IP Header Length': np.mean(ipHeaderLengths) if ipHeaderLengths else 0,
            'Min IP Header Length': np.min(ipHeaderLengths) if ipHeaderLengths else 0,
            'Max IP Header Length': np.max(ipHeaderLengths) if ipHeaderLengths else 0,
            'RB Flag Count': ipRbFlags,
            'DF Flag Count': ipDfFlags,
            'MF Flag Count': ipMfFlags,
        }
        featuresDict[flow] = flowParametes #save the dictionary of values into the featuresDict
    return dict(featuresDict)

#----------------------------------------------DNS-TUNNELING-END---------------------------------------------#

#--------------------------------------------SAVING-COLLECTED-DATA-------------------------------------------#

def SaveCollectedData(flows):
    global selectedColumns

    # create a dataframe from the collected data
    values = list(flows.values())
    ordered_values = [[valueDict[col] for col in selectedColumns] for valueDict in values] #reorder the values in the same order that the models were trained on
    valuesDataframe = pd.DataFrame(ordered_values, columns=selectedColumns)

    if not os.path.isfile('benign_dataset.csv'):
        valuesDataframe.to_csv('benign_dataset.csv', index=False) #save the new data if needed
    else:
        # open an existing file and merge the collected data to it
        readBenignCsv = pd.read_csv('benign_dataset.csv')
        mergedDataframe = pd.concat([readBenignCsv , valuesDataframe], axis=0)
        mergedDataframe.to_csv('benign_dataset.csv', index=False)
        print(f'Found {valuesDataframe.shape[0]} rows.')

#------------------------------------------SAVING-COLLECTED-DATA-END-----------------------------------------#


if __name__ == '__main__':
    # GetAvailableInterfaces()

    #call scan network func to initiate network scan 'en6' / 'Ethernet'
    ScanNetwork('Ethernet') 

    # #test call arp processing function and check for arp spoofing attacks
    # ProcessARP()

    # test port scanning and dos attacks
    flows = ProcessFlows(flowDict)

    # write result of flows captured in txt file
    # with open('detectedFlows.txt', 'w') as file:
    #     for flow, features in flows.items():
    #         file.write(f'Flow: {flow}\n')
    #         for feature, value in features.items():
    #             file.write(f' {feature}: {value}\n')
    #         file.write('================================================================\n')

    # save the collected data
    SaveCollectedData(flows)

    #call predict function to determine if attack is present
    PredictPortDoS(flows)