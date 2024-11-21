import sys
import os
import re
import logging
from abc import ABC, abstractmethod
import scapy.all as scapy
from scapy.all import sniff, wrpcap, rdpcap, get_if_list, IP, IPv6, TCP, UDP, ICMP, ARP, Raw 
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dhcp import DHCP, BOOTP
from urllib.parse import unquote
from queue import Queue


#--------------------------------------------Default_Packet----------------------------------------------#
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
    length = None #size of packet

    # constructor for default packet 
    def __init__(self, protocol=None, packet=None):
        self.protocol = protocol
        self.packet = packet
        self.length = len(self.packet)
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
        elif self.packet.haslayer(IPv6): #if packet has ipv6 layer
            self.srcIp = self.packet[IPv6].src #represents the source ip
            self.dstIp = self.packet[IPv6].dst #represents the destination ip
            hopLimit = self.packet[IPv6].hlim #represents the hop limit parameter in packet
            trafficClass = self.packet[IPv6].tc #represnets the traffic class in packet
            self.ipParam = (hopLimit, trafficClass) #save both as tuple


    # method to return a normalized flow representation of a packet
    def GetFlowTuple(self):
        # extract flow tuple from packet
        srcIp, srcPort, dstIp, dstPort, protocol = self.srcIp, self.srcPort, self.dstIp, self.dstPort, self.protocol
        
        # check if tuple isn't normalized and sort it if necessary
        if (srcIp > dstIp) or (srcIp == dstIp and srcPort > dstPort):
            srcIp, srcPort, dstIp, dstPort = dstIp, dstPort, srcIp, srcPort #swap src and dst to ensure normalized order

        return (srcIp, srcPort, dstIp, dstPort, protocol) #return the flow tuple of packet


#--------------------------------------------Default_Packet-END----------------------------------------------#

#----------------------------------------------------TCP---------------------------------------------------#
class TCP_Packet(Default_Packet):
    srcPort = None
    dstPort = None
    seqNum = None
    ackNum = None
    windowSize = None
    flagDict = None
    optionDict = None

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

#-------------------------------------------------TCP-END------------------------------------------------#

#---------------------------------------------------UDP-------------------------------------------------#
class UDP_Packet(Default_Packet):
    def __init__(self, packet=None): #ctor 
        super().__init__('UDP', packet) #call parent ctor
        if packet.haslayer(UDP): #checks if packet is UDP
            self.packetType = UDP #add packet type

#----------------------------------------------UDP-END----------------------------------------------#

#---------------------------------------------------DNS------------------------------------------------#
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
    
#-------------------------------------------------DNS-END----------------------------------------------#

# ------------------------------------------------ARP----------------------------------------------#
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
            self.srcIP = self.packet[ARP].psrc #add arp source ip address
            self.dstIP = self.packet[ARP].pdst #add arp destination ip address
            self.arpType = 'Request' if self.packet[ARP].op == 1 else 'Reply' #add the arp type
            self.hwType = self.packet[ARP].hwtype #add the hardware type
            self.pType = self.packet[ARP].ptype #add protocol type to output
            self.hwLen = self.packet[ARP].hwlen #add hardware length to output
            self.pLen = self.packet[ARP].plen #add protocol length to output

#---------------------------------------------ARP-END----------------------------------------------#

flowDict = {} #represents dict of {(flow tuple) - [packet list]} related to port scanning and dos
dnsDict = {} #represents dict of packets related to dns tunneling 
arpDict = {} #represents dict of packets related to arp poisoning
dnsCounter = 0 #global counter for dns packets
arpCounter = 0 #global counter for arp packets
tempcounter = 0

#-----------------------------------------HANDLE-FUNCTIONS-----------------------------------------#
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
    global dnsCounter
    DNS_Object = DNS_Packet(packet, dnsCounter) #create a new object for packet
    dnsDict[DNS_Object.dnsId] = DNS_Object #insert it to packet dictionary
    dnsCounter += 1 #increase the counter


#method that handles ARP packets
def handleARP(packet):
    global arpCounter
    ARP_Object = ARP_Packet(packet, arpCounter) #create a new object for packet
    arpDict[ARP_Object.arpId] = ARP_Object #insert it to packet dictionary
    arpCounter += 1 #increase the counter

#-----------------------------------------HANDLE-FUNCTIONS-END-----------------------------------------#

#-----------------------------------------HELPER-FUNCTIONS-----------------------------------------#

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

#-----------------------------------------HELPER-FUNCTIONS-END-----------------------------------------#

#-------------------------------------------SNIFF-FUNCTIONS------------------------------------------#
# function for processing the portScanDosDict and creating the dataframe that will be passed to classifier
def ProcessPortScanDos(packetList):
    pass


# function for checking when to stop sniffing packets, stop condition
def StopScan(packet):
    return True if tempcounter >=100 else False


# function for capturing specific packets for later analysis
def PacketCapture(packet):
    captureDict = {TCP: handleTCP, UDP: handleUDP, DNS: handleDNS, ARP: handleARP} #represents dict with packet type and handler func

    # iterate over capture dict and find coresponding handler function for each packet
    for packetType, handler in captureDict.items():
        if packet.haslayer(packetType): #if we found matching packet we call its handle method
            handler(packet) #call handler method of each packet


# function for initialing a packet scan on desired network interface
def ScanNetwork(interface):
    try: #we call sniff with desired interface 
        sniff(iface=interface, prn=PacketCapture, stop_filter=StopScan, store=0)
    except PermissionError: #if user didn't run with administrative privileges 
        print('Permission denied. Please run again with administrative privileges.') #print permission error message in terminal
    except Exception as e: #we catch an exception if something happend while sniffing
        print(f'An error occurred while sniffing: {e}') #print error message in terminal

#-----------------------------------------SNIFF-FUNCTIONS-END------------------------------------------#


if __name__ == '__main__':
    GetAvailableInterfaces()
    print('Starting Network Scan...')

    ScanNetwork('Ethernet') #call scan network func to initiate network scan 'en6'

    print('Finsihed Network Scan.\n')

    # test results of flow dict
    for key in flowDict:
        print(f'{key} : {len(flowDict[key])}')