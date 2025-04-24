import sys, os, socket, platform, joblib, csv
import numpy as np
import pandas as pd
from abc import ABC, abstractmethod
from ipaddress import IPv4Interface, IPv6Interface, IPv4Address, IPv6Address
from scapy.all import AsyncSniffer, srp, get_if_list, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, Raw, conf
from scapy.layers.dns import DNS
from PySide6.QtNetwork import QNetworkInterface
from datetime import datetime, timedelta
from pathlib import Path

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) #ensures that when the main.py file is ran it will run from the src folder in the terminal (this allows the import of ui class from interface folder)

#----------------------------------------------Default_Packet------------------------------------------------#
# abstarct class for default packet
class Default_Packet(ABC):
    protocol = None #represents the packet protocol (TCP, UDP, etc)
    packet = None #represents the packet object itself for our use later
    packetType = None #represents the packet type based on scapy known types
    srcIp = None #represents source ip of packet 
    srcMac = None #represents the source mac address
    dstIp = None #represents destination ip of packet
    dstMac = None #represents the destination mac address
    srcPort = None #represents source port of packet 
    dstPort = None #represents destination port of packet
    ipParam = None #represents IPv4 / IPv6 fields as tuple (ttl, dscp) / (hopLimit, trafficClass)
    packetLen = None #size of packet (including headers, IP and payload)
    headerLen = None #size of packet header (packet specific header with its payload)
    payloadLen = None #size of payload of packet
    ipFlagDict = {} #represents ip flags
    time = None #timestamp of packet

    # constructor for default packet 
    def __init__(self, protocol=None, packet=None):
        self.protocol = protocol
        self.packet = packet
        self.srcMac = self.packet.src
        self.dstMac = self.packet.dst
        self.packetLen = len(self.packet)
        self.headerLen = 0
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
            # we extract the binary number that represents the ipv4 flags
            ipFlags = self.packet[IP].flags #represents flags of ip
            self.ipFlagDict = {
                'MF': (ipFlags & 0x1) != 0, #More Fragments flag
                'DF': (ipFlags & 0x2) != 0, #Don't Fragment flag
                'EVIL': (ipFlags & 0x4) != 0, #Evil flag
            }
        elif self.packet.haslayer(IPv6): #if packet has ipv6 layer
            self.srcIp = self.packet[IPv6].src #represents the source ip
            self.dstIp = self.packet[IPv6].dst #represents the destination ip
            hopLimit = self.packet[IPv6].hlim #represents the hop limit parameter in packet
            trafficClass = self.packet[IPv6].tc #represnets the traffic class in packet
            self.ipParam = (hopLimit, trafficClass) #save both as tuple


    # method to return a normalized flow representation of a packet
    def GetFlowTuple(self):
        currentInterface = NetworkInformation.networkInfo.get(NetworkInformation.selectedInterface) #the values of the selected network interface

        # extract flow tuple from packet
        srcIp, srcMac, dstIp, dstMac, protocol = self.srcIp, self.srcMac, self.dstIp, self.dstMac, self.protocol

        #we create the flow tuple based on lexicographic order if it does not contain host ip address to ensure consistency
        if (dstIp in currentInterface.get('ipv4Addrs')) or (dstIp in currentInterface.get('ipv6Addrs')): #check if dst ip is our ip address
            return (srcIp, srcMac, dstIp, dstMac, protocol) #return the flow tuple of packet with host ip as dst ip in tuple

        elif (srcIp in currentInterface.get('ipv4Addrs')) or (srcIp in currentInterface.get('ipv6Addrs')) or (srcIp > dstIp): #check if tuple src ip is our ip address or if its not normalized 
            return (dstIp, dstMac, srcIp, srcMac, protocol) #return tuple in normalized order and also ensure that our ip is dst ip in flow

        return (srcIp, srcMac, dstIp, dstMac, protocol) #return the flow tuple of packet

#--------------------------------------------Default_Packet-END----------------------------------------------#

#----------------------------------------------------TCP-----------------------------------------------------#
class TCP_Packet(Default_Packet):
    srcPort = None
    dstPort = None
    seqNum = None
    ackNum = None
    segmentSize = None
    windowSize = None
    flagDict = {}
    optionDict = {}

    # constructor for TCP packet 
    def __init__(self, packet=None):
        super().__init__('TCP', packet) #call parent ctor
        if packet.haslayer(TCP): #checks if packet is TCP
            self.packetType = TCP #specify the packet type
            self.headerLen = len(self.packet[TCP]) #add header len of tcp
            self.segmentSize = len(self.packet[TCP].payload) #add segment size of tcp
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
            self.headerLen = len(self.packet[UDP]) #add header len of udp

#---------------------------------------------------UDP-END--------------------------------------------------#

#----------------------------------------------------DNS-----------------------------------------------------#
class DNS_Packet(Default_Packet):
    dnsType = None
    dnsSubType = None
    dnsClass = None
    dnsDomainName = None
    dnsNumOfReqOrRes = None
    dnsData = None

    def __init__(self, packet=None):
        super().__init__('DNS', packet) #call parent ctor
        if packet.haslayer(DNS): #checks if packet is DNS
            self.packetType = DNS #add packet type
            self.headerLen = len(self.packet[DNS]) #add header len of dns
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
    arpType = None
    hwType = None
    pType = None
    hwLen = None
    pLen = None

    def __init__(self, packet=None):
        super().__init__('ARP', packet) #call parent ctor
        if packet.haslayer(ARP): #checks if packet is ARP
            self.packetType = ARP #add packet type
            self.headerLen = len(self.packet[ARP]) #add header len of arp
            self.InitARP() #call method to initialize ARP specific params

    # method for ARP packet information
    def InitARP(self):
        if self.packet.haslayer(ARP): #if packet has layer of ARP
            self.srcIp = self.packet[ARP].psrc #add ARP source ip address
            self.srcMac = self.packet[ARP].hwsrc #add ARP source mac address
            self.dstIp = self.packet[ARP].pdst #add ARP destination ip address
            self.dstMac = self.packet[ARP].hwdst #add ARP destination mac address
            self.arpType = 'Request' if self.packet[ARP].op == 1 else 'Reply' #add the ARP type
            self.hwType = self.packet[ARP].hwtype #add the hardware type
            self.pType = self.packet[ARP].ptype #add protocol type to output
            self.hwLen = self.packet[ARP].hwlen #add hardware length to output
            self.pLen = self.packet[ARP].plen #add protocol length to output

#--------------------------------------------------ARP-END---------------------------------------------------#

#--------------------------------------------NETWORK-INFORMATION---------------------------------------------#
# static class that represents network information of network interfaces
class NetworkInformation(ABC):
    # this list represents the usual network interfaces that are available in various platfroms
    supportedInterfaces = ['eth', 'wlan', 'en', 'enp', 'wlp', 'Ethernet', 'Wi-Fi', 'lo', '\\Device\\NPF_Loopback']
    systemInfo = None #represents a dictionary with all system information about the users machine
    networkInfo = None #represents a dict of dicts where each inner dict represents an available network interface
    selectedInterface = None #represents user-selected interface name: 'Ethernet' / 'en6'
    previousInterface = None #represents previous interfcae used for network analysis

    # function for initializing the dict of data about all available interfaces
    @staticmethod
    def InitNetworkInfo():
        NetworkInformation.networkInfo = NetworkInformation.GetNetworkInterfaces() #find all available network interface and collect all data about these interfaces
        #return all available interface names for the user to select in sorted order
        return sorted(NetworkInformation.networkInfo, key=lambda x: (next((i for i, prefix 
                in enumerate(NetworkInformation.supportedInterfaces) if x.startswith(prefix)), len(NetworkInformation.supportedInterfaces)), x))


    # function to print all available interfaces
    @staticmethod
    def PrintAvailableInterfaces():
        # get a list of all available network interfaces
        interfaces = get_if_list() #call get_if_list method to retrieve the available interfaces
        if interfaces: #if there are interfaces we print them
            print('Available network interfaces:')
            i = 1 #counter for the interfaces 
            for interface in interfaces: #print all availabe interfaces
                if sys.platform.startswith('win32'): #if ran on windows we convert the guid number
                    print(f'{i}. {NetworkInformation.GuidToStr(interface)}')
                else: #else we are on other os so we print the interface 
                    print(f'{i}. {interface}')
                i += 1
        else: #else no interfaces were found
            print('No network interfaces found.')


    # function for retrieving interface name from GUID number (Windows only)
    @staticmethod
    def GuidToStr(guid):
        try: #we try to import the specific windows method from scapy library
            from scapy.arch.windows import get_windows_if_list
        except ImportError as e: #we catch an import error if occurred
            print(f'Error importing module: {e}') #print the error
            return guid #we exit the function
        interfaces = get_windows_if_list() #use the windows method to get list of guid number interfaces
        for interface in interfaces: #iterating over the list of interfaces
            if interface.get('guid') == guid: #we find the matching guid number interface
                return interface['name'] #return the name of the interface associated with guid number
        return guid #else we didnt find the guid number so we return given guid


    # function for retrieving the network interfaces
    @staticmethod
    def GetNetworkInterfaces_OLD():
        interfaces = get_if_list() #get a list of the network interfaces
        if sys.platform.startswith('win32'): #if current os is Windows we convert the guid number to interface name
            interfaces = [NetworkInformation.GuidToStr(interface) for interface in interfaces] #get a new list of network interfaces with correct names instead of guid numbers
        matchedInterfaces = [interface for interface in interfaces if any(interface.startswith(name) for name in NetworkInformation.supportedInterfaces)] #we filter the list to retrieving interfaces
        return matchedInterfaces #return the matched interfaces as list


    # function for collecting all available interfaces on the current machine including all their information including name, ipv4 and ipv6 addresses and subnets and more
    @staticmethod
    def GetNetworkInterfaces():
        Availableinterfaces = QNetworkInterface.allInterfaces() #represents all available network interfaces for machine
        networkInterfaces = {} #represents network interfaces dict where keys are name of interface and value is interface dict

        # iterate through all network interfaces and initialize our network interfaces dict
        for iface in conf.ifaces.values():
            # we add only interfaces we support with scapy and that are up
            if iface.ips and any(iface.name.startswith(name) for name in NetworkInformation.supportedInterfaces):
                # initialize interface name, description, mac, MTU and ipv4 and ipv6 addresses (always dict of two elements: 4: ipv4Addrs, 6: ipv6Addrs)
                name, description, mac, maxTransmitionUnit = iface.name, iface.description, iface.mac, NetworkInformation.GetMTUFromInterface(Availableinterfaces, iface.name)
                ipv4Addrs, ipv6Addrs, ipv4Subnets, ipv6Subnets = iface.ips.get(4, []), iface.ips.get(6, []), set(), set()

                # initialize ipv4 subnets based on ipv4 ips we found
                for ipAddress in ipv4Addrs:
                    netmask = NetworkInformation.GetNetmaskFromIp(Availableinterfaces, ipAddress) #get netmask with our function
                    if ipAddress and netmask:
                        subnet = IPv4Interface(f'{ipAddress}/{netmask}').network #create ipv4 subnet object
                        ipv4Subnets.add((subnet, f'{'.'.join(ipAddress.split('.')[:3])}.0/24', netmask)) #set of tuples such that (subnet (real), range(/24), netmask)

                # initialize ipv6 subnets based on ipv6 ips we found
                for ipAddress in ipv6Addrs:
                    netmask = NetworkInformation.GetNetmaskFromIp(Availableinterfaces, ipAddress) #get netmask with our function
                    if ipAddress and netmask:
                        netmaskPrefix = int(IPv6Address(netmask)).bit_count() #expand ipv6 netmask for calculating subnet
                        subnet = IPv6Interface(f'{ipAddress}/{netmaskPrefix}').network #create ipv6 subnet object
                        ipv6Subnets.add((subnet, f'{':'.join(ipAddress.split(':')[:4])}::/64', netmask)) #set of tuples such that (subnet (real), range(/64), netmask)

                # if interface is active and has ip address we add it to network interfaces
                if ipv4Addrs or ipv6Addrs:
                    # initialize interface dict with all given information
                    interfaceDict = {
                        'name': name if name else 'None',
                        'description': description if description else 'None',
                        'maxTransmitionUnit': maxTransmitionUnit if maxTransmitionUnit else 'None',
                        'mac': mac if mac else 'None',
                        'ipv4Addrs': ipv4Addrs,
                        'ipv4Subnets': ipv4Subnets,
                        'ipv6Addrs': ipv6Addrs,
                        'ipv6Subnets': ipv6Subnets
                    }
                    networkInterfaces[interfaceDict.get('name')] = interfaceDict #add interface to our network interfaces
        
        return networkInterfaces #return the filtered and matched interfaces


    # function for getting a correct netmask for a given IP address using QtNetwork
    @staticmethod
    def GetNetmaskFromIp(Availableinterfaces, ipAddress):
        # iterate over each interface and find correct netmask
        for iface in Availableinterfaces:
            for entry in iface.addressEntries():
                # means we found our matching subnet for ip
                if entry.ip().toString() == ipAddress:
                    return entry.netmask().toString()
        return None #return None if the IP was not found


    # function for getting a correct MTU for a given interface using QtNetwork
    @staticmethod
    def GetMTUFromInterface(Availableinterfaces, interface):
        # iterate over each interface and find correct interface
        for iface in Availableinterfaces:
            # means we found our matching interface, we return found MTU
            if iface.humanReadableName() == interface or iface.name() == interface:
                return str(iface.maximumTransmissionUnit())
        return None #return None if interface was not found


    # function for getting system information
    @staticmethod
    def GetSystemInformation():
        NetworkInformation.systemInfo = {
            'osType': str(platform.system()) + ' ' + str(platform.release()),
            'osVersion': str(platform.version()),
            'architecture': str(platform.architecture()[0]),
            'hostName': str(socket.gethostname()),
        }
        return NetworkInformation.systemInfo
    

    # function for getting current timespamp in format hh:mm:ss dd:mm:yy
    @staticmethod
    def GetCurrentTimestamp():
        return datetime.now().strftime('%H:%M:%S %d/%m/%y') #get timestamp for attack in our format
    

    # function that compares difference between two timespamps in minutes 
    @staticmethod
    def CompareTimepstemps(timestampOld, timestampNew, minutes=1):
        # convert strings to datetime objects
        timeOld = datetime.strptime(timestampOld, '%H:%M:%S %d/%m/%y')
        timeNew = datetime.strptime(timestampNew, '%H:%M:%S %d/%m/%y')
        timeDifference = abs(timeNew - timeOld) # calculate the absolute time difference

        return timeDifference >= timedelta(minutes=minutes)
     
#--------------------------------------------NETWORK-INFORMATION-END-----------------------------------------#

#-----------------------------------------------ARP-SPOOFING-------------------------------------------------#
class ArpSpoofingException(Exception):
    def __init__(self, message, type, attackDict):
        super().__init__(message)
        self.type = type #represents the type of attack, 1 means we found ip assigned to many macs, 2 means mac assigned to many ips
        self.attackDict = attackDict #represents attack dict of ARP spoofing incident

    # str representation of ARP spoofing exception for showing results
    def __str__(self):
        details = '\n##### ARP SPOOFING ATTACK ######\n'
        if self.type == 1:
            details += '\n'.join([
                f'[*] IP: {ip} ==> Source IP: {entry.get('srcIp')}, '
                f'Source MAC: {', '.join(sorted(entry.get('srcMac')))}, '
                f'Destination IP: {entry.get('dstIp')}, Destination MAC: {entry.get('dstMac')}'
                for ip, entry in self.attackDict.items()])
        elif self.type == 2:
            details += '\n'.join([
                f'[*] MAC: {mac} ==> Source IP: {', '.join(sorted(entry.get('srcIp')))}, '
                f'Source MAC: {entry.get('srcMac')}, '
                f'Destination IP: {entry.get('dstIp')}, Destination MAC: {entry.get('dstMac')}'
                for mac, entry in self.attackDict.items()])
        return f'{self.args[0]}\nDetails:\n{details}\n'


# class that represents a single ARP table, contains an IP to MAC table and an inverse table, has a static method for initing both ARP tables
class ArpTable():
    subnet = None #3-tuple (subnet(real) , range(/24) , netmask)
    arpTable = None #regular IP to MAC ARP table
    invArpTable = None #inverse ARP table, MAC to IP

    # constructor of ArpTable class
    def __init__(self, subnet, arpTable, invArpTable):
        self.subnet = subnet 
        self.arpTable = arpTable
        self.invArpTable = invArpTable


    # fucntion that initializes the static ARP table for storing IP-MAC pairs 
    @staticmethod
    def InitArpTable(ipRange='192.168.1.0/24', isInit=False):
        arpTable = {} #represents our ARP table dict (IP to MAC)
        invArpTable = {} #represents our inverse (MAC to IP), used for verification
        totalAttackDict = {'ipToMac': {}, 'macToIp': {}} #represents total attack dict with anomalies
        arpRequest = ARP(pdst=ipRange) #create ARP request packet with destination IP range
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')  #create broadcast ethernet frame broadcast
        arpRequestBroadcast = broadcast / arpRequest #combine both ARP request and ethernet frame 

        # send the ARP request and capture the responses
        # srp function retunes tuple (response packet, received device)
        answeredList = srp(arpRequestBroadcast, timeout=0.75, verbose=False)[0]

        # iterate over all devices that answered to our ARP request packet and add them to our table
        for device in answeredList:
            # represents the device that answered us with his source IP and MAC
            srcIp, srcMac, dstIp, dstMac = device[1].psrc, device[1].hwsrc, device[1].pdst, device[1].hwdst

            # we check that packet is not associated to a temporary IP (0.0.0.0) or MAC (00:00:00:00:00:00)
            if srcIp != '0.0.0.0' and srcMac != '00:00:00:00:00:00':
                # means IP not in ARP table, we add it with it's MAC address
                if not arpTable.get(srcIp):
                    arpTable[srcIp] = srcMac #set the srcMac address in srcIp index
                # else srcMac doesn't match with known srcMac in srcIp index
                elif arpTable.get(srcIp) and arpTable.get(srcIp) != srcMac:
                    srcMacs = {arpTable.get(srcIp), srcMac} #represents srcMacs we detected for ARP spoofing
                    # add an ARP spoofing anomaly, same IP but different MAC addresses
                    totalAttackDict['ipToMac'].setdefault(srcIp, {'srcIp': srcIp, 'srcMac': set(), 'dstIp': dstIp, 'dstMac': dstMac,
                                                                'protocol': 'ARP', 'timestamp': NetworkInformation.GetCurrentTimestamp()})['srcMac'].update(srcMacs)

                # means MAC not in inv ARP table, we add it with it's IP address
                if not invArpTable.get(srcMac):
                    invArpTable[srcMac] = srcIp #set the srcIp address in srcMac index
                # else srcIp doesn't match with known srcIp in srcMac index
                elif invArpTable.get(srcMac) and invArpTable.get(srcMac) != srcIp:
                    srcIps = {invArpTable.get(srcMac), srcIp} #represents srcIps we detected for ARP spoofing
                    # add an ARP spoofing anomaly, same MAC but different IP addresses
                    totalAttackDict['macToIp'].setdefault(srcMac, {'srcIp': set(), 'srcMac': srcMac, 'dstIp': dstIp, 'dstMac': dstMac,
                                                                    'protocol': 'ARP', 'timestamp': NetworkInformation.GetCurrentTimestamp()})['srcIp'].update(srcIps)

        # we check if isInit is not set, if so we check if we had an attack and throw exeption
        if not isInit:
            # we check if one of the attack dicts is not empty, means we have an attack
            if totalAttackDict.get('ipToMac'):
                #throw an exeption to inform user of it's presence
                raise ArpSpoofingException(
                    'Detected ARP spoofing incidents: IP-to-MAC anomalies',
                    type=1,
                    attackDict=totalAttackDict.get('ipToMac')
                )
                
            elif totalAttackDict.get('macToIp'):
                # throw an exeption to inform user of its presence
                raise ArpSpoofingException(
                    'Detected ARP spoofing incidents: MAC-to-IP anomalies',
                    type=2,
                    attackDict=totalAttackDict.get('macToIp')
                )

        return (arpTable, invArpTable) if not isInit else (arpTable, invArpTable, totalAttackDict)


# static class that represents the detection of ARP Spoofing attack using an algorithem to detect duplications in ARP tables based on collected ARP packets
class ArpSpoofing(ABC):
    arpTables = {} #represents all ARP tables where the key of the table is the subnet, each inner ARP table is a tuple (arpTable, invArpTable) with mapping of IP->MAC and MAC->IP in each table in tuple
    ipSubnetCache = {} #represents a dict with cache of all ip addresses with their matched subnet
    isArpTables = False #represents initialization state of arpTables dict

    # function that iterates over available ipv4 subnets and initializes an ARP table for each one
    @staticmethod
    def InitAllArpTables():
        # represents result of ARP initialization dictionary {state: T/F, type: 3-InitArp, attackDict: {}}
        result = {'state': True, 'type': 3, 'attackDict': {}}
        totalAttackDict = {'ipToMac': {}, 'macToIp': {}} #represents total attack dict with anomalies

        # we initialize our ARP tables only if selected network interface has changed
        if NetworkInformation.selectedInterface != NetworkInformation.previousInterface:
            # clear previous interface information that was saved in our dictionaries
            NetworkInformation.previousInterface = NetworkInformation.selectedInterface
            ArpSpoofing.arpTables, ArpSpoofing.ipSubnetCache = {}, {}

            # iterate over all given subnets, for each check if an ARP table exists for it
            for subnet in NetworkInformation.networkInfo.get(NetworkInformation.selectedInterface).get('ipv4Subnets'):
                if not ArpSpoofing.arpTables.get(subnet[0]):
                    # initialize ARP table for subnet with init flag set
                    arpTable, invArpTable, attackDict =  ArpTable.InitArpTable(subnet[1], True)

                    # add our ARP table object into ARP tables dict as ArpTable object
                    ArpSpoofing.arpTables[subnet[0]] = ArpTable(subnet, arpTable, invArpTable)

                    # if attackDict is not empty, merge its data into totalAttackDict
                    if attackDict:
                        # merge the ipToMac dictionary from this attackDict into totalAttackDict
                        if attackDict.get('ipToMac'):
                            for ip, entry in attackDict['ipToMac'].items():
                                totalAttackDict['ipToMac'].setdefault(ip, {'srcIp': ip, 'srcMac': set(), 'dstIp': entry.get('dstIp'), 'dstMac': entry.get('dstMac'),
                                                                            'protocol': entry.get('protocol'), 'timestamp': entry.get('timestamp')})['srcMac'].update(entry.get('srcMac'))

                        # merge the macToIp dictionary from this attackDict into totalAttackDict:
                        if attackDict.get('macToIp'):
                            for mac, entry in attackDict['macToIp'].items():
                                totalAttackDict['macToIp'].setdefault(mac, {'srcIp': set(), 'srcMac': mac, 'dstIp': entry.get('dstIp'), 'dstMac': entry.get('dstMac'),
                                                                             'protocol': entry.get('protocol'), 'timestamp': entry.get('timestamp')})['srcIp'].update(entry.get('srcIp'))

            # check if we have attacks detected if so we update result dict
            if totalAttackDict.get('ipToMac') or totalAttackDict.get('macToIp'):
                result.update({'state': False, 'type': 3, 'attackDict': totalAttackDict})

            # print our static ARP tables
            ArpSpoofing.PrintArpTables()

        return result


    # function for getting the correct subnet given an IP address
    @staticmethod
    def GetSubnetForIP(ipAddress): 
        try:
            # convert given IP address into IPv4 address object
            ipObject = IPv4Address(ipAddress)

            # check if the given IP address has subnet in ipSubnetCache
            if ipObject in ArpSpoofing.ipSubnetCache:
                return ArpSpoofing.ipSubnetCache[ipObject]

            # check if given IP address object matches subnet object
            for subnet in ArpSpoofing.arpTables:
                # means we found matching subnet, we save the match for later use
                if ipObject in subnet:
                    ArpSpoofing.ipSubnetCache[ipObject] = subnet
                    return subnet

            # finally if no subnet matches IP address we set it to none
            ArpSpoofing.ipSubnetCache[ipObject] = None
            return None
        except Exception:
            return None
  

    # function for printing all ARP tables
    @staticmethod
    def PrintArpTables():
        if ArpSpoofing.arpTables:
            print('All ARP Tables:')
            for subnet, arpTableObject in ArpSpoofing.arpTables.items():
                if arpTableObject:
                    print(f'ARP Table: {subnet}\n')
                    for key, value in arpTableObject.arpTable.items():
                        print(f'IP: {key} --> MAC: {value}')
                    print('=' * 44 + '\n')


    # function for processing ARP packets and check for ARP spoofing attacks
    @staticmethod
    def ProcessARP(arpList):
        # represents result of analysis dictionary {state: T/F, type: 1-ipToMac / 2-macToIp, attackDict: {}}
        result = {'state': False, 'type': 1, 'attackDict': {}}
        attackDict = {} #represents attack dict with anomalies
        try:
            # check that ARP tables are initialzied
            if not ArpSpoofing.isArpTables:
                raise RuntimeError('Error, cannot process ARP packets, ARP tables are not initalized.')

            # iterate over our ARP list and check each packet for inconsistencies
            for packet in arpList:
                # we check that packet is not associated to a temporary IP (0.0.0.0) or MAC (00:00:00:00:00:00)
                if isinstance(packet, ARP_Packet) and packet.srcIp != '0.0.0.0' and packet.srcMac != '00:00:00:00:00:00':
                    subnet = ArpSpoofing.GetSubnetForIP(packet.srcIp) #get correct subnet for given IP address

                    # check that we found subnet for IP address and that it's from our interface subnets 
                    if subnet and ArpSpoofing.arpTables.get(subnet): 
                        arpTableObject = ArpSpoofing.arpTables.get(subnet) #get matching ARP table for IP address with it's subnet

                        # means IP address is not present in our ARP table
                        if not arpTableObject.arpTable.get(packet.srcIp):
                            # means MAC address was assinged to different IP, we assume there's possiblility
                            # that this device got assigned a new IP address from dhcp server
                            if arpTableObject.invArpTable.get(packet.srcMac):
                                oldIp = arpTableObject.invArpTable[packet.srcMac] #save old IP address assigned to this MAC address
                                del arpTableObject.arpTable[oldIp] #remove old IP address entry from ARP table
                                del arpTableObject.invArpTable[packet.srcMac] #remove MAC address from inverse ARP table

                            # we create new temp ARP table to check if we get valid response from only one device with matching MAC address
                            ipArpTable = ArpTable.InitArpTable(packet.srcIp) #initialize temp IP ARP table for specific IP and check if valid

                            # we check if there's a reply, if not we dismiss the packet
                            if ipArpTable[0] and ipArpTable[0].get(packet.srcIp):
                                # means MAC addresses match, we add entries to our tables
                                if ipArpTable[0].get(packet.srcIp) == packet.srcMac:
                                    arpTableObject.arpTable[packet.srcIp] = packet.srcMac #assign MAC address to its IP in ARP table
                                    arpTableObject.invArpTable[packet.srcMac] = packet.srcIp #assign IP address to MAC in inverse ARP table
                                # means MAC addresses don't match, we alert because different device asnwered us
                                else:
                                    srcIp, srcMacs = packet.srcIp, {ipArpTable[0].get(packet.srcIp), packet.srcMac} #create the details for exception
                                    # add an ARP spoofing anomaly, same IP but different MAC addresses
                                    attackDict.setdefault(srcIp, {'srcIp': srcIp, 'srcMac': set(), 'dstIp': packet.dstIp, 'dstMac': packet.dstMac,
                                                                'protocol': 'ARP', 'timestamp': NetworkInformation.GetCurrentTimestamp()})['srcMac'].update(srcMacs)

                        # means IP address is present in our ARP table, we check it's parameters
                        else:
                            # means source MAC address does'nt match stored MAC address in ARP table, we alert for spoofed MAC address
                            if arpTableObject.arpTable.get(packet.srcIp) != packet.srcMac:
                                srcIp, srcMacs = packet.srcIp, {arpTableObject.arpTable.get(packet.srcIp), packet.srcMac} #create the details for exception
                                # add an ARP spoofing anomaly, same IP but different MAC addresses
                                attackDict.setdefault(srcIp, {'srcIp': srcIp, 'srcMac': set(), 'dstIp': packet.dstIp, 'dstMac': packet.dstMac,
                                                            'protocol': 'ARP', 'timestamp': NetworkInformation.GetCurrentTimestamp()})['srcMac'].update(srcMacs)

            # means we detected ARP spoofing attack
            if attackDict:
                # throw an exeption to inform user of its presence
                raise ArpSpoofingException(
                    'Detected ARP spoofing incidents: IP-to-MAC anomalies',
                    type=1,
                    attackDict=attackDict
                )
            
            result['state'] = True #indication for no attacks

        except ArpSpoofingException as e: #if we received ArpSpoofingException we alert the user
            result.update({'state': False, 'type': e.type, 'attackDict': e.attackDict}) #indication of attack
            print(e)
        except Exception as e: #we catch an exception if something happend
            print(f'Error occurred: {e}')
        finally:
            return result

#----------------------------------------------ARP-SPOOFING-END----------------------------------------------#

#----------------------------------------------PORT-SCANNING-DoS---------------------------------------------#
class PortScanDoSException(Exception):
    def __init__(self, message, type, attackDict):
        super().__init__(message)
        self.type = type #represents the type of attack, 1 means we detected PortScan attack, 2 means we detected DoS attack
        self.attackDict = attackDict #represents the attack dict with detected attack flows

    # str representation of port scan and dos exception for showing results
    def __str__(self):
        attackName = 'PortScan' if self.type == 1 else 'DoS'
        if self.type == 3:
            attackName = 'PortScan and DoS'
        details = f'\n##### {attackName.upper()} ATTACK ######\n'
        details += '\n'.join([f'''[*] Source IP: {flow[0]} , Source Mac: {flow[1]} , Destination IP: {flow[2]}, Destination Mac: {flow[3]} , Protocol: {flow[4]} , Attack: {attackName}'''
                        for flow in self.attackDict])
        return f'{self.args[0]}\nDetails:\n{details}\n'
    

# static class that represents the collection and detection of PortScan and DoS attacks 
class PortScanDoS(ABC):
    loadedModel = joblib.load(currentDir.parent / 'models' / 'port_scan_dos_svm_model.pkl') #load SVM model for portScanDos
    loadedScaler = joblib.load(currentDir.parent / 'models' / 'port_scan_dos_scaler.pkl') #load scaler for SVM model
    selectedColumns = [
        'Number of Ports', 'Average Packet Length', 'Packet Length Min', 'Packet Length Max', 
        'Packet Length Std', 'Packet Length Variance', 'Total Length of Fwd Packet', 'Fwd Packet Length Max', 
        'Fwd Packet Length Mean', 'Fwd Packet Length Min', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 
        'Bwd Packet Length Mean', 'Bwd Packet Length Min', 'Bwd Packet Length Std', 'Fwd Segment Size Avg', 
        'Bwd Segment Size Avg', 'Subflow Fwd Bytes', 'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count', 
        'Flow Duration', 'Packets Per Second', 'IAT Max', 'IAT Mean', 'IAT Std'
    ]

    # function for processing the flowDict and creating the dataframe that will be passed to classifier
    @staticmethod
    def ProcessFlows(portScanDosDict):
        featuresDict = {} #represents our features dict where each flow tuple has its corresponding features

        # iterate over our flow dict and calculate features
        for flow, packetList in portScanDosDict.items():
            uniquePorts = set() #represents the unique destination ports in flow
            packetLengths = [] #represents packet length of all packets in flow
            fwdLengths = [] #represents length of forward packets in flow
            bwdLengths = [] #represents length of backward packets in flow
            fwdSegmentLengths = [] #represents length of forward tcp packets segment size in flow
            bwdSegmentLengths = [] #represents length of backward tcp packets segment size in flow
            timestamps = [] #represents timestamps of each packet in flow
            subflowLastPacketTS, subflowCount = -1, 0 #last timestamp of the subflow and the counter of subflows
            synFlags, ackFlags, rstFlags = 0, 0, 0 #counter for tcp flags

            # iterate over each packet in flow
            for packet in packetList:
                #append packet length to list
                packetLengths.append(packet.packetLen)

                # append each packet timestemp to our list for IAT
                if packet.time:
                    timestamps.append(packet.time)

                # check if packet is tcp and calculate its specific parameters
                if isinstance(packet, TCP_Packet):
                    # check each flag in tcp and increment counter if set
                    if packet.flagDict.get('SYN'):
                        synFlags += 1
                    if packet.flagDict.get('ACK'):
                        ackFlags += 1
                    if packet.flagDict.get('RST'):
                        rstFlags += 1

                if packet.srcIp == flow[0]: #means forward packet
                    # add forward packet lengths
                    fwdLengths.append(packet.headerLen)

                    #add forward segment size for tcp packets
                    if isinstance(packet, TCP_Packet):
                        fwdSegmentLengths.append(packet.segmentSize)

                    # check for unique destination ports and add it if new port
                    if packet.dstPort not in uniquePorts:
                        uniquePorts.add(packet.dstPort) #add the port to the set
                    
                    # count subflows in forward packets using counters and timestamps
                    if subflowLastPacketTS == -1:
                        subflowLastPacketTS = packet.time
                    if (packet.time - subflowLastPacketTS) > 1.0: #check that timestamp difference is greater than 1 sec
                        subflowCount += 1

                else: #else means backward packets
                    # add backward packets lengths
                    bwdLengths.append(packet.headerLen)

                    #add backward segment size for tcp packets
                    if isinstance(packet, TCP_Packet):
                        bwdSegmentLengths.append(packet.segmentSize)

            # calculate inter-arrival time features (IAT) and flow duration
            interArrivalTimes = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
            flowDuration = np.sum(interArrivalTimes) if interArrivalTimes else 0

            # calculate the value dictionary for the current flow and insert it into the featuresDict
            flowParametes = {
                'Number of Ports': len(uniquePorts), #represents number of unique destination ports
                'Average Packet Length': np.mean(packetLengths) if packetLengths else 0, #represents average packet length
                'Packet Length Min': np.min(packetLengths) if packetLengths else 0, #represents min packet length
                'Packet Length Max': np.max(packetLengths) if packetLengths else 0, #represents max packet length
                'Packet Length Std': np.std(packetLengths) if packetLengths else 0, #represents std packet length
                'Packet Length Variance': np.var(packetLengths) if packetLengths else 0, #represents packet length variance
                'Total Length of Fwd Packet': np.sum(fwdLengths) if fwdLengths else 0, # total length of forward packets
                'Fwd Packet Length Max': np.max(fwdLengths) if fwdLengths else 0, #represents max forward packets length
                'Fwd Packet Length Mean': np.mean(fwdLengths) if fwdLengths else 0, #represents mean forward packets length
                'Fwd Packet Length Min': np.min(fwdLengths) if fwdLengths else 0, #represents min forward packets length
                'Fwd Packet Length Std': np.std(fwdLengths) if fwdLengths else 0, #represents std forward packets length
                'Bwd Packet Length Max': np.max(bwdLengths) if bwdLengths else 0, #represents max backward packets length
                'Bwd Packet Length Mean': np.mean(bwdLengths) if bwdLengths else 0, #represents mean backward packets length
                'Bwd Packet Length Min': np.min(bwdLengths) if bwdLengths else 0, #represents min backward packets length
                'Bwd Packet Length Std': np.std(bwdLengths) if bwdLengths else 0, #represents std backward packets length
                'Fwd Segment Size Avg': np.mean(fwdSegmentLengths) if fwdSegmentLengths else 0, #represents average forward segment size
                'Bwd Segment Size Avg': np.mean(bwdSegmentLengths) if bwdSegmentLengths else 0, #represents average backward segment size
                'Subflow Fwd Bytes': np.sum(fwdLengths) / subflowCount if subflowCount > 0 else 0, #represents subflow bytes of forward packets
                'SYN Flag Count': synFlags, #represents SYN flag count
                'ACK Flag Count': ackFlags, #represents ACK flag count
                'RST Flag Count': rstFlags, #represents RST flag count
                'Flow Duration': flowDuration if flowDuration else 0, #represents flow duration, sum of all IAT of packets
                'Packets Per Second': len(packetList) / flowDuration if flowDuration > 0 else 0, #represents packets per second in flow
                'IAT Max': np.max(interArrivalTimes) if interArrivalTimes else 0, #represents max inter-arrival time
                'IAT Mean': np.mean(interArrivalTimes) if interArrivalTimes else 0, #represents mean inter-arrival time
                'IAT Std': np.std(interArrivalTimes) if interArrivalTimes else 0 #represents std inter-arrival time
            }   
            featuresDict[flow] = flowParametes #save the dictionary of values into the featuresDict
        return featuresDict


    # function for predicting PortScanning and DoS attacks given flow dictionary
    @staticmethod
    def PredictPortDoS(flowDict):
        # represents result of analysis dictionary {state: T/F, type: 1-PortScan / 2-DoS / 3-Together, attackDict: {}}
        result = {'state': False, 'type': 1, 'attackDict': {}}
        attackDict = {} #represents attack dict with anomalies
        try: 
            # extract keys and values from flowDict and save it as a DataFrame
            keyColumns = ['srcIp', 'srcMac', 'dstIp', 'dstMac', 'protocol']
            flowDataframe = pd.DataFrame.from_dict(flowDict, orient='index').reset_index()
            flowDataframe.columns = keyColumns + flowDataframe.columns[5:].to_list() #rename the column names of the keys
            valuesDataframe = flowDataframe.drop(keyColumns, axis=1)

            # scale the input data and predict the scaled input
            scaledDataframe = PortScanDoS.loadedScaler.transform(valuesDataframe)
            valuesDataframe = pd.DataFrame(scaledDataframe, columns=PortScanDoS.selectedColumns)
            predictions = PortScanDoS.loadedModel.predict(valuesDataframe)
            flowDataframe.loc[:, 'Result'] = predictions
            flowDataframe.loc[:, 'timestamp'] = np.full(shape=len(flowDataframe), fill_value=NetworkInformation.GetCurrentTimestamp(), dtype=object)
            attackDictKeys = keyColumns + ['Result'] #first 5 columns + 'Result'

            # check for PortScan and DoS attacks together in model predictions
            if (1 in predictions) and (2 in predictions):
                # we convert the dataframe into dict where each key is flow: (srcIp, srcMac, dstIp, dstMac, protocol, result), value: {details}
                attackDict = flowDataframe[flowDataframe['Result'] != 0].set_index(attackDictKeys).to_dict(orient='index') #indication of PortScan and DoS attacks together
                raise PortScanDoSException( #throw an exeption to inform user of its presence
                    'Detected PortScan and DoS attack',
                    type=3,
                    attackDict=attackDict
                )

            # check for PortScan attacks in model predictions
            elif 1 in predictions:
                # we convert the dataframe into dict where each key is flow: (srcIp, srcMac, dstIp, dstMac, protocol, result), value: {details}
                attackDict = flowDataframe[flowDataframe['Result'] == 1].set_index(attackDictKeys).to_dict(orient='index') #indication of PortScan attack
                raise PortScanDoSException( #throw an exeption to inform user of its presence
                    'Detected PortScan attack',
                    type=1,
                    attackDict=attackDict
                )

            # check for DoS attacks in model predictions
            elif 2 in predictions:
                # we convert the dataframe into dict where each key is flow: (srcIp, srcMac, dstIp, dstMac, protocol, result), value: {details}
                attackDict = flowDataframe[flowDataframe['Result'] == 2].set_index(attackDictKeys).to_dict(orient='index') #indication of DoS attack
                raise PortScanDoSException( #throw an exeption to inform user of its presence
                    'Detected DoS attack',
                    type=2,
                    attackDict=attackDict
                )

            # print the dataframe and other data to the terminal
            print(
                '#' + '=' * 155 + '#\n'
                f'\n |>> No Port Scanning / DoS attacks where detected <<|\n |>> Number of flows in current cycle: {len(flowDataframe)} <<|'
                f'\n\n |>> Currect Cycle Dataframe: <<|\n\n{flowDataframe[keyColumns + ['Result', 'timestamp']]}'
                '\n' + '#' + '=' * 155 + '#'
            )

            result['state'] = True #indication for no attacks

        except PortScanDoSException as e: #if we received PortScanDoSException we alert the user
            result.update({'state': False, 'type': e.type, 'attackDict': e.attackDict}) #indication of attack
            print(e)
        except Exception as e: #we catch an exception if something happend
            print(f'Error occurred: {e}')
        finally:
            return result

#--------------------------------------------PORT-SCANNING-DoS-END-------------------------------------------#

#-----------------------------------------------DNS-TUNNELING------------------------------------------------#
class DNSTunnelingException(Exception):
    def __init__(self, message, type, attackDict):
        super().__init__(message)
        self.type = type #represents the type of dns tunneling attack (default 1)
        self.attackDict = attackDict #represents the attack dict with detected attack flows

    # str representation of dns tunneling exception for showing results
    def __str__(self):
        details = '\n##### DNS Tunneling ATTACK ######\n'
        details += '\n'.join([f'''[*] Source IP: {flow[0]} , Source Mac: {flow[1]} , Destination IP: {flow[2]}, Destination Mac: {flow[3]} , Protocol: {flow[4]}'''
                        for flow in self.attackDict])
        return f'{self.args[0]}\nDetails:\n{details}\n'


# static class that represents the collection and detection of DNS Tunneling attack
class DNSTunneling(ABC):
    loadedModel = joblib.load(currentDir.parent / 'models' / 'dns_svm_model.pkl') #load SVM model for DNS tunneling
    loadedScaler = joblib.load(currentDir.parent / 'models' / 'dns_scaler.pkl') #load scaler for SVM model
    selectedColumns = [
        'A Record Count', 'AAAA Record Count', 'CName Record Count', 'TXT Record Count', 'MX Record Count', 'DF Flag Count',
        'Average Response Data Length', 'Min Response Data Length', 'Max Response Data Length', 'Average Domain Name Length',
        'Min Domain Name Length', 'Max Domain Name Length', 'Average Sub Domain Name Length', 'Min Sub Domain Name Length', 
        'Max Sub Domain Name Length', 'Average Packet Length', 'Min Packet Length', 'Max Packet Length', 'Number of Domian Names',
        'Number of Sub Domian Names', 'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Total Number of Packets', 
        'Flow Duration', 'IAT Max', 'IAT Mean', 'IAT Std'
    ]

    # function for processing the flowDict and creating the dataframe that will be passed to classifier
    @staticmethod
    def ProcessFlows(dnsDict): 
        featuresDict = {} #represents our features dict where each flow tuple has its corresponding features

        # iterate over our flow dict and calculate features
        for flow, packetList in dnsDict.items():
            ARecordCount = 0 #represennts number of A record (ipv4) packets in flow
            AAAARecordCount = 0 #represennts number of AAAA record (ipv6) packets in flow
            CNameRecordCount = 0 #represents number of C-Name record packets in flow
            TxtRecordCount = 0 #represennts number of TXT record packets in flow
            MXRecordCount = 0 #represents number of MX record packets in flow
            ipDfFlags = 0 #represents DF flag of ip header
            uniqueDomainNames = set() #represents unique domian names in packetes
            uniqueSubDomainNames = set() #represents unique sub domian names in packetes
            domainNameLengths = [] #represents the domian name lengths
            subDomainLengths = [] #represents the sub domain name lengths
            responseDataLengths = [] #represents the response data lengths
            packetLengths = [] #represents packet lengths
            fwdLengths = [] #represents length of forward packets in flow
            bwdLengths = [] #represents length of backward packets in flow
            timestamps = [] #represents timestamps of each packet in flow

            # iterate over each packet in flow
            for packet in packetList:
                if isinstance(packet, DNS_Packet):
                    # add packet length to list
                    packetLengths.append(packet.packetLen)

                    # append each packet timestemp to our list for IAT
                    if packet.time:
                        timestamps.append(packet.time)
                    
                    # check the dns sub type and increment the correct counter
                    if packet.dnsSubType == 1: #means A record
                        ARecordCount += 1
                    elif packet.dnsSubType == 5: #means C-Name record
                        CNameRecordCount += 1
                    elif packet.dnsSubType == 15: #means MX record
                        MXRecordCount += 1
                    elif packet.dnsSubType == 16: #means TXT record
                        TxtRecordCount += 1
                    elif packet.dnsSubType == 28: #means AAAA record
                        AAAARecordCount += 1

                    # check DF flag in ipv4 and increment counter if set
                    if packet.ipFlagDict.get('DF'):
                        ipDfFlags += 1
                    
                    if packet.srcIp == flow[0]: #means forward packet
                        # add forward packet lengths
                        fwdLengths.append(packet.headerLen)
                        if packet.dnsType == 'Response': #means response packet
                            # add response data to response data list
                            if packet.dnsData:
                                totalLength = len(packet.dnsData) #represents total length of packets
                                if isinstance(packet.dnsData, list): #if data is list we convert it
                                    totalLength = np.sum([len(response) for response in packet.dnsData])
                                elif isinstance(packet.dnsData, dict): #if data is dict we convert it
                                    totalLength = np.sum([len(value) for value in packet.dnsData.values()])
                                responseDataLengths.append(totalLength) #add the total length to our list

                    else: #else means backward packets
                        # add backward packet lengths
                        bwdLengths.append(packet.headerLen)
                        if packet.dnsType == 'Request': #means request packet
                            domainNameLengths.append(len(packet.dnsDomainName)) #add domian name length
                            subdomains = str(packet.dnsDomainName).split('.') #get all subdomain names
                            subDomainLengths.append(np.mean([len(subdomain) for subdomain in subdomains])) 

                            #check if request domain name is unique and not in our set
                            if packet.dnsDomainName not in uniqueDomainNames:
                                uniqueDomainNames.add(packet.dnsDomainName) #add domain name to set
                            
                            # check if the subdomains are unique and not in our set
                            for subdomain in subdomains:
                                if subdomain not in uniqueDomainNames:
                                    uniqueSubDomainNames.add(subdomain)

            # calculate inter-arrival time features (IAT) and flow duration
            interArrivalTimes = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
            flowDuration = np.sum(interArrivalTimes) if interArrivalTimes else 0

            # calculate the value dictionary for the current flow and insert it into the featuresDict
            flowParametes = {
                'A Record Count': ARecordCount, #represents A record count
                'AAAA Record Count': AAAARecordCount, #represents AAAA record count
                'CName Record Count': CNameRecordCount, #represents C-Name record count
                'TXT Record Count': TxtRecordCount, #represents TXT record count
                'MX Record Count': MXRecordCount, #represents MX record count
                'DF Flag Count': ipDfFlags, #represents DF flag count
                'Average Response Data Length': np.mean(responseDataLengths) if responseDataLengths else 0, #represents average response data length
                'Min Response Data Length': np.min(responseDataLengths) if responseDataLengths else 0, #represents min response data length
                'Max Response Data Length': np.max(responseDataLengths) if responseDataLengths else 0, #represents max response data length
                'Average Domain Name Length': np.mean(domainNameLengths) if domainNameLengths else 0, #represents average domain name length
                'Min Domain Name Length': np.min(domainNameLengths) if domainNameLengths else 0, #represents min domain name length
                'Max Domain Name Length': np.max(domainNameLengths) if domainNameLengths else 0, #represents max domain name length
                'Average Sub Domain Name Length': np.mean(subDomainLengths) if subDomainLengths else 0, #represents average sub domain name length
                'Min Sub Domain Name Length': np.min(subDomainLengths) if subDomainLengths else 0, #represents min sub domain name length
                'Max Sub Domain Name Length': np.max(subDomainLengths) if subDomainLengths else 0, #represents max sub domain name length
                'Average Packet Length': np.mean(packetLengths) if packetLengths else 0, #represents average packet length
                'Min Packet Length': np.min(packetLengths) if packetLengths else 0, #represents min packet length
                'Max Packet Length': np.max(packetLengths) if packetLengths else 0, #represents max packet length
                'Number of Domian Names': len(uniqueDomainNames) if uniqueDomainNames else 0, #represents number of unique domain names
                'Number of Sub Domian Names': len(uniqueSubDomainNames) if uniqueSubDomainNames else 0, #represents number of unique sub domain names
                'Total Length of Fwd Packet': np.sum(fwdLengths) if fwdLengths else 0, #represents total length of forward packets
                'Total Length of Bwd Packet': np.sum(bwdLengths) if bwdLengths else 0, #represents total length of backward packets
                'Total Number of Packets': len(packetList) if packetList else 0, #represents total number of packets in flow
                'Flow Duration': flowDuration if flowDuration else 0, #represents flow duration, sum of all IAT of packets
                'IAT Max': np.max(interArrivalTimes) if interArrivalTimes else 0, #represents max inter-arrival time
                'IAT Mean': np.mean(interArrivalTimes) if interArrivalTimes else 0, #represents min inter-arrival time
                'IAT Std': np.std(interArrivalTimes) if interArrivalTimes else 0 #represents std inter-arrival time
            }
            featuresDict[flow] = flowParametes #save the dictionary of values into the featuresDict
        return featuresDict


    # function for predicting DNS Tunneling attack given flow dictionary
    @staticmethod
    def PredictDNS(flowDict):
        # represents result of analysis dictionary {state: T/F, type: 1-DnsTunneling, attackDict: {}}
        result = {'state': False, 'type': 1, 'attackDict': {}}
        attackDict = {} #represents attack dict with anomalies
        try: 
            # extract keys and values from flowDict and save it as a DataFrame
            keyColumns = ['srcIp', 'srcMac', 'dstIp', 'dstMac', 'protocol']
            flowDataframe = pd.DataFrame.from_dict(flowDict, orient='index').reset_index() 
            flowDataframe.columns = keyColumns + flowDataframe.columns[5:].to_list() #rename the column names of the keys
            valuesDataframe = flowDataframe.drop(keyColumns, axis=1)

            # scale the input data and predict the scaled input
            scaledDataframe = DNSTunneling.loadedScaler.transform(valuesDataframe)
            valuesDataframe = pd.DataFrame(scaledDataframe, columns=DNSTunneling.selectedColumns)
            predictions = DNSTunneling.loadedModel.predict(valuesDataframe)
            flowDataframe.loc[:, 'Result'] = predictions
            flowDataframe.loc[:, 'timestamp'] = np.full(shape=len(flowDataframe), fill_value=NetworkInformation.GetCurrentTimestamp(), dtype=object)
            attackDictKeys = keyColumns + ['Result'] #first 5 columns + 'Result'

            # check for DNS Tunneling attacks in model predictions
            if 1 in predictions:
                # we convert the dataframe into dict where each key is flow: (srcIp, srcMac, dstIp, dstMac, protocol, result), value: {details}
                attackDict = flowDataframe[flowDataframe['Result'] == 1].set_index(attackDictKeys).to_dict(orient='index') #indication of DNS attack
                raise DNSTunnelingException( #throw an exeption to inform user of its presence
                    'Detected DNS Tunneling attack',
                    type=1,
                    attackDict=attackDict
                )

            # print the dataframe and other data to the terminal
            print(
                '#' + '=' * 155 + '#\n'
                f'\n |>> No DNS Tunneling attacks where detected <<|\n |>> Number of flows in current cycle: {len(flowDataframe)} <<|'
                f'\n\n |>> Currect Cycle Dataframe: <<|\n\n{flowDataframe[keyColumns + ['Result', 'timestamp']]}'
                '\n' + '#' + '=' * 155 + '#'
            )

            result['state'] = True #indication for no attacks

        except DNSTunnelingException as e: #if we received DNSTunnelingException we alert the user
            result.update({'state': False, 'type': e.type, 'attackDict': e.attackDict}) #indication of attack
            print(e)
        except Exception as e: #we catch an exception if something happend
            print(f'Error occurred: {e}')
        finally:
            return result

#----------------------------------------------DNS-TUNNELING-END---------------------------------------------#

#--------------------------------------------SAVING-COLLECTED-DATA-------------------------------------------#

# static class that has some basic functionality for saving the collected data from the sniffer
class SaveData(ABC):

    # function for saving the collected flows into a CSV file (used to collect benign data)
    @staticmethod
    def SaveCollectedData(flows, filePath='benign_dataset.csv', selectedColumns=PortScanDoS.selectedColumns):
        collectedRows = 0 # represents number of collected rows
        
        try:
            # create a dataframe from the collected data
            values = list(flows.values())

            # reorder the values in the same order that the models were trained on
            orderedValues = [[valueDict[col] for col in selectedColumns] for valueDict in values]
            valuesDataframe = pd.DataFrame(orderedValues, columns=selectedColumns)
            
            # write dataframe values to csv file or append to an existing csv file
            valuesDataframe.to_csv(filePath, mode='a', header=not Path(filePath).exists(), index=False)
            collectedRows = valuesDataframe.shape[0] #save number of rows written

            return collectedRows
        
        # if file is open in another program we avoid exeption and return 0 to indicate no collected rows
        except Exception:
            return collectedRows


    # function for saving the collected flows into a txt file
    @staticmethod
    def SaveFlowsInFile(flows, filePath='detected_flows.txt'):
        # write result of flows captured in txt file
        with open(filePath, 'w', encoding='utf-8') as file:
            # iterate ove reach flow in flows dictionary
            for flow, features in flows.items():
                file.write(f'Flow: {flow}\n') #write flow info
                # iterate over each feature of flow
                for feature, value in features.items():
                    file.write(f' {feature}: {value}\n') #write flow's feature
                file.write('=' * 64 + '\n') #add seperator

#------------------------------------------SAVING-COLLECTED-DATA-END-----------------------------------------#