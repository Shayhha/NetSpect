import sys, os, logging, joblib, time
import numpy as np
import pandas as pd
from abc import ABC, abstractmethod
from ipaddress import ip_address, ip_network, IPv4Interface
from psutil import net_if_addrs, net_if_stats
from scapy.all import sniff, get_if_list, srp, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, Raw, conf 
from scapy.layers.dns import DNS
from collections import defaultdict
import shutil #temporary import for saving a copy of a file with false positive data

# dynamically add the src directory to sys.path, this allows us to access all moduls in the project at run time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
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
        currentInterface = SniffNetwork.networkInfo.get(SniffNetwork.selectedInterface) #the values of the selected network interface

        # extract flow tuple from packet
        srcIp, dstIp, protocol = self.srcIp, self.dstIp, self.protocol

        #we create the flow tuple based on lexicographic order if it does not contain host ip address to ensure consistency
        if (dstIp in currentInterface.get('ipv4Addrs')) or (dstIp in currentInterface.get('ipv6Addrs')): #check if dst ip is our ip address
            return (srcIp, dstIp, protocol) #return the flow tuple of packet with host ip as dst ip in tuple

        elif (srcIp in currentInterface.get('ipv4Addrs')) or (srcIp in currentInterface.get('ipv6Addrs')) or (srcIp > dstIp): #check if tuple src ip is our ip address or if its not normalized 
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
    dnsPacketLen = None

    def __init__(self, packet=None, dnsId=None):
        super().__init__('DNS', packet) #call parent ctor
        if packet.haslayer(DNS): #checks if packet is DNS
            self.packetType = DNS #add packet type
        self.dnsId = dnsId
        self.dnsPacketLen = len(self.packet[DNS])
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

#----------------------------------------------SNIFF-NETWORK-------------------------------------------------#

# static class that represents the main functionality of the program, to sniff network packets and collect data about them in-order to detect attacks
class SniffNetwork(ABC):
    networkInfo = None #represents a dict of dicts where each inner dict represents an available network interface
    selectedInterface = None #the user-selected interface name: 'Ethernet' / 'en6'
    startTime, timeoutTime, threshold = None, 40, 10000 #represents our stop conditions for the sniffing, stopping after x time or a max amount of packets reached
    portScanDosDict = {} #represents dict of {(flow tuple) - [packet list]} related to port scanning and dos
    dnsDict = {} #represents dict of packets related to dns tunneling 
    arpDict = {} #represents dict of packets related to arp poisoning
    tcpUdpCounter = 0 #global counter for tcp and udp packets
    dnsCounter = 0 #global counter for dns packets
    arpCounter = 0 #global counter for arp packets

    # function for initializing the dict of data about all available interfaces
    @staticmethod
    def InitNetworkInfo():
        SniffNetwork.networkInfo = SniffNetwork.GetNetworkInterfaces() #find all available network interface and collect all data about these interfaces
        return SniffNetwork.networkInfo.keys() #return all available interface names for the user to select
    

    # function for initialing a packet scan on desired network interface
    @staticmethod
    def ScanNetwork():
        try:
            print('Starting Network Scan...')
            availableInterfaces = SniffNetwork.InitNetworkInfo() #find all available network interfaces
            ArpSpoofing.InitAllArpTables(SniffNetwork.networkInfo.get(SniffNetwork.selectedInterface)) #initialize all of our static arp tables with subnets

            print(f'\n{SniffNetwork.networkInfo.get(SniffNetwork.selectedInterface)}\n') #print host selected interface info (name, ip addresses, mac, etc.)
            ArpSpoofing.printArpTables() #print all initialized arp tables

            # call scapy sniff function with desired interface and sniff network packets
            SniffNetwork.startTime = time.time() #starting a timer to determin when to stop the sniffer
            sniff(iface=SniffNetwork.selectedInterface, prn=SniffNetwork.PacketCapture, stop_filter=SniffNetwork.StopScan, store=0)
        except PermissionError: #if user didn't run with administrative privileges 
            print('Permission denied. Please run again with administrative privileges.') #print permission error message in terminal
        except ArpSpoofingException as e: #if we recived ArpSpoofingException we alert the user
            print(e)
        except Exception as e: #we catch an exception if something happend while sniffing
            print(f'An error occurred while sniffing: {e}') #print error message in terminal
        finally:
            print('Finsihed Network Scan.\n')


    # function for checking when to stop sniffing packets, stop condition
    @staticmethod
    def StopScan(packet):
        # return True if ( ((time.time() - SniffNetwork.startTime) > SniffNetwork.timeoutTime) or (SniffNetwork.arpCounter >= 20) ) else False
        # return True if ( ((time.time() - SniffNetwork.startTime) > SniffNetwork.timeoutTime) or (SniffNetwork.tcpUdpCounter >= SniffNetwork.threshold) ) else False
        return True if ( ((time.time() - SniffNetwork.startTime) > SniffNetwork.timeoutTime) or (SniffNetwork.dnsCounter >= 350) ) else False


    # function for capturing specific packets for later analysis
    @staticmethod
    def PacketCapture(packet):
        captureDict = {TCP: SniffNetwork.handleTCP, UDP: SniffNetwork.handleUDP, DNS: SniffNetwork.handleDNS, ARP: SniffNetwork.handleARP} #represents dict with packet type and handler func

        # iterate over capture dict and find coresponding handler function for each packet
        for packetType, handler in captureDict.items():
            if packet.haslayer(packetType): #if we found matching packet we call its handle method
                handler(packet) #call handler method of each packet


    #--------------------------------------------HANDLE-FUNCTIONS------------------------------------------------#

    # method that handles TCP packets
    @staticmethod
    def handleTCP(packet):
        if packet.haslayer(DNS): #if we found a dns packet we also call dns handler
            SniffNetwork.handleDNS(packet) #call our handleDNS func
        TCP_Object = TCP_Packet(packet) #create a new object for packet
        flowTuple = TCP_Object.GetFlowTuple() #get flow representation of packet
        if flowTuple in SniffNetwork.portScanDosDict: #if flow tuple exists in dict
            SniffNetwork.portScanDosDict[flowTuple].append(TCP_Object) #append to list our packet
        else: #else we create new entry with flow tuple
            SniffNetwork.portScanDosDict[flowTuple] = [TCP_Object] #create new list with packet
        SniffNetwork.tcpUdpCounter += 1


    # method that handles UDP packets
    @staticmethod
    def handleUDP(packet):
        if packet.haslayer(DNS): #if we found a dns packet we also call dns handler
            SniffNetwork.handleDNS(packet) #call our handleDNS func
        UDP_Object = UDP_Packet(packet) #create a new object for packet
        flowTuple = UDP_Object.GetFlowTuple() #get flow representation of packet
        if flowTuple in SniffNetwork.portScanDosDict: #if flow tuple exists in dict
            SniffNetwork.portScanDosDict[flowTuple].append(UDP_Object) #append to list our packet
        else: #else we create new entry with flow tuple
            SniffNetwork.portScanDosDict[flowTuple] = [UDP_Object] #create new list with packet
        SniffNetwork.tcpUdpCounter += 1


    # method that handles DNS packets
    @staticmethod
    def handleDNS(packet):
        # DNS_Object = DNS_Packet(packet, dnsCounter) #create a new object for packet
        # dnsDict[DNS_Object.dnsId] = DNS_Object #insert it to packet dictionary
        DNS_Object = DNS_Packet(packet) #create a new object for packet
        flowTuple = DNS_Object.GetFlowTuple() #get flow representation of packet
        if flowTuple in SniffNetwork.dnsDict: #if flow tuple exists in dict
            SniffNetwork.dnsDict[flowTuple].append(DNS_Object) #append to list our packet
        else: #else we create new entry with flow tuple
            SniffNetwork.dnsDict[flowTuple] = [DNS_Object] #create new list with packet
        SniffNetwork.dnsCounter += 1


    # method that handles ARP packets
    @staticmethod
    def handleARP(packet):
        ARP_Object = ARP_Packet(packet, SniffNetwork.arpCounter) #create a new object for packet
        SniffNetwork.arpDict[ARP_Object.arpId] = ARP_Object #insert it to packet dictionary
        SniffNetwork.arpCounter += 1 #increase the counter

    #------------------------------------------HANDLE-FUNCTIONS-END----------------------------------------------#

    #--------------------------------------------HELPER-FUNCTIONS------------------------------------------------#

    # method to print all available interfaces
    @staticmethod
    def GetAvailableInterfaces():
        # get a list of all available network interfaces
        interfaces = get_if_list() #call get_if_list method to retrieve the available interfaces
        if interfaces: #if there are interfaces we print them
            print('Available network interfaces:')
            i = 1 #counter for the interfaces 
            for interface in interfaces: #print all availabe interfaces
                if sys.platform.startswith('win32'): #if ran on windows we convert the guid number
                    print(f'{i}. {SniffNetwork.GuidToStr(interface)}')
                else: #else we are on other os so we print the interface 
                    print(f'{i}. {interface}')
                i += 1
        else: #else no interfaces were found
            print('No network interfaces found.')


    # method for retrieving interface name from GUID number (Windows only)
    @staticmethod
    def GuidToStr(guid):
        try: #we try to import the specific windows method from scapy library
            from scapy.arch.windows import get_windows_if_list
        except ImportError as e: #we catch an import error if occurred
            print(f'Error importing module: {e}') #print the error
            return guid #we exit the function
        interfaces = get_windows_if_list() #use the windows method to get list of guid number interfaces
        for interface in interfaces: #iterating over the list of interfaces
            if interface['guid'] == guid: #we find the matching guid number interface
                return interface['name'] #return the name of the interface associated with guid number
        return guid #else we didnt find the guid number so we return given guid


    # method for retrieving the network interfaces
    @staticmethod
    def GetNetworkInterfaces_OLD():
        networkNames = ['eth', 'wlan', 'en', 'enp', 'wlp', 'lo', 'Ethernet', 'Wi-Fi', '\\Device\\NPF_Loopback'] #this list represents the usual network interfaces that are available in various platfroms
        interfaces = get_if_list() #get a list of the network interfaces
        if sys.platform.startswith('win32'): #if current os is Windows we convert the guid number to interface name
            interfaces = [SniffNetwork.GuidToStr(interface) for interface in interfaces] #get a new list of network interfaces with correct names instead of guid numbers
        matchedInterfaces = [interface for interface in interfaces if any(interface.startswith(name) for name in networkNames)] #we filter the list to retrieving ethernet and wifi interfaces
        return matchedInterfaces #return the matched interfaces as list


    # function for collecting all available interfaces on the current machine and as much data about them as possible including name, speed, ip addresses, subnets and more
    @staticmethod
    def GetNetworkInterfaces():
        supportedInterfaces = ['eth', 'wlan', 'en', 'enp', 'wlp', 'lo', 'Ethernet', 'Wi-Fi', '\\Device\\NPF_Loopback'] #this list represents the usual network interfaces that are available in various platfroms
        networkInterfaces = {} #represents network interfaces dict where keys are name of interface and value is interface dict
        ifaceStats = net_if_stats() #for getting extra info about each interface using stats function

        # iterate through all network interfaces and initialize our network interfaces dict
        for iface in conf.ifaces.values():
            # we add only interfaces we support with scapy and that are up
            if iface.ips and any(iface.name.startswith(name) for name in supportedInterfaces):
                # initialize our ipv4 and ipv6 addresses (always dict of two elements: 4: ipv4Addrs, 6: ipv6Addrs)
                ipv4Addrs, ipv6Addrs, ipv4Subnets, ipv6Subnets = iface.ips[4], iface.ips[6], [], set()

                # initialize ipv4 subnets based on ipv4 ips we found
                for ipAddress in ipv4Addrs:
                    netmask = SniffNetwork.GetNetmaskFromIp(ipAddress) #get netmask with our function
                    if ipAddress and netmask:
                        subnet = IPv4Interface(f'{ipAddress}/{netmask}').network
                        ipv4Subnets.append((str(subnet), f'{'.'.join(ipAddress.split('.')[:3])}.0/24', netmask)) #list of tuples such that (subnet (real), range(/24), netmask)

                # initialize ipv6 subnets based on ipv6 ips we found, excluding loopback
                for ipAddress in ipv6Addrs:
                    if ipAddress and (not ipAddress.startswith('::1')) and (not ipAddress.endswith('::1')): #exclude loopback
                        ipv6Subnets.add(f'{':'.join(ipAddress.split(':')[:4])}::/64') #represents /64 subnet estimation

                # continue to next interface if this one does not have any ip address
                if (len(ipv4Addrs) == 0) and (len(ipv6Addrs) == 0): continue

                # initialize interface dict with all given information
                interfaceDict = {
                    'name': iface.name if iface.name else '',
                    'description': iface.description if iface.description else '',
                    'status': ifaceStats.get(iface.name).isup if ifaceStats.get(iface.name) else 'None',
                    'maxSpeed': ifaceStats.get(iface.name).speed if ifaceStats.get(iface.name) else 'None',
                    'maxTransmitionUnit': ifaceStats.get(iface.name).mtu if ifaceStats.get(iface.name) else 'None',
                    'mac': iface.mac if iface.mac else '',
                    'ipv4Addrs': ipv4Addrs,
                    'ipv4Info': ipv4Subnets,
                    'ipv6Addrs': ipv6Addrs,
                    'ipv6Info': list(ipv6Subnets)
                }
                networkInterfaces[interfaceDict['name']] = interfaceDict #add interface to our network interfaces
        
        return networkInterfaces #return the filtered and matched interfaces


    # function for getting a correct netmask for a given IP address using psutil
    @staticmethod
    def GetNetmaskFromIp(ipAddress):
        interfaces = net_if_addrs()

        # iterate over each interface and find correct netmask
        for addresses in interfaces.values():
            for addr in addresses:
                if addr.family.name == 'AF_INET' and addr.address == ipAddress:
                    return addr.netmask #return the subnet mask if the IP matches
                    
        return None #return None if the IP is not found

    #-------------------------------------------HELPER-FUNCTIONS-END---------------------------------------------#

#---------------------------------------------SNIFF-NETWORK-END----------------------------------------------#

#-----------------------------------------------ARP-SPOOFING-------------------------------------------------#
class ArpSpoofingException(Exception):
    def __init__(self, message, state, details):
        super().__init__(message)
        self.state = state #represents the state of attack, 1 means we found ip assigned to many macs, 2 means mac assigned to many ips
        self.details = details #represents additional details about the spoofing

    # str representation of arp spoofing exception for showing results
    def __str__(self):
        detailsList = '\n##### ARP SPOOFING ATTACK ######\n'
        detailsList += '\n'.join([f'[*] {key} ==> {', '.join(value)}' for key, value in self.details.items()])
        return f'{self.args[0]}\nDetails:\n{detailsList}\n'


# class that represents a single ARP table, contains an IP to MAC table and an inverse table, has a static method for initing both ARP tables
class ArpTable():
    subnet = None #3-tuple (subnet(real) , range(/24) , netmask)
    arpTable = None #regular IP to MAC ARP table
    invArpTable = None #inverse ARP table, MAC to IP

    def __init__(self, subnet):
        self.subnet = subnet 
        self.arpTable, self.invArpTable = ArpTable.InitArpTable(subnet[1])


    # fucntion that initializes the static arp table for testing IP-MAC pairs 
    @staticmethod
    def InitArpTable(ipRange='192.168.1.0/24'):
        arpTable = {} #represents our arp table dict (ip to mac)
        invArpTable = {} #represents our inverse (mac to ip), used for verification
        attacksDict = {'ipToMac': {}, 'macToIp': {}} #represents attack dict with anomalies
        arpRequest = ARP(pdst=ipRange) #create arp request packet with destination ip range
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')  #create broadcast ethernet frame broadcast
        arpRequestBroadcast = broadcast / arpRequest #combine both arp request and ethernet frame 
        
        # send the ARP request and capture the responses
        # srp function retunes tuple (response packet, received device)
        answeredList = srp(arpRequestBroadcast, timeout=0.75, verbose=False)[0]
        
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

        # we check if one of the attack dicts is not empty, means we have an attack
        if attacksDict['ipToMac']: #means we have an ip that has many macs
            #throw an exeption to inform user of its presence
            raise ArpSpoofingException(
                'Detected ARP spoofing incidents: IP-to-MAC anomalies',
                state=1,
                details={ip: list(macs) for ip, macs in attacksDict['ipToMac'].items()}
            )
        elif attacksDict['macToIp']: #means we have a mac that has many ips
            # throw an exeption to inform user of its presence
            raise ArpSpoofingException(
                'Detected ARP spoofing incidents: MAC-to-IP anomalies',
                state=2,
                details={mac: list(ips) for mac, ips in attacksDict['macToIp'].items()}
            )
        
        return arpTable, invArpTable


# static class that represents the detection of ARP Spoofing attack using an algorithem to detect duplications in ARP tables based on collected ARP packets
class ArpSpoofing(ABC):
    arpTables = {} #represents all ARP tables where the key of the table is the subnet, each inner ARP table is a tuple (arpTable, invArpTable) with mapping of IP->MAC and MAC->IP in each table in tuple
    cache = {} #represents a dict with cache of all ip addresses that matched a subnet
    interfaceInfo = {} #represents the dict with all data about the user-selected network interface

    # function that iterates over available ipv4 subnets and inits an ARP table for each one
    @staticmethod
    def InitAllArpTables(interfaceInfo):
        # iterate over all given subnets, for each check if an ARP table exists for it
        for subnet in interfaceInfo.get('ipv4Info'):
            if not ArpSpoofing.arpTables.get(subnet[0]):
                # init a new ARP tabel if an ARP table for that subnet is not initialized
                subnetObject = ip_network(subnet[0])
                ArpSpoofing.arpTables[subnetObject] = ArpTable(subnet) 


    # function for getting the correct arp table given an IP address
    @staticmethod
    def getSubnetForIP(ipAddress): 
        try:
            if ipAddress in ArpSpoofing.cache: #check if the given IP address was cached
                return ArpSpoofing.cache[ipAddress]

            # check if the IP address object is in the subnet list
            ipObject = ip_address(ipAddress) #convert to IP address to ipaddress object
            for subnet in ArpSpoofing.arpTables.keys():
                if ipObject in subnet:
                    ArpSpoofing.cache[ipAddress] = subnet
                    return subnet
            
            ArpSpoofing.cache[ipAddress] = None
            return None
        except ValueError as e:
            print(f'Invalid IP or Subnet: {e}')
            return None
  

    # function for printing all arp tables
    @staticmethod
    def printArpTables():
        if ArpSpoofing.arpTables:
            print('All ARP Tables:')
            for subnet, arpTableObject in ArpSpoofing.arpTables.items():
                if arpTableObject:
                    print(f'ARP Table: {subnet}\n')
                    for key, value in arpTableObject.arpTable.items():
                        print(f'IP: {key} --> MAC: {value}')
                    print('===========================================\n')
        print('\n')


    # function for processing arp packets and check for arp spoofing attacks
    @staticmethod
    def ProcessARP():
        attacksDict = {} #represents attack dict with anomalies
        try:
            if not ArpSpoofing.arpTables: #check that arpTable is initialzied
                raise RuntimeError('Error, cannot process ARP packets, ARP tables are not initalized.')

            # iterate over our arp dictionary and check each packet for inconsistencies
            for packet in SniffNetwork.arpDict.values():
                # we check that packet has a source ip and also that its not assinged to a temporary ip (0.0.0.0)
                if isinstance(packet, ARP_Packet) and packet.srcIp != None and packet.srcIp != '0.0.0.0':
                    subnet = ArpSpoofing.getSubnetForIP(packet.srcIp)
                    if subnet == None: 
                        print(f'Error, received an ARP packet from an outside subnet, no arp table mached the ARP packet source IP address "{packet.srcIp}"')
                        continue
                    arpTableObject = ArpSpoofing.arpTables.get(subnet) #get the specific arpTable using the correct subnet

                    if packet.srcIp not in arpTableObject.arpTable: #means ip is not present in our arp table
                        # means mac was assinged to different ip, we assume there's a possiblility 
                        # that this device got assigned a new ip from dhcp server
                        if packet.srcMac in arpTableObject.invArpTable:
                            oldIp = arpTableObject.invArpTable[packet.srcMac] #save old ip that was assigned to this mac
                            del arpTableObject.arpTable[oldIp] #remove old ip entry from arp table
                            del arpTableObject.invArpTable[packet.srcMac] #remove mac from inverse arp table

                        # we create new temp arp table to check if we got valid response from only one device and that mac's match
                        ipArpTable = ArpTable.InitArpTable(packet.srcIp) #initialize temp ip arp table for specific ip and check if valid
                        if ipArpTable[0]: #we check if there's a reply, if not we dismiss the packet
                            if ipArpTable[0][packet.srcIp] == packet.srcMac: #means macs match, valid 
                                arpTableObject.arpTable[packet.srcIp] = packet.srcMac #assign the mac address to its ip in our arp table
                                arpTableObject.invArpTable[packet.srcMac] = packet.srcIp #assign to the inverse arp table
                            else: #means macs dont match, we alret because differnet device asnwered us
                                ip, macs = packet.srcIp, {ipArpTable[0][packet.srcIp], packet.srcMac} #create the details for exception
                                attacksDict.setdefault(ip, set()).update(macs) #add an anomaly: same IP, different MAC

                    else: #means ip is present in our arp table, we check its parameters
                        if arpTableObject.arpTable[packet.srcIp] != packet.srcMac: #means we have a spoofed mac address
                            ip, macs = packet.srcIp, {arpTableObject.arpTable[packet.srcIp], packet.srcMac} #create the details for exception
                            attacksDict.setdefault(ip, set()).update(macs) #add an anomaly: same IP, different MAC

            if attacksDict: #means we detected an attack
                # throw an exeption to inform user of its presence
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
    

# static class that represents the collection and detection of PortScan and DoS attacks 
class PortScanDoS(ABC):
    selectedColumns = [
        'Number of Ports', 'Average Packet Size', 'Packet Length Min', 'Packet Length Max', 
        'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'Total Length of Fwd Packet', 
        'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Bwd Packet Length Max', 'Bwd Packet Length Mean', 
        'Bwd Packet Length Min', 'Bwd Packet Length Std', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg', 
        'Subflow Fwd Bytes', 'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count', 'Flow Duration', 
        'Packets Per Second', 'IAT Total', 'IAT Max', 'IAT Mean', 'IAT Std'
    ]

    # function for processing the flowDict and creating the dataframe that will be passed to classifier
    @staticmethod
    def ProcessFlows():
        featuresDict = defaultdict(dict) #represents our features dict where each flow tuple has its corresponding features

        # iterate over our flow dict and calculate features
        for flow, packetList in SniffNetwork.portScanDosDict.items():
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
                'Number of Ports': len(uniquePorts), # number of unique destination ports
                'Average Packet Size': np.mean(payloadLengths) if payloadLengths else 0,
                'Packet Length Min': np.min(payloadLengths) if payloadLengths else 0, # packet length features
                'Packet Length Max': np.max(payloadLengths) if payloadLengths else 0,
                'Packet Length Mean': np.mean(payloadLengths) if payloadLengths else 0,
                'Packet Length Std': np.std(payloadLengths) if payloadLengths else 0,
                'Packet Length Variance': np.var(payloadLengths) if payloadLengths else 0,
                'Total Length of Fwd Packet': np.sum(fwdLengths) if fwdLengths else 0, # total and average size features
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
    @staticmethod
    def PredictPortDoS(flowDict):
        try: 
            # extract keys and values from flowDict and save it as a DataFrame
            keyColumns = ['Src IP', 'Dst IP', 'Protocol']
            flowDataframe = pd.DataFrame.from_dict(flowDict, orient='index').reset_index()
            flowDataframe.columns = keyColumns + flowDataframe.columns[3:].to_list() #rename the column names of the keys
            keysDataframe = flowDataframe[keyColumns].copy()
            valuesDataframe = flowDataframe.drop(keyColumns, axis=1)

            # load the PortScanning and DoS model
            modelPath = getModelPath('port_scan_dos_svm_model.pkl')
            scalerPath = getModelPath('port_scan_dos_scaler.pkl')
            loadedModel = joblib.load(modelPath) 
            loadedScaler = joblib.load(scalerPath) 

            # scale the input data and predict the scaled input
            scaledDataframe = loadedScaler.transform(valuesDataframe)
            valuesDataframe = pd.DataFrame(scaledDataframe, columns=PortScanDoS.selectedColumns)
            predictions = loadedModel.predict(valuesDataframe)
            keysDataframe.loc[:, 'Result'] = predictions

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

        except PortScanDoSException as e: #if we recived ArpSpoofingException we alert the user
            print(e)
        except Exception as e: #we catch an exception if something happend
            print(f'Error occurred: {e}')
        finally:
            shutil.copy('detectedFlows.txt', f'{np.random.randint(1,1000000)}_detectedFlows.txt') # temporary code for saving false positive if the occure during scans

#--------------------------------------------PORT-SCANNING-DoS-END-------------------------------------------#

#-----------------------------------------------DNS-TUNNELING------------------------------------------------#
class DNSTunnelingException(Exception):
    def __init__(self, message, flows):
        super().__init__(message)
        self.flows = flows #represents the flow in which the attack was detected

    # str representation of dns tunneling exception for showing results
    def __str__(self):
        detailsList = '\n##### DNS Tunneling ATTACK ######\n'
        detailsList += '\n'.join([f'[*] Source IP: {flow['Src IP']} , Destination IP: {flow['Dst IP']} , Protocol: {flow['Protocol']}' for flow in self.flows])
        return f'{self.args[0]}\nDetails:\n{detailsList}\n'


# static class that represents the collection and detection of DNS Tunneling attack
class DNSTunneling(ABC):
    selectedColumns = [
        'A Record Count', 'AAAA Record Count', 'CName Record Count', 'TXT Record Count', 'MX Record Count', 'DF Flag Count',
        'Average Response Data Length', 'Min Response Data Length', 'Max Response Data Length', 'Average Domain Name Length',
        'Min Domain Name Length', 'Max Domain Name Length', 'Average Sub Domain Name Length', 'Min Sub Domain Name Length', 
        'Max Sub Domain Name Length', 'Average Packet Length', 'Min Packet Length', 'Max Packet Length', 'Number of Domian Names',
        'Number of Sub Domian Names', 'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Total Number of Packets', 
        'Flow Duration', 'IAT Total', 'IAT Max', 'IAT Mean', 'IAT Std'
    ]

    @staticmethod
    def ProcessFlows(): 
        featuresDict = defaultdict(dict) #represents our features dict where each flow tuple has its corresponding features

        # iterate over our flow dict and calculate features
        for flow, packetList in SniffNetwork.dnsDict.items():
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
            firstSeenPacket, lastSeenPacket = 0, 0 #represnts timestemps for first and last packets

            # iterate over each packet in flow
            for packet in packetList:
                if isinstance(packet, DNS_Packet):  
                    # append each packet timestemp to out list for IAT
                    if packet.time:
                        timestamps.append(packet.time)
                    
                        # for calculating flow duration
                        if firstSeenPacket == 0:
                            firstSeenPacket = packet.time
                        lastSeenPacket = packet.time

                    # add packet length and ip header length to lists
                    packetLengths.append(packet.packetLen)

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
                    if 'DF' in packet.ipFlagDict and packet.ipFlagDict['DF']:
                        ipDfFlags += 1
                    
                    if packet.srcIp == flow[0]: #means forward packet
                        fwdLengths.append(packet.dnsPacketLen)
                        if packet.dnsType == 'Response': #means response packet
                            # add response data to response data list
                            if packet.dnsData:
                                totalLength = len(packet.dnsData) #represents total length of packets
                                if isinstance(packet.dnsData, list): #if data is list we convert it
                                    totalLength = np.sum([len(response) for response in packet.dnsData])
                                elif isinstance(packet.dnsData, dict): #if data is dict we convert it
                                    totalLength = np.sum([len(value) for value in packet.dnsData.values()])
                                responseDataLengths.append(totalLength) #add the total length to our list

                    elif packet.srcIp == flow[1]: #else means backward packets
                        bwdLengths.append(packet.dnsPacketLen)
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
                        
            # inter-arrival time features (IAT) and flow duration
            interArrivalTimes = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
            flowDuration = lastSeenPacket - firstSeenPacket

            # calculate the value dictionary for the current flow and insert it into the featuresDict
            flowParametes = {
                'A Record Count': ARecordCount, # counters and flags
                'AAAA Record Count': AAAARecordCount,
                'CName Record Count': CNameRecordCount,
                'TXT Record Count': TxtRecordCount,
                'MX Record Count': MXRecordCount,
                'DF Flag Count': ipDfFlags,
                'Average Response Data Length': np.mean(responseDataLengths) if responseDataLengths else 0, # response data length
                'Min Response Data Length': np.min(responseDataLengths) if responseDataLengths else 0,
                'Max Response Data Length': np.max(responseDataLengths) if responseDataLengths else 0,
                'Average Domain Name Length': np.mean(domainNameLengths) if domainNameLengths else 0, # domain name length
                'Min Domain Name Length': np.min(domainNameLengths) if domainNameLengths else 0,
                'Max Domain Name Length': np.max(domainNameLengths) if domainNameLengths else 0,
                'Average Sub Domain Name Length': np.mean(subDomainLengths) if subDomainLengths else 0, # sub domain name length
                'Min Sub Domain Name Length': np.min(subDomainLengths) if subDomainLengths else 0,
                'Max Sub Domain Name Length': np.max(subDomainLengths) if subDomainLengths else 0,
                'Average Packet Length': np.mean(packetLengths) if packetLengths else 0, # packet length
                'Min Packet Length': np.min(packetLengths) if packetLengths else 0,
                'Max Packet Length': np.max(packetLengths) if packetLengths else 0,
                'Number of Domian Names': len(uniqueDomainNames) if uniqueDomainNames else 0, # unique domains and sub domains
                'Number of Sub Domian Names': len(uniqueSubDomainNames) if uniqueSubDomainNames else 0,
                'Total Length of Fwd Packet': np.sum(fwdLengths) if fwdLengths else 0, # total length of forward and backward packets
                'Total Length of Bwd Packet': np.sum(bwdLengths) if bwdLengths else 0, 
                'Total Number of Packets': len(packetList) if packetList else 0,
                'Flow Duration': flowDuration, # flow duration and packets per second in flow
                'IAT Total': np.sum(interArrivalTimes) if interArrivalTimes else 0, # inter-arrival time features (IAT)
                'IAT Max': np.max(interArrivalTimes) if interArrivalTimes else 0, 
                'IAT Mean': np.mean(interArrivalTimes) if interArrivalTimes else 0,
                'IAT Std': np.std(interArrivalTimes) if interArrivalTimes else 0
            }
            featuresDict[flow] = flowParametes #save the dictionary of values into the featuresDict
        return dict(featuresDict)


    # function for predicting DNS Tunneling attack given flow dictionary
    @staticmethod
    def PredictDNS(flowDict):
        try: 
            # extract keys and values from flowDict and save it as a DataFrame
            keyColumns = ['Src IP', 'Dst IP', 'Protocol']
            flowDataframe = pd.DataFrame.from_dict(flowDict, orient='index').reset_index() 
            flowDataframe.columns = keyColumns + flowDataframe.columns[3:].to_list() #rename the column names of the keys
            keysDataframe = flowDataframe[keyColumns].copy()
            valuesDataframe = flowDataframe.drop(keyColumns, axis=1)

            # load the PortScanning and DoS model
            modelPath = getModelPath('dns_svm_model.pkl')
            scalerPath = getModelPath('dns_scaler.pkl')
            loadedModel = joblib.load(modelPath) 
            loadedScaler = joblib.load(scalerPath) 

            # scale the input data and predict the scaled input
            scaledDataframe = loadedScaler.transform(valuesDataframe)
            valuesDataframe = pd.DataFrame(scaledDataframe, columns=DNSTunneling.selectedColumns)
            predictions = loadedModel.predict(valuesDataframe)
            keysDataframe.loc[:, 'Result'] = predictions

            # check for attacks in model predictions
            if 1 in predictions: #1 means DNS Tunneling attack
                raise DNSTunnelingException( #throw an exeption to inform user of its presence
                    'Detected DNS Tunneling attack',
                    flows=keysDataframe[keysDataframe['Result'] == 1].to_dict(orient='records')
                )
            
            # show results of the prediction
            labelCounts = keysDataframe['Result'].value_counts()
            print(f'Results: {labelCounts}\n')
            print(f'Num of DNS Tunneling ips: {keysDataframe[keysDataframe['Result'] == 1]['Src IP'].unique()}\n')
            print(f'Number of detected attacks:\n {keysDataframe[keysDataframe['Result'] != 0]}\n')
            print('Predictions:\n', keysDataframe)  

        except DNSTunnelingException as e: #if we recived ArpSpoofingException we alert the user
            print(e)
        except Exception as e: #we catch an exception if something happend
            print(f'Error occurred: {e}')
        finally:
            shutil.copy('detectedFlowsDNS.txt', f'{np.random.randint(1,1000000)}_detectedFlowsDNS.txt') # temporary code for saving false positive if the occure during scans

#----------------------------------------------DNS-TUNNELING-END---------------------------------------------#

#--------------------------------------------SAVING-COLLECTED-DATA-------------------------------------------#

# static class that has some basic functionality for saving the collected data from the sniffer
class SaveData(ABC):

    # function for saving the collected flows into a CSV file (used to collect benign data)
    @staticmethod
    def SaveCollectedData(flows, filename='benign_dataset.csv', selectedColumns=PortScanDoS.selectedColumns):
        # create a dataframe from the collected data
        values = list(flows.values())
        ordered_values = [[valueDict[col] for col in selectedColumns] for valueDict in values] #reorder the values in the same order that the models were trained on
        valuesDataframe = pd.DataFrame(ordered_values, columns=selectedColumns)

        if not os.path.isfile(filename):
            valuesDataframe.to_csv(filename, index=False) #save the new data if needed
        else:
            # open an existing file and merge the collected data to it
            readBenignCsv = pd.read_csv(filename)
            mergedDataframe = pd.concat([readBenignCsv , valuesDataframe], axis=0)
            mergedDataframe.to_csv(filename, index=False)
            print(f'Found {valuesDataframe.shape[0]} rows.')

    
    # function for saving the collected flows into a txt file
    @staticmethod
    def SaveFlowsInFile(flows, filename='detectedFlows.txt'):
        # write result of flows captured in txt file
        with open(filename, 'w') as file:
            for flow, features in flows.items():
                file.write(f'Flow: {flow}\n')
                for feature, value in features.items():
                    file.write(f' {feature}: {value}\n')
                file.write('================================================================\n')

#------------------------------------------SAVING-COLLECTED-DATA-END-----------------------------------------#

#-------------------------------------------------MAIN-START-------------------------------------------------#

if __name__ == '__main__':

    # call scan network func to initiate network scan 'en6' / 'Ethernet' / 'Wi-Fi'
    SniffNetwork.selectedInterface = 'Ethernet' #mimicking a user selected interface from spinbox
    SniffNetwork.ScanNetwork()

    # call arp processing function and check for arp spoofing attacks
    # ArpSpoofing.ProcessARP()

    # call port scanning and dos processing function and predict attack
    # portScanFlows = PortScanDoS.ProcessFlows()
    # SaveData.SaveFlowsInFile(portScanFlows) #save the collected data in txt format
    # SaveData.SaveCollectedData(portScanFlows) #save the collected data in CSV format
    # PortScanDoS.PredictPortDoS(portScanFlows) #call our predict function for detecting port dos attack

    # call dns processing function and predict attack
    dnsFlows = DNSTunneling.ProcessFlows()
    SaveData.SaveFlowsInFile(dnsFlows, 'detectedFlowsDNS.txt') #save the collected data in txt format
    SaveData.SaveCollectedData(dnsFlows, 'dns_benign_dataset.csv', DNSTunneling.selectedColumns) #save the collected data in CSV format
    DNSTunneling.PredictDNS(dnsFlows)

#--------------------------------------------------MAIN-END--------------------------------------------------#