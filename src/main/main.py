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
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSClientKeyExchange, TLSServerKeyExchange, TLSNewSessionTicket
from urllib.parse import unquote
from queue import Queue


#--------------------------------------------Default_Packet----------------------------------------------#
# abstarct class for default packet
class Default_Packet(ABC):
    name = None #represents the packet name
    packet = None #represents the packet object itself for our use later
    packetType = None #represents the packet type based on scapy known types
    srcIP = None #represents source ip of packet 
    dstIP = None #represents destination ip of packet
    srcPort = None #represents source port of packet 
    dstPort = None #represents destination port of packet
    ipParam = None #represents IPv4 / IPv6 fields as tuple (ttl, dscp) / (hopLimit, trafficClass)
    id = None #represents the id for the packet object, for ease of use in dictionary later
    length = None #size of packet

    # constructor for default packet 
    def __init__(self, name=None, packet=None, id=None):
        self.name = name
        self.packet = packet
        self.id = id
        self.length = len(self.packet)
        self.ipInfo() #initialize ip info


    # method for ip configuration capture
    def ipInfo(self): 
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
    def __init__(self, packet=None, id=None):
        super().__init__('TCP', packet, id) #call parent ctor
        if packet.haslayer(TCP): #checks if packet is TCP
            self.packetType = TCP #specify the packet type
        self.InitTCP() #call initTCP to initialize tcp specific params


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
    def __init__(self, packet=None, id=None): #ctor 
        super().__init__('UDP', packet, id) #call parent ctor
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

    def __init__(self, packet=None, id=None):
        super().__init__('DNS', packet, id) #call parent ctor
        if packet.haslayer(DNS): #checks if packet is DNS
            self.packetType = DNS #add packet type

    #method for packet information
    def InitDNS(self):
        if self.packet.haslayer(DNS): #if packet has DNS layer
            dnsPacket = self.packet[DNS] #save the dns packet in parameter
            self.dnsId = dnsPacket.id #id of the dns packet
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
    srcMac = None
    dstMac = None
    arpType = None
    hwType = None
    pType = None
    hwLen = None
    pLen = None

    def __init__(self, packet=None, id=None):
        super().__init__('ARP', packet, id) #call parent ctor
        if packet.haslayer(ARP): #checks if packet is arp
            self.packetType = ARP #add packet type
        self.InitARP()

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

packetDictionary = {} #initialize the packet dictionary
portScanDosQueue = Queue() #represents queue of packets related to port scanning and dos
dnsQueue = Queue() #represents queue of packets related to dns tunneling 
arpQueue = Queue() #represents queue of packets related to arp poisoning
packetCounter = 0 #global counter for dictionary elements

#-----------------------------------------HANDLE-FUNCTIONS-----------------------------------------#
#method that handles TCP packets
def handleTCP(packet):
    global packetCounter
    TCP_Object = TCP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[TCP_Object.getId()] = TCP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return TCP_Object #finally return the object

#method that handles UDP packets
def handleUDP(packet):
    global packetCounter
    UDP_Object = UDP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[UDP_Object.getId()] = UDP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return UDP_Object #finally return the object

#method that handles DNS packets
def handleDNS(packet):
    global packetCounter
    DNS_Object = DNS_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[DNS_Object.getId()] = DNS_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return DNS_Object #finally return the object

#method that handles ARP packets
def handleARP(packet):
    global packetCounter
    ARP_Object = ARP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[ARP_Object.getId()] = ARP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return ARP_Object #finally return the object

#-----------------------------------------HANDLE-FUNCTIONS-END-----------------------------------------#