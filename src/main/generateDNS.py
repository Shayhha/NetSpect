import socket
import random
import time
import subprocess
import platform

# list of DNS servers
DNS_SERVERS = [
    '8.8.8.8',         # Google DNS
    '8.8.4.4',         # Google Secondary DNS
    '1.1.1.1',         # Cloudflare DNS
    '1.0.0.1',         # Cloudflare Secondary DNS
    '9.9.9.9',         # Quad9 DNS
    '149.112.112.112', # Quad9 Secondary DNS
    '208.67.222.222',  # OpenDNS
    '208.67.220.220',  # OpenDNS Secondary DNS
    '76.76.2.0',       # Control D DNS
    '76.76.10.0',      # Control D Secondary DNS
    '94.140.14.14',    # AdGuard DNS
    '94.140.15.15',    # AdGuard Secondary DNS
    '185.228.168.9',   # CleanBrowsing DNS
    '185.228.169.9',   # CleanBrowsing Secondary DNS
    '76.76.19.19',     # Alternate DNS
    '76.223.122.150',  # Alternate Secondary DNS
    '4.2.2.1',         # Level3 DNS
    '4.2.2.2',         # Level3 Secondary DNS
    '84.200.69.80',    # DNS.Watch
    '84.200.70.40',    # DNS.Watch Secondary DNS
    '8.26.56.26',      # Comodo Secure DNS
    '8.20.247.20'      # Comodo Secure Secondary DNS
]

# traffic distribution for query types
QUERY_TYPES = {
    'A': 70,      # IPv4 address
    'AAAA': 20,   # IPv6 address
    'MX': 5,      # Mail exchange
    'TXT': 3,     # Metadata
    'CNAME': 2    # CNAME
}

# random list of 100 domains that are online
DOMAINS = [
    'example.org', 'archive.org', 'w3schools.org', 'pythonanywhere.org', 'sciencemag.org',
    'freecodecamp.org', 'openai.org', 'gnu.org', 'mit.edu', 'stanford.edu',
    'bbc.co.uk', 'theguardian.co.uk', 'abc.net.au', 'theaustralian.com.au', 'globeandmail.ca',
    'cbc.ca', 'timesofindia.indiatimes.com', 'ndtv.com.in', 'google.co.za', 'sabc.co.za',
    'euronews.fr', 'lemonde.fr', 'spiegel.de', 'zeit.de', 'elpais.es',
    'lavanguardia.es', 'corriere.it', 'repubblica.it', '20min.ch', 'blick.ch',
    'ieee.org', 'iana.org', 'ietf.org', 'cern.ch', 'emblebi.ac.uk',
    'creativecommons.org', 'wwf.panda.org', 'nature.com', 'scopus.com', 'springer.com',
    'docker.io', 'github.io', 'sourceforge.net', 'sciencedirect.com', 'researchgate.net',
    'vldb.org', 'jupyter.org', 'conda-forge.org', 'kaggle.com', 'tensorflow.org',
    'rottentomatoes.com', 'letterboxd.com', 'pitchfork.com', 'soundcloud.com', 'bandcamp.com',
    'archiveofourown.org', 'fanfiction.net', 'goodreads.com', 'bookdepository.com', 'audible.ca',
    'europa.eu', 'un.org', 'who.int', 'unesco.org', 'nato.int',
    'nasa.gov', 'gov.uk', 'gov.au', 'gov.ca', 'gov.za',
    'arxiv.org', 'bioinformatics.org', 'pnas.org', 'plos.org', 'scielo.org',
    'zenodo.org', 'data.gov', 'noaa.gov', 'nist.gov', 'usgs.gov',
    'wikidata.org', 'wiktionary.org', 'openstreetmap.org', 'codecademy.com', 'khanacademy.org',
    'openlibrary.org', 'projectgutenberg.org', 'coursera.org', 'udemy.com', 'edx.org',
    'openweathermap.org', 'api.ipify.org', 'ipinfo.io', 'ipdata.co', 'timeapi.io',
    'jsonplaceholder.typicode.com', 'mockapi.io', 'pokeapi.co', 'restcountries.com', 'catfact.ninja'
]


# add optional padding to a query
def addPadding(query):
    paddingSize = random.randint(1, 20) #small padding size
    return query + (b'\x00' * paddingSize)


# construct a DNS query with specified query type and optional padding
def constructDNSQuery(domain, queryType):
    query = (
        b'\xaa\xbb' # Transaction ID
        b'\x01\x00' # Standard query
        b'\x00\x01' # Questions: 1
        b'\x00\x00' # Answer RRs
        b'\x00\x00' # Authority RRs
        b'\x00\x00' # Additional RRs
    )
    # add domain name to query
    query += b''.join([bytes([len(part)]) + part.encode() for part in domain.split('.')]) + b'\x00'

    # query type mapping
    queryTypeMap = {
        'A': b'\x00\x01',
        'AAAA': b'\x00\x1c',
        'MX': b'\x00\x0f',
        'TXT': b'\x00\x10',
        'CNAME': b'\x00\x05'
    }

    query += queryTypeMap.get(queryType, b'\x00\x01') #default to A if unknown
    query += b'\x00\x01' #class IN

    # add padding in 15% of queries
    if random.random() < 0.15:
        query = addPadding(query)

    return query


# send a DNS query to a server
def sendDNSQuery(domain, dnsServer, queryType, port=53):
    try:
        # create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)

        # construct the DNS query
        query = constructDNSQuery(domain, queryType)

        # send the query
        sock.sendto(query, (dnsServer, port))

        # receive the response
        response, _ = sock.recvfrom(512)
        print(f'Received response for {domain} ({queryType}) from {dnsServer}: {response[:40]}...')  # Truncated for display

    except Exception as e:
        print(f'Error querying {domain} ({queryType}) from {dnsServer}: {e}')
    finally:
        sock.close()


# Generate and send DNS queries in a loop
def generateDNSTraffic():
    # shuffle the list randomly and divide the list into 3 groups
    random.shuffle(DNS_SERVERS)
    groups = [DNS_SERVERS[i::3] for i in range(3)]
    sendingDNSCounter = [1, 4, 8]

    # for each dns server in each group send the correct amount of dns querys
    for i, dnsServerGroups in enumerate(groups):
        for dnsServer in dnsServerGroups:
            for _ in range(sendingDNSCounter[i]):
                # select a random domain
                domain = random.choice(DOMAINS) 

                # determine the query type based on distribution (A is most common, TXT and CNAME is lease common)
                queryType = random.choices(
                    population=list(QUERY_TYPES.keys()),
                    weights=list(QUERY_TYPES.values()),
                    k=1
                )[0]
                    
                sendDNSQuery(domain, dnsServer, queryType)


if __name__ == '__main__':    
    # generate dns traffic using a helper function
    generateDNSTraffic()

    # clear the dns cache after generating traffic
    try:
        command = 'sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder'
        if platform.system() == 'Windows':
            command = 'ipconfig /flushdns'
        
        subprocess.run(command, shell=True, check=True)
        print('DNS cache cleared successfully.')
    except subprocess.CalledProcessError as e:
        print(f'Error clearing DNS cache: {e}')
    except Exception as ex:
        print(f'An error occurred: {ex}')
