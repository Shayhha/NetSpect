import sys, os, time, random, pytest
from PySide6.QtCore import Qt
# ensures that UnitTest.py file will run from main folder in the terminal
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'src', 'main'))
from src.main.NetSpect import *
os.chdir(os.path.dirname(__file__))


#------------------------------------------------------TEST-MAIN-FUNCTIONS------------------------------------------------------#
# class for testing main functions in NetSpect application
class TestMainFunctions():

    # test step function for GetNetworkInterfaces function
    def testGetNetworkInterfaces(self) -> None:
        # get all available network interfaces with our function
        availableInterfaces = NetworkInformation.GetNetworkInterfaces()

        # assert function was successful and retrived an interface
        firstInterface = next(iter(availableInterfaces.values()), None)
        assert availableInterfaces != {} and firstInterface != None, 'Received an empty interface dictionary, no interfaces were found.'


    # test step function for GetNetmaskFromIp function positive attempt
    def testGetNetmaskFromIpPositive(self) -> None:
        # get interfaces with QNetwork
        interfaces = QNetworkInterface.allInterfaces()

        # get all available network interfaces with our function
        availableInterfaces = NetworkInformation.GetNetworkInterfaces()

        # get first available network interface
        firstInterface = next(iter(availableInterfaces.values()), None)

        # get ipv4 address list from first interface
        ipv4Addresses = firstInterface.get('ipv4Addrs') if firstInterface else []

        # assert that we received an initialized ipv4 addresses list
        assert ipv4Addresses != [], 'Received an empty ipv4 list, no ipv4 addresses were found.'

        # get netmask from first ip address
        netmask = NetworkInformation.GetNetmaskFromIp(interfaces, ipv4Addresses[0])

        # assert function was successful and retrived a netmask for the first ip
        assert netmask != None, 'Failed receiving a netmask for ipv4 address.'


    # test step function for GetNetmaskFromIp function negative attempt
    def testGetNetmaskFromIpNegative(self) -> None:
        # get interfaces with QNetwork
        interfaces = QNetworkInterface.allInterfaces()

        # represents a random ipv4 address
        ipv4Address = '.'.join(str(random.randint(0, 255)) for _ in range(4))

        # get netmask from random ip address
        netmask = NetworkInformation.GetNetmaskFromIp(interfaces, ipv4Address)

        # assert function was successful and didnt receive a netmask
        assert netmask == None, 'Received a netmask for invalid ipv4 address.'


    # test step function for GetMTUFromInterface function positive attempt
    def testGetMTUFromInterfacePositive(self) -> None:
        # get interfaces with QNetwork
        interfaces = QNetworkInterface.allInterfaces()

        # get all available network interfaces with our function
        availableInterfaces = NetworkInformation.GetNetworkInterfaces()

        # get first available network interface
        firstInterface = next(iter(availableInterfaces.values()), None)

        # get interface name of first interface
        interfaceName = firstInterface.get('name') if firstInterface else ''

        # assert that we received a valid interface name
        assert interfaceName != '', 'Failed receiving interface name.'

        # get mtu from the first interface
        interfaceMTU = NetworkInformation.GetMTUFromInterface(interfaces, interfaceName)

        # assert function was successful and retrived mtu for the first interface
        assert interfaceMTU != None, 'Failed receiving mtu for interface.'


    # test step function for GetMTUFromInterface function negative attempt
    def testGetMTUFromInterfaceNegative(self) -> None:
        # get interfaces with QNetwork
        interfaces = QNetworkInterface.allInterfaces()

        # represents a random interface name
        interfaceName = f'Ethernet{random.randint(1, 99)}'

        # get mtu from random interface name
        interfaceMTU = NetworkInformation.GetMTUFromInterface(interfaces, interfaceName)

        # assert function was successful and didnt receive mtu
        assert interfaceMTU == None, 'Received mtu for invalid interface name.'


    # test step function for CompareTimepstemps function positive attempts
    @pytest.mark.parametrize('timestamps', [('22:00:10 01/05/24', '22:10:10 01/05/24', 10), ('09:10:00 10/05/24', '09:25:00 10/05/24', 15), ('07:21:45 05/05/24', '08:21:45 05/05/24', 60)])
    def testCompareTimepstempsPositive(self, timestamps: tuple) -> None:
        # assert function was successful and compared the timestamps correctly
        assert NetworkInformation.CompareTimestamps(timestamps[0], timestamps[1], timestamps[2])  == True, f'Expected {timestamps[2]} minutes between {timestamps[0]} and {timestamps[1]}, but function returned False.'


    # test step function for CompareTimepstemps function negative attempts
    @pytest.mark.parametrize('timestamps', [('20:30:55 02/05/24', '20:35:55 02/05/24', 15), ('09:00:00 04/05/24', '09:30:00 04/05/24', 45), ('07:00:00 03/05/24', '07:30:00 03/05/24', 60)])
    def testCompareTimepstempsNegative(self, timestamps: tuple) -> None:
        # assert function was successful and compared the timestamps correctly
        assert NetworkInformation.CompareTimestamps(timestamps[0], timestamps[1], timestamps[2])  == False, f'Expected mismatch for {timestamps[2]} minutes between {timestamps[0]} and {timestamps[1]}, but function returned True.'


    # test step function for GuidToStr function
    def testGuidToStrPositive(self) -> None:
        # test only for Windows machines
        if sys.platform.startswith('win32'):
            # get a list of the network interfaces
            interfaces = get_if_list()

            # assert that we received an initialized ipv4 addresses list
            assert interfaces != [], 'Received an empty interfaces list, no guid were found.'

            # get the first guid in interfaces
            guid = interfaces[0]

            # call the translate function with given guid
            output = NetworkInformation.GuidToStr(guid)

            # assert that the given guid is valid by check that the output is not equal to the input
            assert output != guid, f'Failed to translate the guid. Input: {guid}, Output: {output}.'
        else:
            assert True


    # test step function for GuidToStr function
    @pytest.mark.parametrize('guid', ['07444BF8-F269-473F-B278-891AA8D81C6E', '{473F-B278-891AA8D81C6E}', 'not a guid'])
    def testGuidToStrNegative(self, guid: str) -> None:
        # test only for Windows machines
        if sys.platform.startswith('win32'):
            # call the translate function with given guid
            output = NetworkInformation.GuidToStr(guid)

            # assert that the given guid is invalid by check that the output is equal to the input
            assert output == guid, f'Was able to translate an invalid guid. Input: {guid}, Output: {output}.'
        else:
            assert True


    # test step function for GetSystemInformation function
    def testGetSystemInformation(self) -> None:
        # call the function for getting system information
        output = NetworkInformation.GetSystemInformation()

        # assert that the output is not empty
        assert output != None, 'Output is None, expected a dict with values.'
        assert len(output) == 4, 'Output is missing data key value pairs.'
        assert all([type(value) == str for value in output.values()]), 'At least one value is not of type string.'


    # test step function for SaveFlowsInFile function
    def testSaveFlowsInFile(self) -> None:
        # declare file name, path and the contents
        fileName = 'testFile.txt'
        fileContents = {('first value', 'second value'): {'a': 4, 'b': 5, 'c': 10}}

        # call the function to save flows in file
        SaveData.SaveFlowsInFile(fileContents, fileName)

        # assert that the file was created
        assert os.path.isfile(fileName), f'File with name: {fileName} does not exist.'

        # assert that the contents of the file matches the input data
        with open(fileName, 'r', encoding='utf-8') as file:
            contents = file.read()
        os.remove(fileName) #delete the file before checking if the contents is valid

        assert all(str(flow) in contents for flow in fileContents.keys()), 'Key is missing from file.'
        for expected in ['a', 'b', 'c', '4', '5', '10']:
            assert expected in contents, f'"{expected}" is missing from file.'


    # test step function for SaveCollectedData function
    def testSaveCollectedData(self) -> None:
        # declare file name, path and the contents
        fileName = 'testFile.csv'
        fileContents = {('first value', 'second value'): {'a': 4, 'b': 5, 'c': 10}}
        selectedColumns = ['a', 'b', 'c']

        # call the function to save flows in file
        SaveData.SaveCollectedData(fileContents, fileName, selectedColumns)

        # assert that the file was created
        assert os.path.isfile(fileName), f'File with name: {fileName} does not exist.'
        
        # assert that the contents of the file matches the input data
        with open(fileName, 'r', encoding='utf-8') as file:
            contents = file.read()
        os.remove(fileName) #delete the file before checking if the contents is valid

        for expected in ['a', 'b', 'c', '4', '5', '10']:
            assert expected in contents, f'"{expected}" is missing from file.'

#---------------------------------------------------TEST-MAIN-FUNCTIONS-END-----------------------------------------------------#

#------------------------------------------------------------MAIN---------------------------------------------------------------#
# main function for running the tests
if __name__ == '__main__':
    pytest.main(['-v', __file__])

#----------------------------------------------------------MAIN-END-------------------------------------------------------------#