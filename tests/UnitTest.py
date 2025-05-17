import sys, os, time, random, pytest
from PySide6.QtCore import Qt
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) #ensures that UnitTest.py file will run from main folder in the terminal
from src.main.MainFunctions import *


# test step function for GetNetworkInterfaces function
def testGetNetworkInterfaces():
    # get all available network interfaces with our function
    availableInterfaces = NetworkInformation.GetNetworkInterfaces()

    # assert function was successful and retrived an interface
    firstInterface = next(iter(availableInterfaces.values()), None)
    assert availableInterfaces != {} and firstInterface != None, 'Received an empty interface dictionary, no interfaces were found.'


# test step function for GuidToStr function
def testGuidToStrPositive():
    # hard code a valid guid string
    guid = '{07444BF8-F269-473F-B278-891AA8D81C6E}'

    # call the translate function with given guid
    output = NetworkInformation.GuidToStr(guid)

    # assert that the given guid is valid by check that the output is not equal to the input
    assert output != guid, f'Failed to translate the guid. Input: {guid}, Output: {output}.'


# test step function for GuidToStr function
@pytest.mark.parametrize('guid', ['07444BF8-F269-473F-B278-891AA8D81C6E', '{473F-B278-891AA8D81C6E}', 'not a guid'])
def testGuidToStrNegative(guid):
    # call the translate function with given guid
    output = NetworkInformation.GuidToStr(guid)

    # assert that the given guid is invalid by check that the output is equal to the input
    assert output == guid, f'Was able to translate an invalid guid. Input: {guid}, Output: {output}.'


# test step function for GetSystemInformation function
def testGetSystemInformation():
    # call the function for getting system information
    output = NetworkInformation.GetSystemInformation()

    # assert that the output is not empty
    assert output != None, 'Output is None, expected a dict with values.'
    assert len(output) == 4, 'Output is missing data key value pairs.'
    assert all([type(value) == str for value in output.values()]), 'At least one value is not of type string.'


# test step function for SaveFlowsInFile function
def testSaveFlowsInFile():
    # declare file name, path and the contents
    fileName = 'testFile.txt'
    fileContents = {('first value', 'second value'): {'a': 4, 'b': 5, 'c': 10}}

    # call the function to save flows in file
    SaveData.SaveFlowsInFile(fileContents, fileName)

    # assert that the file was created
    assert os.path.isfile(fileName), f'File with name: {fileName} does not exist.'

    # assert that the contents of the file matches the input data
    with open(fileName, "r", encoding="utf-8") as file:
        contents = file.read()
    os.remove(fileName) #delete the file before checking if the contents is valid

    assert all(str(flow) in contents for flow in fileContents.keys()), 'Key is missing from file.'
    for expected in ['a', 'b', 'c', '4', '5', '10']:
        assert expected in contents, f'"{expected}" is missing from file.'


# test step function for SaveCollectedData function
def testSaveCollectedData():
    # declare file name, path and the contents
    fileName = 'testFile.csv'
    fileContents = {('first value', 'second value'): {'a': 4, 'b': 5, 'c': 10}}
    selectedColumns = ['a', 'b', 'c']

    # call the function to save flows in file
    SaveData.SaveCollectedData(fileContents, fileName, selectedColumns)

    # assert that the file was created
    assert os.path.isfile(fileName), f'File with name: {fileName} does not exist.'
    
    # assert that the contents of the file matches the input data
    with open(fileName, "r", encoding="utf-8") as file:
        contents = file.read()
    os.remove(fileName) #delete the file before checking if the contents is valid

    for expected in ['a', 'b', 'c', '4', '5', '10']:
        assert expected in contents, f'"{expected}" is missing from file.'


# main function for running the tests
if __name__ == '__main__':
    pytest.main(['-v', __file__])