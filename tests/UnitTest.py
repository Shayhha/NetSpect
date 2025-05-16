import sys, os, time, random, pytest
from PySide6.QtCore import Qt
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src', 'main'))) #ensures that UnitTest.py file will run from main folder in the terminal
from src.main.MainFunctions import *


# test step function for GetNetworkInterfaces function
def testGetNetworkInterfaces():
    # get all available network interfaces with our function
    availableInterfaces = NetworkInformation.GetNetworkInterfaces()

    # assert function was successful and retrived an interface
    firstInterface = next(iter(availableInterfaces.values()), None)
    assert availableInterfaces != {} and firstInterface != None, 'Received an empty interface dictionary, no interfaces were found.'