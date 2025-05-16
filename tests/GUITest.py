import sys, os, random, pytest
from PySide6.QtCore import Qt


# function for waiting until desired condition is met in certin timeout
def WaitCondition(qtbot, condition, timeout=3000):
    try:
        # run our desired function in specified timeout
        qtbot.waitUntil(lambda: condition, timeout=timeout)

    # check if we reached timeout, if so show print error message
    except TimeoutError:
        assert False, 'Operaton did not start within timeout.'


# test step function for login popup
def testLogin(NetSpectWindow, qtbot):
    # fill login form
    qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, 'User')
    qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, 'User123')

    # click login button
    qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

    # wait until login process finishes
    WaitCondition(qtbot, NetSpectWindow.userData.get('userId') != None)

    # assert login was successful
    userId = NetSpectWindow.userData.get('userId')
    assert isinstance(userId, int) and userId > 0, 'Failed loggin into User account.'


# test step function for register popup
def testRegister(NetSpectWindow, qtbot):
    # generate random test user credentials
    userNumber = random.randint(1, 999999)
    email = f'test.{userNumber}@test.com'
    userame = f'TestUser{userNumber}'
    password = 'TestPass123'

    # fill registration form
    qtbot.keyClicks(NetSpectWindow.ui.registerEmailLineEdit, email)
    qtbot.keyClicks(NetSpectWindow.ui.registerUsernameLineEdit, userame)
    qtbot.keyClicks(NetSpectWindow.ui.registerPasswordLineEdit, password)
    qtbot.keyClicks(NetSpectWindow.ui.registerConfirmPasswordLineEdit, password)

    # click register button
    qtbot.mouseClick(NetSpectWindow.ui.registerPushButton, Qt.LeftButton)

    # wait until registration process finishes
    WaitCondition(qtbot, NetSpectWindow.userData.get('userId') != None, timeout=5000)

    # assert registration was successful
    userId = NetSpectWindow.userData.get('userId')
    assert isinstance(userId, int) and userId > 0, 'User registration failed.'

    # delete test user only if registration succeeded
    if isinstance(userId, int) and userId > 0:
        NetSpectWindow.sqlThread.HardDeleteAccount(userId)