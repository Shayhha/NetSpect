import sys, os, time, random, pytest
from PySide6.QtCore import Qt


# function for waiting until desired condition is met in certin timeout
def WaitCondition(qtbot, condition, timeout=3000):
    try:
        # run our desired function in specified timeout
        qtbot.waitUntil(lambda: condition, timeout=timeout)

    # check if we reached timeout, if so show print error message
    except TimeoutError:
        assert False, 'Operaton did not start within timeout.'


# test step function for positive login attempt
def testLoginPositive(NetSpectWindow, qtbot):
    # fill login form
    qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, 'User')
    qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, 'User123')

    # click login button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

    # wait until login process finishes
    WaitCondition(qtbot, NetSpectWindow.userData.get('userId') != None)

    # assert login was successful
    userId = NetSpectWindow.userData.get('userId')
    assert isinstance(userId, int) and userId > 0 and NetSpectWindow.ui.accountIcon.isHidden(), 'Failed logging into User account.'


# test step function for negative login attempt
def testLoginNegative(NetSpectWindow, qtbot):
    # generate random user credentials
    userNumber = random.randint(1, 999999)
    userame = f'User{userNumber}'
    password = 'Pass123'

    # fill login form
    qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, userame)
    qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, password)

    # click login button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

    # wait until login process finishes
    WaitCondition(qtbot, NetSpectWindow.ui.loginErrorMessageLabel.text() != '')

    # assert login failed and that there's an error message
    userId = NetSpectWindow.userData.get('userId')
    errorMessage = NetSpectWindow.ui.loginErrorMessageLabel.text()
    assert userId == None and errorMessage != '', 'Was able to log into an invalid account.'


# test step function for positive register attempt
def testRegisterPositive(NetSpectWindow, qtbot):
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
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.registerPushButton, Qt.LeftButton)

    # wait until registration process finishes
    WaitCondition(qtbot, NetSpectWindow.userData.get('userId') != None, timeout=5000)

    # assert registration was successful
    userId = NetSpectWindow.userData.get('userId')
    assert isinstance(userId, int) and userId > 0 and NetSpectWindow.ui.accountIcon.isHidden(), 'User registration failed.'

    # delete test user only if registration succeeded
    if isinstance(userId, int) and userId > 0:
        NetSpectWindow.sqlThread.HardDeleteAccount(userId)


# test step function for negative register attempt
@pytest.mark.parametrize('credentials', [('TestEmail', 'TestUser[]', ''), ('', 'TestUser//', 'TestPass'), ('test.1@test.com', '', 'TestPass123')])
def testRegisterNegative(NetSpectWindow, qtbot, credentials):
    # fill registration form
    qtbot.keyClicks(NetSpectWindow.ui.registerEmailLineEdit, credentials[0])
    qtbot.keyClicks(NetSpectWindow.ui.registerUsernameLineEdit, credentials[1])
    qtbot.keyClicks(NetSpectWindow.ui.registerPasswordLineEdit, credentials[2])
    qtbot.keyClicks(NetSpectWindow.ui.registerConfirmPasswordLineEdit, credentials[2])

    # click register button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.registerPushButton, Qt.LeftButton)

    # wait until registration process finishes
    WaitCondition(qtbot, NetSpectWindow.ui.registerErrorMessageLabel.text() != '')

    # assert registration failed and that there's an error message
    userId = NetSpectWindow.userData.get('userId')
    errorMessage = NetSpectWindow.ui.registerErrorMessageLabel.text()
    assert userId == None and errorMessage != '', 'Was able to register an invalid account.'

    # delete test user only if registration succeeded
    if isinstance(userId, int) and userId > 0:
        NetSpectWindow.sqlThread.HardDeleteAccount(userId)


# test step function for logout attempt
def testLogout(NetSpectWindow, qtbot):
    # fill login form
    qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, 'User')
    qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, 'User123')

    # click login button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

    # wait until login process finishes
    WaitCondition(qtbot, NetSpectWindow.userData.get('userId') != None)

    # assert login was successful
    userId = NetSpectWindow.userData.get('userId')
    assert isinstance(userId, int) and userId > 0 and NetSpectWindow.ui.accountIcon.isHidden(), 'Failed logging into User account.'

    # click logout button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.logoutIcon, Qt.LeftButton)

    # wait until logout process finishes
    WaitCondition(qtbot, NetSpectWindow.userData.get('userId') == None)

    # assert logout was successful
    userId = NetSpectWindow.userData.get('userId')
    assert userId == None and NetSpectWindow.ui.accountIcon.isVisible(), 'Failed logging out of User account.'


# test step function for changing page attempt
@pytest.mark.parametrize('index', [1, 2, 3, 4, 0])
def testChangePage(NetSpectWindow, qtbot, index):
    # change to desired page index in stacked widget
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(index)

    # wait until change page index process finishes
    WaitCondition(qtbot, NetSpectWindow.ui.stackedWidget.currentIndex() == index, timeout=2000)

    # assert change page index was successful
    currentIndex = NetSpectWindow.ui.stackedWidget.currentIndex()
    assert currentIndex == index, 'Failed changing page index.'


# test step function for starting and stopping scan attempt
def testStartStopScan(NetSpectWindow, qtbot):
    try:
        # click start button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.startStopPushButton, Qt.LeftButton)

        # wait until runningTimerCounter eaches 5 seconds
        qtbot.waitUntil(lambda: NetSpectWindow.ui.runningTimeCounter.text() == '0:00:05', timeout=10000)

        # assert start scan was successful
        assert NetSpectWindow.ui.runningTimeCounter.text() != '0:00:00' and NetSpectWindow.snifferThread.isRunning(), 'Failed starting network scan.'

        # click stop button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.startStopPushButton, Qt.LeftButton)

        # wait until runningTimerCounter resets back to zero
        qtbot.waitUntil(lambda: NetSpectWindow.ui.runningTimeCounter.text() == '0:00:00', timeout=10000)

        # assert stop scan was successful
        assert NetSpectWindow.ui.runningTimeCounter.text() == '0:00:00' and NetSpectWindow.snifferThread == None, 'Failed stopping network scan.'

    # check if we reached timeout, if so show print error message
    except TimeoutError:
        assert False, 'Operaton did not start within timeout.'