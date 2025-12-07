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


# test step function for testing change user network interface positive scenario
def testChangeNetworkInterfacePositive(NetSpectWindow, qtbot):
    # get current network interface
    currentInterface = NetSpectWindow.ui.networkInterfaceComboBox.currentText()

    # check current network interface in info page
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(3)
    assert NetSpectWindow.ui.connectedInterfaceInfoLabel.text() == currentInterface, f'Current network interface in Info Page is invalid. Expected: {currentInterface}, Found: {NetSpectWindow.ui.connectedInterfaceInfoLabel.text()}.'

    # change selected network interface
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(0)
    NetSpectWindow.ui.networkInterfaceComboBox.setCurrentIndex(1)
    currentInterface = NetSpectWindow.ui.networkInterfaceComboBox.currentText()

    # go to info page
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(3)
    assert NetSpectWindow.ui.connectedInterfaceInfoLabel.text() == currentInterface, f'Current network interface in Info Page is invalid. Expected: {currentInterface}, Found: {NetSpectWindow.ui.connectedInterfaceInfoLabel.text()}.'

        
# test step function for testing change email positive scenarios
@pytest.mark.parametrize('email', ['newEmail@gmail.com', 'USERNAME@something.com', 'email123@test.co.il'])
def testChangeEmailPositive(NetSpectWindow, qtbot, email):
    # save the default email and login
    defaultEmail = 'user@user.com'

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
    assert isinstance(userId, int) and userId > 0, 'Failed logging into User account.'

    # go to settings page
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

    # clear existing input and fill new email
    NetSpectWindow.ui.emailLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.emailLineEdit, email)

    # click save email button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.emailPushButton, Qt.LeftButton)

    # assert no error message appeared
    errorMessage = NetSpectWindow.ui.saveEmailErrorMessageLabel.text()
    assert NetSpectWindow.ui.saveEmailErrorMessageLabel.isVisible() == False, f'Error message is visible after changing the email. Error: {errorMessage}'
    assert errorMessage == '', f'Error message exists after changing the email. Error: {errorMessage}'

    # change email back to default, first clear existing input and fill default email
    NetSpectWindow.ui.emailLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.emailLineEdit, defaultEmail)

    # click save email button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.emailPushButton, Qt.LeftButton)

    
# test step function for testing change email negative scenarios
@pytest.mark.parametrize('email', ['new)(*&@gmail.com', 'USERNAME@something', 'email123test.co.il'])
def testChangeEmailNegative(NetSpectWindow, qtbot, email):
    # save the default email and login
    defaultEmail = 'User'

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
    assert isinstance(userId, int) and userId > 0, 'Failed logging into User account.'

    # go to settings page
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

    # clear existing input and fill new email
    NetSpectWindow.ui.emailLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.emailLineEdit, email)

    # click save email button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.emailPushButton, Qt.LeftButton)

    # assert error message appeared (check if it appeared, if not change the email back to default and fail the test)
    if NetSpectWindow.ui.saveEmailErrorMessageLabel.isVisible() == False or NetSpectWindow.ui.saveEmailErrorMessageLabel.text() == '':
        # change email back to default, first clear existing input and fill default email
        NetSpectWindow.ui.emailLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.emailLineEdit, defaultEmail)

        # click save email button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.emailPushButton, Qt.LeftButton)

        assert True == False, f'Error message is not visible after changing the email to an invalid one. Change email does not work correctly.'


# test step function for testing change username positive scenarios
@pytest.mark.parametrize('username', ['TestName', 'testname', 'testName!', 'Testname123'])
def testChangeUsernamePositive(NetSpectWindow, qtbot, username):
    # save the default username and login
    defaultUsername = 'User'

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
    assert isinstance(userId, int) and userId > 0, 'Failed logging into User account.'

    # go to settings page
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

    # clear existing input and fill new username
    NetSpectWindow.ui.usernameLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.usernameLineEdit, username)

    # click save username button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.usernamePushButton, Qt.LeftButton)

    # assert no error message appeared
    errorMessage = NetSpectWindow.ui.saveUsernameErrorMessageLabel.text()
    assert NetSpectWindow.ui.saveUsernameErrorMessageLabel.isVisible() == False, f'Error message is visible after changing the username. Error: {errorMessage}'
    assert errorMessage == '', f'Error message exists after changing the username. Error: {errorMessage}'

    # change username back to default, first clear existing input and fill default username
    NetSpectWindow.ui.usernameLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.usernameLineEdit, defaultUsername)

    # click save username button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.usernamePushButton, Qt.LeftButton)

    
# test step function for testing change username negative scenarios
@pytest.mark.parametrize('username', ['A', 'new', '1234'])
def testChangeUsernameNegative(NetSpectWindow, qtbot, username):
    # save the default username and login
    defaultUsername = 'User'

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
    assert isinstance(userId, int) and userId > 0, 'Failed logging into User account.'

    # go to settings page
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

    # clear existing input and fill new username
    NetSpectWindow.ui.usernameLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.usernameLineEdit, username)

    # click save username button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.usernamePushButton, Qt.LeftButton)

    # assert error message appeared (check if it appeared, if not change the username back to default and fail the test)
    if NetSpectWindow.ui.saveUsernameErrorMessageLabel.isVisible() == False or NetSpectWindow.ui.saveUsernameErrorMessageLabel.text() == '':
        # change username back to default, first clear existing input and fill default username
        NetSpectWindow.ui.usernameLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.usernameLineEdit, defaultUsername)

        # click save username button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.usernamePushButton, Qt.LeftButton)

        assert True == False, f'Error message is not visible after changing the username to an invalid one. Change username does not work correctly.'


# test step function for testing change password positive scenarios
@pytest.mark.parametrize('passwords', [('User123', 'User1234', 'User1234'), ('User123', '1234Abcd', '1234Abcd'), ('User123', '12!@#aB', '12!@#aB')])
def testChangePasswordPositive(NetSpectWindow, qtbot, passwords):
    # save the default password and login
    defaultPassword = 'User123'

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
    assert isinstance(userId, int) and userId > 0, 'Failed logging into User account.'

    # go to settings page
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)
    
    # clear existing input and fill new passwords
    NetSpectWindow.ui.currentPasswordLineEdit.clear()
    NetSpectWindow.ui.newPasswordLineEdit.clear()
    NetSpectWindow.ui.confirmPasswordLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.currentPasswordLineEdit, passwords[0])
    qtbot.keyClicks(NetSpectWindow.ui.newPasswordLineEdit, passwords[1])
    qtbot.keyClicks(NetSpectWindow.ui.confirmPasswordLineEdit, passwords[2])

    # click save password button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.passwordPushButton, Qt.LeftButton)

    # assert no error message appeared
    errorMessage = NetSpectWindow.ui.savePasswordErrorMessageLabel.text()
    assert NetSpectWindow.ui.savePasswordErrorMessageLabel.isVisible() == False, f'Error message is visible after changing the password. Error: {errorMessage}'
    assert errorMessage == '', f'Error message exists after changing the password. Error: {errorMessage}'

    # change password back to default, first clear existing input and fill default passwords
    NetSpectWindow.ui.currentPasswordLineEdit.clear()
    NetSpectWindow.ui.newPasswordLineEdit.clear()
    NetSpectWindow.ui.confirmPasswordLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.currentPasswordLineEdit, passwords[1])
    qtbot.keyClicks(NetSpectWindow.ui.newPasswordLineEdit, defaultPassword)
    qtbot.keyClicks(NetSpectWindow.ui.confirmPasswordLineEdit, defaultPassword)

    # click save password button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.passwordPushButton, Qt.LeftButton)

    
# test step function for testing change password negative scenarios
@pytest.mark.parametrize('passwords', [('User123', 'User123', 'User12'), ('User1234', 'User1234', 'User1234'), ('User123', 'U2', 'U2')])
def testChangePasswordNegative(NetSpectWindow, qtbot, passwords):
    # save the default password and login
    defaultPassword = 'User123'

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
    assert isinstance(userId, int) and userId > 0, 'Failed logging into User account.'

    # go to settings page
    NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

    # clear existing input and fill new password
    NetSpectWindow.ui.currentPasswordLineEdit.clear()
    NetSpectWindow.ui.newPasswordLineEdit.clear()
    NetSpectWindow.ui.confirmPasswordLineEdit.clear()
    qtbot.keyClicks(NetSpectWindow.ui.currentPasswordLineEdit, passwords[0])
    qtbot.keyClicks(NetSpectWindow.ui.newPasswordLineEdit, passwords[1])
    qtbot.keyClicks(NetSpectWindow.ui.confirmPasswordLineEdit, passwords[2])

    # click save password button
    time.sleep(1)
    qtbot.mouseClick(NetSpectWindow.ui.passwordPushButton, Qt.LeftButton)

    # assert error message appeared (check if it appeared, if not change the password back to default and fail the test)
    if NetSpectWindow.ui.savePasswordErrorMessageLabel.isVisible() == False or NetSpectWindow.ui.savePasswordErrorMessageLabel.text() == '':
        # change password back to default, first clear existing input and fill default password
        NetSpectWindow.ui.currentPasswordLineEdit.clear()
        NetSpectWindow.ui.newPasswordLineEdit.clear()
        NetSpectWindow.ui.confirmPasswordLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.currentPasswordLineEdit, passwords[1])
        qtbot.keyClicks(NetSpectWindow.ui.newPasswordLineEdit, defaultPassword)
        qtbot.keyClicks(NetSpectWindow.ui.confirmPasswordLineEdit, defaultPassword)

        # click save password button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.passwordPushButton, Qt.LeftButton)

        assert True == False, f'Error message is not visible after changing the password to an invalid one. Change password does not work correctly.'


# main function for running the tests
if __name__ == '__main__':
    pytest.main(['-v', __file__])