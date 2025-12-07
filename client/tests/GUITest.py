import sys, os, time, random, pytest
from PySide6.QtCore import Qt
os.chdir(os.path.dirname(__file__))


#-------------------------------------------------------TEST-GUI-FUNCTIONS------------------------------------------------------#
# class for testing GUI functions in NetSpect application
class TestGUIFunctions():

    # function for waiting until desired condition is met in certin timeout
    def WaitCondition(self, qtbot, condition, signal=None, timeout: int=3000) -> None:
        try:
            if signal:
                # wait for the signal, then evaluate condition
                with qtbot.waitSignal(signal, timeout=timeout):
                    pass

            # run our desired function in specified timeout
            qtbot.waitUntil(condition, timeout=timeout)

        # check if we reached timeout, if so show print error message
        except TimeoutError:
            assert False, 'Operaton did not start within timeout.'


    # test step function for positive register attempt
    def testRegisterPositive(self, NetSpectWindow, qtbot, TestUser: dict) -> None:
        # fill registration form
        qtbot.keyClicks(NetSpectWindow.ui.registerEmailLineEdit, TestUser.get('email'))
        qtbot.keyClicks(NetSpectWindow.ui.registerUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.registerPasswordLineEdit, TestUser.get('password'))
        qtbot.keyClicks(NetSpectWindow.ui.registerConfirmPasswordLineEdit, TestUser.get('password'))

        # click register button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.registerPushButton, Qt.LeftButton)

        # wait until registration process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.registrationResultSignal, timeout=5000)

        # assert registration was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0 and NetSpectWindow.ui.accountIcon.isHidden(), 'User registration failed.'


    # test step function for negative register attempts
    @pytest.mark.parametrize('credentials', [('TestEmail', 'TestUser[]', ''), ('', 'TestUser//', 'TestPass'), ('testuser.1@netspect.com', '', 'TestPass123')])
    def testRegisterNegative(self, NetSpectWindow, qtbot, TestUser: dict, credentials: tuple) -> None:
        # fill registration form
        qtbot.keyClicks(NetSpectWindow.ui.registerEmailLineEdit, credentials[0])
        qtbot.keyClicks(NetSpectWindow.ui.registerUsernameLineEdit, credentials[1])
        qtbot.keyClicks(NetSpectWindow.ui.registerPasswordLineEdit, credentials[2])
        qtbot.keyClicks(NetSpectWindow.ui.registerConfirmPasswordLineEdit, credentials[2])

        # click register button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.registerPushButton, Qt.LeftButton)

        # wait until registration process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.ui.registerErrorMessageLabel.text() != '')

        # assert registration failed and that there's an error message
        userId = NetSpectWindow.userData.get('userId')
        errorMessage = NetSpectWindow.ui.registerErrorMessageLabel.text()
        assert userId == None and errorMessage != '', 'Was able to register an invalid account.'

        # delete test user only if registration succeeded
        if isinstance(userId, int) and userId > 0:
            NetSpectWindow.sqlManager.HardDeleteAccount()


    # test step function for positive login attempt
    def testLoginPositive(self, NetSpectWindow, qtbot, TestUser: dict) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0 and NetSpectWindow.ui.accountIcon.isHidden(), 'Failed logging into user\'s account.'


    # test step function for negative login attempt
    def testLoginNegative(self, NetSpectWindow, qtbot, TestUser: dict) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, f'{TestUser.get('password')}Test')

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.ui.loginErrorMessageLabel.text() != '', signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login failed and that there's an error message
        userId = NetSpectWindow.userData.get('userId')
        errorMessage = NetSpectWindow.ui.loginErrorMessageLabel.text()
        assert userId == None and errorMessage != '', 'Was able to log into account with invalid credentials.'


    # test step function for logout attempt
    def testLogout(self, NetSpectWindow, qtbot, TestUser: dict) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0 and NetSpectWindow.ui.accountIcon.isHidden(), 'Failed logging into user\'s account.'

        # click logout button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.logoutIcon, Qt.LeftButton)

        # wait until logout process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') == None)

        # assert logout was successful
        userId = NetSpectWindow.userData.get('userId')
        assert userId == None and NetSpectWindow.ui.accountIcon.isVisible(), 'Failed logging out of user\'s account.'


    # test step function for changing page attempt
    @pytest.mark.parametrize('index', [1, 2, 3, 4, 0])
    def testChangePage(self, NetSpectWindow, qtbot, TestUser: dict, index: int) -> None:
        # change to desired page index in stacked widget
        NetSpectWindow.ui.stackedWidget.setCurrentIndex(index)

        # wait until change page index process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.ui.stackedWidget.currentIndex() == index, timeout=2000)

        # assert change page index was successful
        currentIndex = NetSpectWindow.ui.stackedWidget.currentIndex()
        assert currentIndex == index, 'Failed changing page index.'


    # test step function for starting and stopping scan attempt
    def testStartStopScan(self, NetSpectWindow, qtbot, TestUser: dict) -> None:
        try:
            # click start button
            time.sleep(1)
            qtbot.mouseClick(NetSpectWindow.ui.startStopPushButton, Qt.LeftButton)

            # wait until runningTimerCounter eaches 5 seconds
            self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.ui.runningTimeCounter.text() == '0:00:05', timeout=10000)

            # assert start scan was successful
            assert NetSpectWindow.ui.runningTimeCounter.text() != '0:00:00' and NetSpectWindow.snifferThread.isRunning(), 'Failed starting network scan.'

            # click stop button
            time.sleep(1)
            qtbot.mouseClick(NetSpectWindow.ui.startStopPushButton, Qt.LeftButton)

            # wait until runningTimerCounter resets back to zero
            self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.ui.runningTimeCounter.text() == '0:00:00', timeout=10000)

            # assert stop scan was successful
            assert NetSpectWindow.ui.runningTimeCounter.text() == '0:00:00' and NetSpectWindow.snifferThread == None, 'Failed stopping network scan.'

        # check if we reached timeout, if so show print error message
        except TimeoutError:
            assert False, 'Operaton did not start within timeout.'


    # test step function for testing change user network interface positive scenario
    def testChangeNetworkInterfacePositive(self, NetSpectWindow, qtbot, TestUser: dict) -> None:
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
    @pytest.mark.parametrize('newEmail', [f'newemail{random.randint(1, 10)}@netspect.com', f'username{random.randint(1, 10)}@something.com', f'email{random.randint(1, 10)}@test.co.il'])
    def testChangeEmailPositive(self, NetSpectWindow, qtbot, TestUser: dict, newEmail: str) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0, 'Failed logging into user\'s account.'

        # go to settings page
        NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

        # clear existing input and fill new email
        NetSpectWindow.ui.emailLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.emailLineEdit, newEmail)

        # click save email button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.emailPushButton, Qt.LeftButton)

        # wait until save email process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('email') != None, signal=NetSpectWindow.sqlManager.changeEmailResultSignal)

        # assert change email was successful
        newEmail = NetSpectWindow.userData.get('email')
        assert isinstance(newEmail, str) and newEmail != TestUser.get('email'), 'Failed changing user\'s email.'

        # assert no error message appeared
        errorMessage = NetSpectWindow.ui.saveEmailErrorMessageLabel.text()
        assert NetSpectWindow.ui.saveEmailErrorMessageLabel.isVisible() == False, f'Error message is visible after changing the email. Error: {errorMessage}'
        assert errorMessage == '', f'Error message exists after changing the email. Error: {errorMessage}'

        # change email back to default, first clear existing input and fill default email
        NetSpectWindow.ui.emailLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.emailLineEdit, TestUser.get('email'))

        # click save email button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.emailPushButton, Qt.LeftButton)


    # test step function for testing change email negative scenarios
    @pytest.mark.parametrize('newEmail', [f'new.user{random.randint(1, 10)}@', f'username{random.randint(1, 10)}@something', f'email{random.randint(1, 10)}test.co.il'])
    def testChangeEmailNegative(self, NetSpectWindow, qtbot, TestUser: dict, newEmail: str) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0, 'Failed logging into user\'s account.'

        # go to settings page
        NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

        # clear existing input and fill new email
        NetSpectWindow.ui.emailLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.emailLineEdit, newEmail)

        # click save email button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.emailPushButton, Qt.LeftButton)

        # assert error message appeared (check if it appeared, if not change the email back to default and fail the test)
        if NetSpectWindow.ui.saveEmailErrorMessageLabel.isVisible() == False or NetSpectWindow.ui.saveEmailErrorMessageLabel.text() == '':
            # change email back to default, first clear existing input and fill default email
            NetSpectWindow.ui.emailLineEdit.clear()
            qtbot.keyClicks(NetSpectWindow.ui.emailLineEdit, TestUser.get('email'))

            # click save email button
            time.sleep(1)
            qtbot.mouseClick(NetSpectWindow.ui.emailPushButton, Qt.LeftButton)

            assert True == False, f'Error message is not visible after changing the email to an invalid one. Was able to change email to an invalid email.'


    # test step function for testing change username positive scenarios
    @pytest.mark.parametrize('newUsername', [f'TestName{random.randint(1, 10)}', f'testName{random.randint(1, 10)}', f'Testname123{random.randint(1, 10)}'])
    def testChangeUsernamePositive(self, NetSpectWindow, qtbot, TestUser: dict, newUsername: str) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0, 'Failed logging into user\'s account.'

        # go to settings page
        NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

        # clear existing input and fill new username
        NetSpectWindow.ui.usernameLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.usernameLineEdit, newUsername)

        # click save username button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.usernamePushButton, Qt.LeftButton)

        # wait until save username process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('username') != None, signal=NetSpectWindow.sqlManager.changeUsernameResultSignal)

        # assert change email was successful
        newUsername = NetSpectWindow.userData.get('username')
        assert isinstance(newUsername, str) and newUsername != TestUser.get('username'), 'Failed changing user\'s username.'

        # assert no error message appeared
        errorMessage = NetSpectWindow.ui.saveUsernameErrorMessageLabel.text()
        assert NetSpectWindow.ui.saveUsernameErrorMessageLabel.isVisible() == False, f'Error message is visible after changing the username. Error: {errorMessage}'
        assert errorMessage == '', f'Error message exists after changing the username. Error: {errorMessage}'

        # change username back to default, first clear existing input and fill default username
        NetSpectWindow.ui.usernameLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.usernameLineEdit, TestUser.get('username'))

        # click save username button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.usernamePushButton, Qt.LeftButton)


    # test step function for testing change username negative scenarios
    @pytest.mark.parametrize('newUsername', [f'A{random.randint(1, 5)}', f'{random.randint(1, 5)}Me', f'{random.randint(1, 100)}'])
    def testChangeUsernameNegative(self, NetSpectWindow, qtbot, TestUser: dict, newUsername: str) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0, 'Failed logging into user\'s account.'

        # go to settings page
        NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

        # clear existing input and fill new username
        NetSpectWindow.ui.usernameLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.usernameLineEdit, newUsername)

        # click save username button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.usernamePushButton, Qt.LeftButton)

        # assert error message appeared (check if it appeared, if not change the username back to default and fail the test)
        if NetSpectWindow.ui.saveUsernameErrorMessageLabel.isVisible() == False or NetSpectWindow.ui.saveUsernameErrorMessageLabel.text() == '':
            # change username back to default, first clear existing input and fill default username
            NetSpectWindow.ui.usernameLineEdit.clear()
            qtbot.keyClicks(NetSpectWindow.ui.usernameLineEdit, TestUser.get('username'))

            # click save username button
            time.sleep(1)
            qtbot.mouseClick(NetSpectWindow.ui.usernamePushButton, Qt.LeftButton)

            assert True == False, f'Error message is not visible after changing the username to an invalid one. Was able to change username to an invalid username.'


    # test step function for testing change password positive scenarios
    @pytest.mark.parametrize('newPassword', [('User1234', 'User1234'), ('1234Abcd', '1234Abcd'), ('12!@#aB', '12!@#aB')])
    def testChangePasswordPositive(self, NetSpectWindow, qtbot, TestUser: dict, newPassword: tuple) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0, 'Failed logging into user\'s account.'

        # go to settings page
        NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)
        
        # clear existing input and fill new passwords
        NetSpectWindow.ui.currentPasswordLineEdit.clear()
        NetSpectWindow.ui.newPasswordLineEdit.clear()
        NetSpectWindow.ui.confirmPasswordLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.currentPasswordLineEdit, TestUser.get('password'))
        qtbot.keyClicks(NetSpectWindow.ui.newPasswordLineEdit, newPassword[0])
        qtbot.keyClicks(NetSpectWindow.ui.confirmPasswordLineEdit, newPassword[1])

        # click save password button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.passwordPushButton, Qt.LeftButton)

        # wait until change password process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.changePasswordResultSignal)

        # assert no error message appeared
        errorMessage = NetSpectWindow.ui.savePasswordErrorMessageLabel.text()
        assert NetSpectWindow.ui.savePasswordErrorMessageLabel.isVisible() == False, f'Error message is visible after changing the password. Error: {errorMessage}'
        assert errorMessage == '', f'Error message exists after changing the password. Error: {errorMessage}'

        # change password back to default password, first clear existing input and fill default passwords
        NetSpectWindow.ui.currentPasswordLineEdit.clear()
        NetSpectWindow.ui.newPasswordLineEdit.clear()
        NetSpectWindow.ui.confirmPasswordLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.currentPasswordLineEdit, newPassword[0])
        qtbot.keyClicks(NetSpectWindow.ui.newPasswordLineEdit, TestUser.get('password'))
        qtbot.keyClicks(NetSpectWindow.ui.confirmPasswordLineEdit, TestUser.get('password'))

        # click save password button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.passwordPushButton, Qt.LeftButton)


    # test step function for testing change password negative scenarios
    @pytest.mark.parametrize('newPassword', [('User123', 'User1'), ('User1234', ''), ('U2', 'U2')])
    def testChangePasswordNegative(self, NetSpectWindow, qtbot, TestUser: dict, newPassword: tuple) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0, 'Failed logging into user\'s account.'

        # go to settings page
        NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

        # clear existing input and fill new password
        NetSpectWindow.ui.currentPasswordLineEdit.clear()
        NetSpectWindow.ui.newPasswordLineEdit.clear()
        NetSpectWindow.ui.confirmPasswordLineEdit.clear()
        qtbot.keyClicks(NetSpectWindow.ui.currentPasswordLineEdit, TestUser.get('password'))
        qtbot.keyClicks(NetSpectWindow.ui.newPasswordLineEdit, newPassword[0])
        qtbot.keyClicks(NetSpectWindow.ui.confirmPasswordLineEdit, newPassword[1])

        # click save password button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.passwordPushButton, Qt.LeftButton)

        # assert error message appeared (check if it appeared, if not change the password back to default and fail the test)
        if NetSpectWindow.ui.savePasswordErrorMessageLabel.isVisible() == False or NetSpectWindow.ui.savePasswordErrorMessageLabel.text() == '':
            # change password back to default, first clear existing input and fill default password
            NetSpectWindow.ui.currentPasswordLineEdit.clear()
            NetSpectWindow.ui.newPasswordLineEdit.clear()
            NetSpectWindow.ui.confirmPasswordLineEdit.clear()
            qtbot.keyClicks(NetSpectWindow.ui.currentPasswordLineEdit, newPassword[0])
            qtbot.keyClicks(NetSpectWindow.ui.newPasswordLineEdit, TestUser.get('password'))
            qtbot.keyClicks(NetSpectWindow.ui.confirmPasswordLineEdit, TestUser.get('password'))

            # click save password button
            time.sleep(1)
            qtbot.mouseClick(NetSpectWindow.ui.passwordPushButton, Qt.LeftButton)

            assert True == False, f'Error message is not visible after changing the password to an invalid one. Was able to change password to an invalid password.'


    # test step function for testing delete account
    def testDeleteAccount(self, NetSpectWindow, qtbot, TestUser: dict) -> None:
        # fill login form
        qtbot.keyClicks(NetSpectWindow.ui.loginUsernameLineEdit, TestUser.get('username'))
        qtbot.keyClicks(NetSpectWindow.ui.loginPasswordLineEdit, TestUser.get('password'))

        # click login button
        time.sleep(1)
        qtbot.mouseClick(NetSpectWindow.ui.loginPushButton, Qt.LeftButton)

        # wait until login process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') != None, signal=NetSpectWindow.sqlManager.loginResultSignal)

        # assert login was successful
        userId = NetSpectWindow.userData.get('userId')
        assert isinstance(userId, int) and userId > 0, 'Failed logging into user\'s account.'

        # go to settings page
        NetSpectWindow.ui.stackedWidget.setCurrentIndex(4)

        # delete test user account
        time.sleep(1)
        NetSpectWindow.sqlManager.HardDeleteAccount()

        # wait until save email process finishes
        self.WaitCondition(qtbot, condition=lambda: NetSpectWindow.userData.get('userId') == None, signal=NetSpectWindow.sqlManager.deleteAccountResultSignal)

        # assert delete account was successful
        userId = NetSpectWindow.userData.get('userId')
        assert userId == None, 'Failed deleting user\'s account.'

#-----------------------------------------------------TEST-GUI-FUNCTIONS-END----------------------------------------------------#

#------------------------------------------------------------MAIN---------------------------------------------------------------#
# main function for running the tests
if __name__ == '__main__':
    pytest.main(['-v', __file__])

#----------------------------------------------------------MAIN-END-------------------------------------------------------------#