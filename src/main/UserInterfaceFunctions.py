from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QEasingCurve, QSortFilterProxyModel, QAbstractTableModel, QModelIndex, QMargins
from PySide6.QtWidgets import QApplication, QMenu, QListWidget, QTableWidget, QTableView, QWidget, QDialog, QPushButton, QLabel, QLineEdit, QStyle, QSizePolicy, QGridLayout, QHeaderView, QSystemTrayIcon, QVBoxLayout, QHBoxLayout, QGraphicsDropShadowEffect, QToolTip
from PySide6.QtGui import QAction, QColor, QIcon, QPixmap, QFont, QCursor, QPainter, QPen
from PySide6.QtCharts import QChart, QChartView, QPieSeries, QBarSeries, QHorizontalStackedBarSeries, QBarSet, QBarCategoryAxis, QValueAxis
from datetime import datetime, timedelta
from pathlib import Path

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located

#-------------------------------------------ANIMATION-methodS----------------------------------------------#

# method for openning the left sideframe with an animation
def OpenSideFrame(self):
    # create animation for sideframe
    self.ui.sideFrame.currentAnimation = QPropertyAnimation(self.ui.sideFrame, b'minimumWidth')
    self.ui.sideFrame.currentAnimation.setDuration(500)
    self.ui.sideFrame.currentAnimation.setEasingCurve(QEasingCurve.InOutQuad)
    self.ui.sideFrame.currentAnimation.setStartValue(70)
    self.ui.sideFrame.currentAnimation.setEndValue(210)
                
    # start the animation
    self.ui.sideFrame.currentAnimation.start()

    # show sidebar labels
    self.ui.menuIcon.hide()
    self.ui.closeMenuIcon.show()
    self.ui.homePageLabel.show()
    self.ui.analyticsLabel.show()
    self.ui.reportLabel.show()
    self.ui.infoLabel.show()


# method for closing the left sideframe with an animation
def CloseSideFrame(self):
    # create animation for sideframe
    self.ui.sideFrame.currentAnimation = QPropertyAnimation(self.ui.sideFrame, b'minimumWidth')
    self.ui.sideFrame.currentAnimation.setDuration(500)
    self.ui.sideFrame.currentAnimation.setEasingCurve(QEasingCurve.OutQuad)
    self.ui.sideFrame.currentAnimation.setStartValue(210)
    self.ui.sideFrame.currentAnimation.setEndValue(70)
    
    # start the animation
    self.ui.sideFrame.currentAnimation.start()

    # add delayed animations to icons and labels
    QTimer.singleShot(100, lambda: HideSideBarLabels(self))
    QTimer.singleShot(400, lambda: ShowSideBarMenuIcon(self))
    self.ui.sideFrame.setMaximumWidth(70)
    self.ui.menuIcon.setFixedWidth(50)


# method for opening the login or register sideframes after clicking the account icon
def AccountIconClicked(self):
    # create animation for sideframe
    self.ui.loginRegisterVerticalFrame.currentAnimation = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    self.ui.loginRegisterVerticalFrame.currentAnimation.setDuration(500)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEasingCurve(QEasingCurve.InOutQuad)
    
    # start fade in animation for sideframe
    if self.ui.loginRegisterVerticalFrame.width() == 0:
        self.ui.loginRegisterVerticalFrame.currentAnimation.setStartValue(0)
        self.ui.loginRegisterVerticalFrame.currentAnimation.setEndValue(303)
        self.ui.loginUsernameLineEdit.setFocus() if self.ui.loginFrame.isVisible() else self.ui.registerEmailLineEdit.setFocus()
        # check if reset passowrd is visible, if so hide it and show login
        if self.ui.resetPasswordFrame.isVisible():
            ToggleLoginResetPassword(self, False)

    # else start fade out animation for sideframe
    else:
        self.ui.loginRegisterVerticalFrame.currentAnimation.setStartValue(303)
        self.ui.loginRegisterVerticalFrame.currentAnimation.setEndValue(0)
        ClearLoginLineEdits(self)
        ClearRegisterLineEdits(self)
        ClearResetPasswordLineEdits(self)
        self.ui.loginUsernameLineEdit.clearFocus()
        self.ui.registerEmailLineEdit.clearFocus()
        self.ui.resetPasswordEmailLineEdit.clearFocus()

    # start the animation for openning the frame
    self.ui.loginRegisterVerticalFrame.currentAnimation.start()
    ApplyShadowLoginRegister(self)


# method for changing between the login and register sideframes
def SwitchBetweenLoginAndRegister(self, showRegister=True):
    # create first animation for closing sideframe
    self.ui.loginRegisterVerticalFrame.currentAnimation = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    self.ui.loginRegisterVerticalFrame.currentAnimation.setDuration(200)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEasingCurve(QEasingCurve.InOutQuad)
    
    # using the current width of sideframe as the start value
    currentWidth = self.ui.loginRegisterVerticalFrame.width()
    self.ui.loginRegisterVerticalFrame.currentAnimation.setStartValue(currentWidth)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEndValue(0)
    
    # start the first animation and chain the second animation to start after the first finishes
    self.ui.loginRegisterVerticalFrame.currentAnimation.start()
    self.ui.loginRegisterVerticalFrame.currentAnimation.finished.connect(lambda: ToggleLoginRegister(self, showRegister)) 


# method for changing between the login and reset password sideframes
def SwitchBetweenLoginAndForgotPassword(self, showResetPassword=True):
    # first animation for closing sideframe
    self.ui.loginRegisterVerticalFrame.currentAnimation = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    self.ui.loginRegisterVerticalFrame.currentAnimation.setDuration(200)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEasingCurve(QEasingCurve.InOutQuad)
    
    # using the current width of sideframe as the start value
    currentWidth = self.ui.loginRegisterVerticalFrame.width()
    self.ui.loginRegisterVerticalFrame.currentAnimation.setStartValue(currentWidth)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEndValue(0)
    
    # start the first animation and chain the second animation to start after the first finishes
    self.ui.loginRegisterVerticalFrame.currentAnimation.start()
    self.ui.loginRegisterVerticalFrame.currentAnimation.finished.connect(lambda: ToggleLoginResetPassword(self, showResetPassword)) 


# method for toggling between login and register sideframes
def ToggleLoginRegister(self, showRegister):
    # means we need to switch to register sideframe
    if showRegister:
        # clear all line edits and show register frame
        ClearLoginLineEdits(self)
        self.ui.loginUsernameLineEdit.clearFocus()
        self.ui.loginFrame.hide()
        self.ui.registerFrame.show()
        self.ui.registerEmailLineEdit.setFocus()
    # else means we need to switch to login sideframe
    else:
        # clear all line edits and show login frame
        ClearRegisterLineEdits(self)
        self.ui.registerEmailLineEdit.clearFocus()
        self.ui.registerFrame.hide()
        self.ui.loginFrame.show()
        self.ui.loginUsernameLineEdit.setFocus()

    # second animation for opening the frame
    self.ui.loginRegisterVerticalFrame.currentAnimation = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    self.ui.loginRegisterVerticalFrame.currentAnimation.setDuration(375)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEasingCurve(QEasingCurve.InOutQuad)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setStartValue(0)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEndValue(303)
    self.ui.loginRegisterVerticalFrame.currentAnimation.start()


# method for toggling between login and reset passowrd sideframes
def ToggleLoginResetPassword(self, showResetPassword):
    # means we need to switch to reset password sideframe
    if showResetPassword:
        # clear all line edits and show reset password frame
        ClearLoginLineEdits(self)
        self.ui.loginUsernameLineEdit.clearFocus()
        self.ui.loginFrame.hide()
        self.ui.resetPasswordFrame.show()
        self.ui.resetPasswordEmailLineEdit.setFocus()
    # else means we need to switch to login sideframe
    else:
        # clear all line edits and show login frame
        ClearResetPasswordLineEdits(self)
        self.ui.resetPasswordEmailLineEdit.clearFocus()
        self.ui.resetPasswordFrame.hide()
        self.ui.loginFrame.show()
        self.ui.loginUsernameLineEdit.setFocus()

    # show the correct line edit and push button for frame
    ToggleBetweenEmailAndCodeResetPassword(self, showResetPassword)

    # second animation for opening the frame
    self.ui.loginRegisterVerticalFrame.currentAnimation = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    self.ui.loginRegisterVerticalFrame.currentAnimation.setDuration(375)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEasingCurve(QEasingCurve.InOutQuad)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setStartValue(0)
    self.ui.loginRegisterVerticalFrame.currentAnimation.setEndValue(303)
    self.ui.loginRegisterVerticalFrame.currentAnimation.start()

#-----------------------------------------ANIMATION-FUNCTIONS-END--------------------------------------------#

#---------------------------------------------CLICK-FUNCTIONS------------------------------------------------#

# method for hiding side bar labels
def HideSideBarLabels(self):
    self.ui.homePageLabel.hide()
    self.ui.analyticsLabel.hide()
    self.ui.reportLabel.hide()
    self.ui.infoLabel.hide()


# method for showing side bar icons
def ShowSideBarMenuIcon(self):
    self.ui.menuIcon.show()
    self.ui.closeMenuIcon.hide()


# method for changing between enter email and enter code screens in reset password
def ToggleBetweenEmailAndCodeResetPassword(self, isEmail=True):
    # means we need to show reset password email frame
    if isEmail:
        # hide reset password code frame and show reset password email frame
        self.ui.resetPasswordCodeLineEdit.hide()
        self.ui.resetPasswordCodeErrorMessageLabel.hide()
        self.ui.verifyCodeButtonFrame.hide()
        self.ui.resetPasswordEmailLineEdit.show()
        self.ui.resetPasswordEmailErrorMessageLabel.hide()
        self.ui.sendCodeButtonFrame.show()

    # means we need to show reset password code frame
    else:
        # hide reset password email frame and show reset password code frame
        self.ui.resetPasswordEmailLineEdit.hide()
        self.ui.resetPasswordEmailErrorMessageLabel.hide()
        self.ui.sendCodeButtonFrame.hide()
        self.ui.resetPasswordCodeLineEdit.show()
        self.ui.resetPasswordCodeErrorMessageLabel.hide()
        self.ui.verifyCodeButtonFrame.show()


# method for showing and hiding the change email, username, password and operation mode from settings page 
def ToggleSettingsInputFields(self, state=False):
    # if true we need to show email, username, password and operation mode
    if state:
        self.ui.settingsChangeVerticalFrame.show()
        self.ui.opperationModeHorizontalFrame.show()
        self.ui.deleteAccoutPushButton.show()
        self.ui.settingsInterfaceMacButtonsVerticalFrame.setContentsMargins(0, 10, 0, 0)
    # else we need to hide email, username, password and operation mode
    else:
        self.ui.settingsChangeVerticalFrame.hide()
        self.ui.opperationModeHorizontalFrame.hide()
        self.ui.deleteAccoutPushButton.hide()
        self.ui.settingsInterfaceMacButtonsVerticalFrame.setContentsMargins(40, 0, 0, 0)


# method for showing and hiding user interface
def ToggleUserInterface(self, state=False):
    # if true we need to show user logged in labels
    if state:
        self.ui.accountIcon.hide()
        self.ui.reportDurationComboBox.setEnabled(True)
        self.ui.analyticsYearComboBox.setEnabled(True)
        self.ui.welcomeLabel.show()
        self.ui.logoutIcon.show()
        ToggleSettingsInputFields(self, True)

    # else we hide user labels
    else:
        ToggleSettingsInputFields(self, False)
        self.ui.logoutIcon.hide()
        self.ui.welcomeLabel.hide()
        self.ui.analyticsYearComboBox.setEnabled(False)
        self.ui.reportDurationComboBox.setEnabled(False)
        self.ui.welcomeLabel.clear()
        self.ui.accountIcon.show()
        self.ui.colorModeComboBox.setCurrentIndex(0) #reset the color combobox if the user has logged out
        self.ui.operationModeComboBox.setCurrentIndex(0) #reset the operation mode combobox if the user has logged out

    # clear detection counter, history and report tables, mac addresses list, sideframe and settings page
    self.ui.numberOfDetectionsCounter.setText('0')
    self.ui.historyTableWidget.setRowCount(0)
    self.ui.reportPreviewTableModel.ClearRows()
    self.ui.macAddressListWidget.clear()
    ClearLoginLineEdits(self)
    ClearRegisterLineEdits(self)
    ClearResetPasswordLineEdits(self)
    ClearSettingsPageLineEdits(self)

    # reset analytics combobox with current chart data
    self.ui.analyticsYearComboBox.clear()
    InitAnalyticsYearCombobox(self)

    # reset attack distribution pie chart
    ResetPieChartToDefault(self) #reset our pie chart

    # reset all the analytics charts
    ResetHistogramChartToDefault(self) #reset our histogram chart
    ResetBarChartToDefault(self) #reset our horizontal bar chart

    # reset analytics cards
    ResertDataInCards(self)

    # reset comboboxes, checkboxes and set default color mode for gui
    self.ui.reportDurationComboBox.setCurrentIndex(4)
    self.ui.arpSpoofingCheckBox.setChecked(True)
    self.ui.portScanningCheckBox.setChecked(True)
    self.ui.denialOfServiceCheckBox.setChecked(True)
    self.ui.dnsTunnelingCheckBox.setChecked(True)
    self.ui.machineInfoCheckBox.setChecked(False)
    ToggleReportInterface(self, False)
    ToggleColorMode(self)
    ToggleOperationMode(self)


# method for showing and hiding report interface
def ToggleReportInterface(self, state):
    # if true we need to show report interface
    if state:
        self.ui.downloadReportPushButton.hide()
        self.ui.cancelReportPushButton.show()
        self.ui.reportProgressBar.setValue(0)
        self.ui.reportProgressBar.show()
    # else we hide report interface
    else:
        self.ui.reportProgressBar.hide()
        self.ui.reportProgressBar.setValue(0)
        self.ui.cancelReportPushButton.hide()
        self.ui.downloadReportPushButton.show()


# method for toggling between detection and collection interfaces
def ToggleOperationMode(self):
    # means we need to change to detection interface
    if self.ui.operationModeComboBox.currentIndex() == 0:
        self.userData['operationMode'] = 0
        self.ui.initiateDefenceLabel.setText('Initiate Detection')
        self.ui.trayIcon.toggleDetectionAction.setText('Start Detection')
    # else means we need to change to data collection interface
    else:
        self.userData['operationMode'] = 1 if self.ui.operationModeComboBox.currentIndex() == 1 else 2
        self.ui.initiateDefenceLabel.setText('Initiate Collection')
        self.ui.trayIcon.toggleDetectionAction.setText('Start Collection')


# method for changing the current page index on the stack widget
def ChangePageIndex(self, index):
    # if index is different from our current index we change to desired page index
    if self.ui.stackedWidget.currentIndex() != index:
        # clear settings page line edits, error messages and clear focus
        ClearSettingsPageLineEdits(self)
        self.ui.emailLineEdit.clearFocus()
        self.ui.usernameLineEdit.clearFocus()
        self.ui.currentPasswordLineEdit.clearFocus()
        self.ui.newPasswordLineEdit.clearFocus()
        self.ui.confirmPasswordLineEdit.clearFocus()
        self.ui.macAddressLineEdit.clearFocus()
        self.ui.stackedWidget.setCurrentIndex(index)


# method for initializing eye buttons for password line edits in gui
def InitPasswordLineEditEyeButtons(self):
    # get password eye icon
    eyeIcon = QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'EyeOpen.png'))

    # set the toggle password visability eye icon in login and register
    self.ui.loginPasswordEyeButton = self.ui.loginPasswordLineEdit.addAction(eyeIcon, QLineEdit.TrailingPosition)
    self.ui.loginPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.loginPasswordLineEdit, self.ui.loginPasswordEyeButton))
    self.ui.registerPasswordEyeButton = self.ui.registerPasswordLineEdit.addAction(eyeIcon, QLineEdit.TrailingPosition)
    self.ui.registerPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.registerPasswordLineEdit, self.ui.registerPasswordEyeButton))
    self.ui.registerConfirmPasswordEyeButton = self.ui.registerConfirmPasswordLineEdit.addAction(eyeIcon, QLineEdit.TrailingPosition)
    self.ui.registerConfirmPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.registerConfirmPasswordLineEdit, self.ui.registerConfirmPasswordEyeButton))

    # set the toggle password visability eye icon in the settings page for change password section
    self.ui.currentPasswordEyeButton = self.ui.currentPasswordLineEdit.addAction(eyeIcon, QLineEdit.TrailingPosition)
    self.ui.currentPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.currentPasswordLineEdit, self.ui.currentPasswordEyeButton))
    self.ui.newPasswordEyeButton = self.ui.newPasswordLineEdit.addAction(eyeIcon, QLineEdit.TrailingPosition)
    self.ui.newPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.newPasswordLineEdit, self.ui.newPasswordEyeButton))
    self.ui.confirmPasswordEyeButton = self.ui.confirmPasswordLineEdit.addAction(eyeIcon, QLineEdit.TrailingPosition)
    self.ui.confirmPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.confirmPasswordLineEdit, self.ui.confirmPasswordEyeButton))


# method for toggling the password visibility using the eye button
def TogglePasswordVisibility(lineEditWidget, eyeButton):
    # check if line edit in password mode
    if lineEditWidget.echoMode() == QLineEdit.Password:
        lineEditWidget.setEchoMode(QLineEdit.Normal) #show the password
        eyeButton.setIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'EyeClosed.png'))) #change to closed eye icon
    # else means line edit in normal mode
    else:
        lineEditWidget.setEchoMode(QLineEdit.Password) #hide the password
        eyeButton.setIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'EyeOpen.png'))) #change to open eye icon


# method for initializing the analytics combobox with year values
def InitAnalyticsYearCombobox(self):
    # check that barChartData dictionary is initialized before setting comobox itemss
    if self.userData.get('analyticsChartData', {}).get('barChartData', {}):
        self.ui.analyticsYearComboBox.blockSignals(True) #block signals while adding items to year combobox
        self.ui.analyticsYearComboBox.addItems(list(reversed(self.userData.get('analyticsChartData', {}).get('barChartData', {}))))
        self.ui.analyticsYearComboBox.blockSignals(False) #enable signals again after adding the items to year combobox


# method for toggling between detection or collection states and setting startStop button stylesheet accordingly
def ToggleStartStopState(self, state):
    # get the correct styles based on given state
    currentStyleSheet = f'''
        #startStopPushButton {{
            border-radius: 60px;
            {'background-color: #d84f4f;' if state else 'background-color: #3a8e32;'}
            border: 1px solid black;
            color: black;
            font-weight: bold;
            outline: none;
        }}

        #startStopPushButton:hover {{
            {'background-color: #db6060;' if state else 'background-color: #4d9946;'}
        }}

        #startStopPushButton:pressed {{
            {'background-color: #ac3f3f;' if state else 'background-color: #2e7128;'}
        }}
    '''

    # if true means we need to change state of startStop button to "Stop Detection" stylesheet
    if state:
        self.ui.startStopPushButton.setText('STOP') #set button text
        # we check operation mode state and change tray icon toggle detection action text accordingly
        if self.ui.operationModeComboBox.currentIndex() == 0:
            self.ui.trayIcon.toggleDetectionAction.setText('Stop Detection')
        else:
            self.ui.trayIcon.toggleDetectionAction.setText('Stop Collection')
    # else means we need to change state of startStop button to "Start Detection" stylesheet
    else:
        self.ui.startStopPushButton.setText('START') #set button text
        # we check operation mode state and change tray icon toggle detection action text accordingly
        if self.ui.operationModeComboBox.currentIndex() == 0:
            self.ui.trayIcon.toggleDetectionAction.setText('Start Detection')
        else:
            self.ui.trayIcon.toggleDetectionAction.setText('Start Collection')
    # finally set the stylesheet of startStop button based on calculated stylesheet
    self.ui.startStopPushButton.setStyleSheet(currentStyleSheet)


# method for toggling between light and dark mode by the user (also used when logging in and out of an account)
def ToggleColorMode(self):
    try:
        # represents our color mode dictionary with predefiend parameters for changing color mode styles, initialized as dark mode
        colorMode = {'lightMode': 0, 'fileName': 'darkModeStyles.qss', 'iconColor': 'Light', 'labelColor': '#f3f3f3'} 

        # check if color mode combobox is set to light mode, if so we change color mode dictionary to light mode dictionary
        if self.ui.colorModeComboBox.currentText() == 'Light Mode': 
            colorMode = {'lightMode': 1, 'fileName': 'lightModeStyles.qss', 'iconColor': 'Dark', 'labelColor': '#151519'}

        # check that our desired styles qss file exists
        if Path(currentDir.parent / 'interface' / colorMode.get('fileName')).exists():
            # clear css from main element
            self.setStyleSheet('')

            # clear existing css from each element in the ui file
            for child in self.findChildren(QWidget):
                child.setStyleSheet('')

            # apply dark mode or light mode theme to the application based on users selection
            self.userData['lightMode'] = colorMode.get('lightMode')
            self.ui.accountIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'Account{colorMode.get('iconColor')}.png')))
            self.ui.settingsIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'Settings{colorMode.get('iconColor')}.png')))
            self.ui.logoutIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'Logout{colorMode.get('iconColor')}.png')))
            self.ui.menuIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'BulletedMenu{colorMode.get('iconColor')}.png')))
            self.ui.closeMenuIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'BulletedMenuRotated{colorMode.get('iconColor')}.png')))
            self.ui.homePageIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'WorkStation{colorMode.get('iconColor')}.png')))
            self.ui.analyticsIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'Analytics{colorMode.get('iconColor')}.png')))
            self.ui.reportIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'Document{colorMode.get('iconColor')}.png')))
            self.ui.infoIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / f'Info{colorMode.get('iconColor')}.png')))
            self.ui.githubInfoLabel.setText(f'''
                <html>
                    <head/>
                    <body>
                        <p>
                            <a href='https://github.com/Shayhha/NetSpect'>
                                <span style="text-decoration: underline; color: {colorMode.get('labelColor')};">Visit NetSpect Page</span>
                            </a>
                        </p>
                    </body>
                </html>
            ''')

            # load desired styles qss file and apply stylesheet for each of our elements in ui
            with open(currentDir.parent / 'interface' / colorMode.get('fileName'), 'r') as stylesFile:
                self.setStyleSheet(stylesFile.read())

            # update color mode for each of our charts
            UpdatePieChartColorMode(self)
            UpdateHistogramChartColorMode(self)
            UpdateBarChartColorMode(self)

            # update the font sizes after updating the value
            UpdateFontSizeInLabel(self, self.ui.totalNumOfAttacksValueLabel)
            UpdateFontSizeInLabel(self, self.ui.attacksPerMonthValueLabel)

        # else desired styles qss file does not exists, we show messagebox
        else:
            self.ui.colorModeComboBox.blockSignals(True) #block signals while changing index in color mode combobox
            self.ui.colorModeComboBox.setCurrentIndex(0 if colorMode.get('lightMode') else 1) #reset the color combobox
            self.ui.colorModeComboBox.blockSignals(False) #enable signals again after changing index in color mode combobox
            ShowMessageBox('Error Occurred', f'Interface {colorMode.get('fileName')} file was not found. Please ensure it exist in the interface folder.', 'Critical')

    except Exception as e:
        self.ui.colorModeComboBox.blockSignals(True) #block signals while changing index in color mode combobox
        self.ui.colorModeComboBox.setCurrentIndex(0 if colorMode.get('lightMode') else 1) #reset the color combobox
        self.ui.colorModeComboBox.blockSignals(False) #enable signals again after changing index in color mode combobox
        ShowMessageBox('Error Changing Color Mode', 'Error occurred while changing color mode, try again later.', 'Critical')

#-------------------------------------------CLICK-FUNCTIONS-END----------------------------------------------#

#---------------------------------------------OTHER-FUNCTIONS------------------------------------------------#

# method for adding a box shadow to the login and register sideframes
def ApplyShadowLoginRegister(self):
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(15)
    shadow.setXOffset(-8)
    shadow.setYOffset(0)
    shadow.setColor(QColor(0, 0, 0, 85))
    self.ui.loginRegisterVerticalFrame.setGraphicsEffect(shadow)


# method for adding a box shadow to the left side bar
def ApplyShadowSidebar(self):
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(5)
    shadow.setXOffset(5)
    shadow.setYOffset(0)
    shadow.setColor(QColor(0, 0, 0, 50))
    self.ui.sideFrame.setGraphicsEffect(shadow)


# method for clearing login line edits and error message
def ClearLoginLineEdits(self):
    # clear login line edits and error messages
    self.ui.loginUsernameLineEdit.clear()
    self.ui.loginPasswordLineEdit.clear()
    ClearErrorMessageText(self.ui.loginErrorMessageLabel)


# method for clearing register line edits and error messag
def ClearRegisterLineEdits(self):
    # clear register line edits and error messages
    self.ui.registerEmailLineEdit.clear()
    self.ui.registerUsernameLineEdit.clear()
    self.ui.registerPasswordLineEdit.clear()
    self.ui.registerConfirmPasswordLineEdit.clear()
    ClearErrorMessageText(self.ui.registerErrorMessageLabel)


# method for clearing the reset password line edits and error messages
def ClearResetPasswordLineEdits(self):
    # clear reset password line edits and error messages
    self.ui.resetPasswordEmailLineEdit.clear()
    self.ui.resetPasswordCodeLineEdit.clear()
    ClearErrorMessageText(self.ui.resetPasswordEmailErrorMessageLabel)
    ClearErrorMessageText(self.ui.resetPasswordCodeErrorMessageLabel)


# method for clearing all pages line edits end error messages
def ClearSettingsPageLineEdits(self):
    # clear settings page line edits and clear error messages
    self.ui.emailLineEdit.clear()
    self.ui.usernameLineEdit.clear()
    self.ui.currentPasswordLineEdit.clear()
    self.ui.newPasswordLineEdit.clear()
    self.ui.confirmPasswordLineEdit.clear()
    self.ui.macAddressLineEdit.clear()
    ClearErrorMessageText(self.ui.saveEmailErrorMessageLabel)
    ClearErrorMessageText(self.ui.saveUsernameErrorMessageLabel)
    ClearErrorMessageText(self.ui.savePasswordErrorMessageLabel)
    ClearErrorMessageText(self.ui.macAddressBlacklistErrorMessageLabel)

    # check if user is logged in, if so we set his email and username back to the line edits
    if self.userData.get('userId'):
        self.ui.emailLineEdit.setText(self.userData.get('email')) #set email of user in settings page
        self.ui.usernameLineEdit.setText(self.userData.get('userName')) #set username of user in settings page


# method that shows right-click menu for copying and deleting items for widget objects
def ShowContextMenu(self, widgetObject, position, isDelete=False):
    currentStyleSheet = f'''
        #contextMenu {{
            {'background-color: #2d2d2d;' if self.userData.get('lightMode') == 0 else 'background-color: #f3f3f3;'}
            {'color: #f3f3f3;' if self.userData.get('lightMode') == 0 else 'color: black;'}
            {'border: 1px solid #555;' if self.userData.get('lightMode') == 0 else 'border: 1px solid gray;'}
            padding: 5px;
            border-radius: 6px;
        }}

        #contextMenu::item {{
            padding: 5px 20px;
            background-color: transparent;
        }}

        #contextMenu::item:selected {{
            {'background-color: rgba(255, 255, 255, 0.1);' if self.userData.get('lightMode') == 0 else 'background-color: rgba(0, 0, 0, 0.1);'}
            {'color: #ffffff;'if self.userData.get('lightMode') == 0 else 'color: black;'}
            border-radius: 4px;
        }}
    '''

    # create context menu for right-click events
    contextMenu = QMenu()
    contextMenu.setObjectName('contextMenu')
    selectedText = None

    # check if widget object is QListWidget
    if isinstance(widgetObject, QListWidget):
        # get current item that is selected
        item = widgetObject.itemAt(position)
        # check if item is valid, if so add actions
        if item:
            selectedText = item.text()

            # create copy action for context menu
            copyAction = QAction('Copy')
            copyAction.triggered.connect(lambda: CopyToClipboard(selectedText))
            contextMenu.addAction(copyAction)

            # add delete action if isDeleted flag is set
            if isDelete:
                # create delete action for context menu
                deleteAction = QAction('Delete')
                deleteAction.triggered.connect(lambda: self.DeleteMacAddressButtonClicked(item))
                contextMenu.addAction(deleteAction)

    # check if widget object is QTableWidget
    elif isinstance(widgetObject, QTableWidget):
        # get current item at index that is selected
        index = widgetObject.indexAt(position)
        # check if index is valid, if so add action
        if index.isValid():
            selectedText = widgetObject.item(index.row(), index.column()).text()

            # create copy action for context menu
            copyAction = QAction('Copy')
            copyAction.triggered.connect(lambda: CopyToClipboard(selectedText))
            contextMenu.addAction(copyAction)

    # check if widget object is QTableView
    elif isinstance(widgetObject, QTableView):
        # get current item at index that is selected
        index = widgetObject.indexAt(position)
        # check if index is valid, if so add action
        if index.isValid():
            selectedText = index.data()

            # create copy action for context menu
            copyAction = QAction('Copy')
            copyAction.triggered.connect(lambda: CopyToClipboard(selectedText))
            contextMenu.addAction(copyAction)

    # set stylesheet for context menu and show the context menu
    if selectedText:
        contextMenu.setStyleSheet(currentStyleSheet)
        contextMenu.exec(widgetObject.viewport().mapToGlobal(position))


# method that copies the item text to the clipborad
def CopyToClipboard(text):
    clipboard = QApplication.clipboard()  
    clipboard.setText(text)


# method for enabling context menu for mac address list widget
def EnableContextMenuMacAddressListWidget(self):
    # add a context menu to the mac address list widget
    self.ui.macAddressListWidget.setContextMenuPolicy(Qt.CustomContextMenu)
    self.ui.macAddressListWidget.customContextMenuRequested.connect(lambda position : ShowContextMenu(self, self.ui.macAddressListWidget, position, isDelete=True))


# method for enabling context menu for ip addresses list widget
def EnableContextMenuIpAddressesListWidget(self):
    # add a context menu to the ip addresses list widget
    self.ui.ipAddressesListWidget.setContextMenuPolicy(Qt.CustomContextMenu)
    self.ui.ipAddressesListWidget.customContextMenuRequested.connect(lambda position : ShowContextMenu(self, self.ui.ipAddressesListWidget, position))


# method for enabling context menu for history table widget and disable editing
def EnableContextMenuHistoryTableWidget(self):
   # add a context menu to the history table widget and disbale editing
    self.ui.historyTableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) #stretch columns
    self.ui.historyTableWidget.verticalHeader().setSectionResizeMode(QHeaderView.Fixed) #fix row heights
    self.ui.historyTableWidget.setSelectionMode(QTableWidget.NoSelection) #set no selection
    self.ui.historyTableWidget.setEditTriggers(QTableWidget.NoEditTriggers) #set not editable
    self.ui.historyTableWidget.setSortingEnabled(False) #no sorting, comes sorted from database
    self.ui.historyTableWidget.setFocusPolicy(Qt.NoFocus) #set no focus
    self.ui.historyTableWidget.setTextElideMode(Qt.ElideMiddle) #set elide text in the middle
    self.ui.historyTableWidget.setContextMenuPolicy(Qt.CustomContextMenu) #set custom context menu
    self.ui.historyTableWidget.customContextMenuRequested.connect(lambda position: ShowContextMenu(self, self.ui.historyTableWidget, position))


# method for setting the text of an error message like login/register/change email/ etc.
def ChangeErrorMessageText(errorMessageObject, message):
    errorMessageObject.setText('<p style="line-height: 0.7;">' + message + '</p>')
    errorMessageObject.show()


# method for clearing error message of error message label
def ClearErrorMessageText(errorMessageObject):
    errorMessageObject.setText('')
    errorMessageObject.hide()


# method for returning the default style sheet of line edit
def GetDefaultLineEditStyleSheet(self, lineEditName):
    defaultStylesheet = f''' 
        #{lineEditName} {{
            {'background-color: #f3f3f3;' if self.userData.get('lightMode') == 0 else 'background-color: #ebeff7;'}
            {'border: 2px solid lightgray;' if self.userData.get('lightMode') == 0 else 'border: 2px solid #899fce;'}
            border-radius: 10px;
            padding: 0px 5px;
            color: black;
        }}
    '''
    return defaultStylesheet


# method for changing the styles of a line edit when it does not match the regex
def NotifyInvalidLineEdit(self, lineEditWidget, lineEditName, errorMessageLabel=None):
    # get current stylesheet by object name for the given line edit
    defaultStylesheet = GetDefaultLineEditStyleSheet(self, lineEditName)

    # set initial styles
    lineEditWidget.setStyleSheet(defaultStylesheet)

    # clear error message and hide error message label if given
    if errorMessageLabel:
        ClearErrorMessageText(errorMessageLabel)

    # check if the input matches the regex, if not update the border style to red (invalid input)
    if not lineEditWidget.hasAcceptableInput():
        if self.userData.get('lightMode') == 0:
            lineEditWidget.setStyleSheet(defaultStylesheet.replace('border: 2px solid lightgray;', 'border: 2px solid #d84f4f;'))
        else:
            lineEditWidget.setStyleSheet(defaultStylesheet.replace('border: 2px solid #899fce;', 'border: 2px solid #d84f4f;'))

#-------------------------------------------OTHER-FUNCTIONS-END----------------------------------------------#

#--------------------------------------------CUSTOM-MESSAGEBOX-----------------------------------------------#

# custom message box class that will be used to show error messages to the user at certain times
class CustomMessageBox(QDialog):
    isMessageBox = False #represents flag for indicating if message box already exists

    # constructor of custom message box class
    def __init__(self, title, message, iconType, isSelectable=False, parent=None):
        super().__init__(parent)

        # set the message box window title and icon
        self.setWindowTitle(title)
        self.setObjectName('customMessageBox') #set object name for message box
        self.setWindowIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))
        self.setFont(QFont('Cairo', 13)) #set font size for message box

        # create the main vertical layout
        layout = QVBoxLayout()

        # create a horizontal layout for the icon and message
        horizontalLayout = QHBoxLayout()

        # create icon label and get message box icon with our method
        iconLabel = QLabel()
        icon = self.GetMessageBoxIcon(iconType) #use the method to get the icon
        
        # create pixmap for icon and set size and margin
        pixmap = icon.pixmap(48, 48)
        iconLabel.setPixmap(pixmap)
        iconLabel.setContentsMargins(15, 0, 15, 0)
        iconLabel.setAlignment(Qt.AlignCenter) #center the icon vertically

        # set the message
        messageLabel = QLabel('<p style="line-height: 0.8;">' + message + '</p>')
        messageLabel.setWordWrap(True) #ensure long messages wrap properly
        messageLabel.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter) #vertically center the text
        messageLabel.setContentsMargins(0, 0, 0, 10)
        messageLabel.setMinimumWidth(250)

        # makes the text selectable by the user only when we show the new password after reset password ended successfully
        if isSelectable:
            messageLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)

        # add the icon and message to the horizontal layout with spacing
        horizontalLayout.addWidget(iconLabel)
        horizontalLayout.addWidget(messageLabel)
        horizontalLayout.setAlignment(Qt.AlignCenter) #center the entire horizontalLayout

        # add stretchable space around the horizontalLayout to center it vertically in the dialog
        layout.addStretch(1) #add stretch before the content
        layout.addLayout(horizontalLayout)
        layout.addStretch(1) #add stretch after the content

        # create buttons layout
        buttonLayout = QHBoxLayout()
        buttonLayout.setAlignment(Qt.AlignCenter) #center the buttons

        # if question message box, we show "Yes" and "No" buttons
        if iconType == 'Question':
            yesButton = QPushButton('Yes')
            yesButton.setCursor(QCursor(Qt.PointingHandCursor))
            yesButton.clicked.connect(self.accept)
            noButton = QPushButton('No')
            noButton.setCursor(QCursor(Qt.PointingHandCursor))
            noButton.clicked.connect(self.reject)
            buttonLayout.addWidget(yesButton)
            buttonLayout.addSpacing(15)
            buttonLayout.addWidget(noButton)
        # else we show "OK" button
        else:
            okButton = QPushButton('OK')
            okButton.setCursor(QCursor(Qt.PointingHandCursor))
            okButton.clicked.connect(self.accept)
            buttonLayout.addWidget(okButton)

        # apply layout to the dialog
        layout.addLayout(buttonLayout)
        self.setLayout(layout)

        # set custom stylesheet
        self.setStyleSheet('''
            #customMessageBox {
                background-color: #f3f3f3;
            }
                        
            #customMessageBox QLabel {
                color: black;
                font-family: 'Cairo';
            }

            #customMessageBox QLabel[alignment='Qt::AlignVCenter|Qt::AlignLeft'] {
                margin-left: 10px;
            }
                        
            #customMessageBox QPushButton {
                background-color: #3a8e32;
                border: 1px solid black;
                border-radius: 10px;
                font-family: 'Cairo';
                font-size: 16px;
                font-weight: bold;
                color: #f3f3f3;
                min-width: 80px;
            }
                           
            #customMessageBox QPushButton:hover {
                background-color: #4d9946;
            }
                           
            #customMessageBox QPushButton:pressed {
                background-color: #2e7128;
            }
                        
            #customMessageBox QPushButton[text='No'] {
                background-color: #d84f4f;
                border: 1px solid black;
                border-radius: 10px;
                font-family: 'Cairo';
                font-size: 16px;
                font-weight: bold;      
                color: #f3f3f3;
                min-width: 80px;
            }
                           
            #customMessageBox QPushButton[text='No']:hover {
                background-color: #db6060;
            }
                           
            #customMessageBox QPushButton[text='No']:pressed {
                background-color: #ac3f3f;
            }
        ''')

        # set dialog properties non-resizable but sized to content
        self.setMinimumSize(350, 150) #set a reasonable minimum size
        self.adjustSize() #adjust the size based on content
        self.setFixedSize(self.size()) #lock the size to prevent resizing


    # method for overriting the original accept method and setting isMessageBox flag
    def accept(self):
        CustomMessageBox.isMessageBox = False
        super().accept()


    # method for overriting the original reject method and setting isMessageBox flag
    def reject(self):
        CustomMessageBox.isMessageBox = False
        super().reject()
    

    # method for mapping the iconType to the appropriate StandardPixmap icon
    def GetMessageBoxIcon(self, iconType):
        if iconType == 'Warning':
            return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning)
        elif iconType == 'Critical':
            return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxCritical)
        elif iconType == 'Question':
            return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxQuestion)
        return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)


# method for showing message box window
def ShowMessageBox(title, message, iconType='Information', isSelectable=False):
    # iconType options can be Information, Warning, Critical, Question
    if not CustomMessageBox.isMessageBox:
        messageBox = CustomMessageBox(title, message, iconType, isSelectable)

        # set isMessageBox and show message box
        CustomMessageBox.isMessageBox = True
        result = messageBox.exec()

        # return result value for question message box, else none
        return result == QDialog.Accepted if iconType == 'Question' else None

#------------------------------------------CUSTOM-MESSAGEBOX-END---------------------------------------------#

#---------------------------------------------ATTACK-PIE-CHART-----------------------------------------------#

# attack pie chart class for showing attacks distribution over time via a pie chart in GUI
class AttackPieChart():
    # dictionary for mapping attack names, key is the database name text and the value is a tuple with slice label, legend name, color
    pieChartLabelDict = {
        'ARP Spoofing': ('ARP', 'ARP Spoofing', QColor('#90cfef')),
        'Port Scan': ('Port Scan', 'Port Scanning', QColor('#209fdf')),
        'DoS': ('DoS', 'Denial of Service', QColor('#15668f')),
        'DNS Tunneling': ('DNS', 'DNS Tunneling', QColor('#092d40'))
    }

    # method for creating and initializing an empty attack pie chart
    def InitAttackPieChart(self):
        try:
            # create pie chart and pie chart series
            self.ui.pieChart = QChart()
            series = QPieSeries()
            self.ui.pieChart.addSeries(series)

            # create font for title
            titleFont = QFont('Cairo', 16, QFont.Bold, False) 

            # create a legend widget
            self.ui.legendWidget = QWidget()
            legendLayout = QGridLayout(self.ui.legendWidget)
            self.ui.legendWidget.setObjectName('legendWidget')

            # setup the base chart widget for pie chart
            self.ui.pieChart.legend().setVisible(False)
            self.ui.pieChart.layout().setContentsMargins(0, 0, 0, 0)
            self.ui.pieChart.setAnimationOptions(QChart.AllAnimations)
            self.ui.pieChart.setBackgroundRoundness(0)
            self.ui.pieChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#c1d0ef'))
            self.ui.pieChart.setTitle('No Data To Display...')
            self.ui.pieChart.setTitleFont(titleFont)

            # create chart view for pie chart
            self.ui.pieChartView = QChartView(self.ui.pieChart)
            self.ui.pieChartView.setRenderHint(QPainter.Antialiasing)
            self.ui.pieChartView.setMinimumSize(440, 260)

            # create vbox layout for pie chart
            VBoxLayout = QVBoxLayout()
            VBoxLayout.setSpacing(0)
            VBoxLayout.setContentsMargins(0, 0, 0, 0)

            # add stles to the title
            self.ui.pieChartTitleLabel = QLabel('Attacks Distribution')
            self.ui.pieChartTitleLabel.setObjectName('pieChartTitleLabel') 

            # setup the pie chart legends in advance
            for i, (sliceName, legendName, sliceColor) in enumerate(AttackPieChart.pieChartLabelDict.values()):
                # create font for legend labels
                legendFont = QFont('Cairo', 12, QFont.Bold, False)
                legendLabel = QLabel(f'{legendName} 0%')
                legendLabel.setFont(legendFont)
                legendLabel.setObjectName(f'{legendName.replace(' ', '')}LegendLabel') #for example: ARPSpoofingLegendLabel

                # create label for attack types color labels
                colorLabel = QLabel()
                colorLabel.setObjectName(f'{legendName.replace(' ', '')}LegendColorLabel')
                colorLabel.setStyleSheet(f'background-color: {sliceColor.name()}; border: 1px solid black;')
                colorLabel.setFixedSize(20, 20)

                row = i // 2
                col = (i % 2) * 2
                legendLayout.addWidget(colorLabel, row, col)
                legendLayout.addWidget(legendLabel, row, col + 1)

            # add items to the chart VBox
            VBoxLayout.addWidget(self.ui.pieChartTitleLabel)
            VBoxLayout.addWidget(self.ui.pieChartView)
            VBoxLayout.addWidget(self.ui.legendWidget)

            # save the chart object in ui for later use
            self.ui.chartVerticalFrame.setLayout(VBoxLayout)
            self.ui.chartVerticalFrame.update()

        except Exception as e:
            ShowMessageBox('Error In Pie Chart Initialization', 'Error occurred in pie chart initialization, try again later.', 'Critical')


# method for updating the pie chart after an attack was detected, expects an attack name like: ARP, DNS, Port Scan, DoS
def UpdatePieChartAfterAttack(self, attackType):
    try:
        # get slice labels and series for updating pie chart
        sliceLabel = AttackPieChart.pieChartLabelDict.get(attackType)[0]
        series = self.ui.pieChart.series()[0]

        # increment the value of the attack slice based on given attack name
        found = False
        for slice in series.slices():
            if sliceLabel in slice.label():  
                slice.setValue(slice.value() + 1)
                found = True
                break

        # if slice does not exist, then create a new slice and add it to the pie chart
        if not found:
            sliceFont = QFont('Cairo', 11, QFont.Bold, False)
            newSlice = series.append(sliceLabel, 1)
            newSlice.setLabelFont(sliceFont)
            newSlice.setLabelVisible(True)
            newSlice.setLabelArmLengthFactor(0.075)
            newSlice.setLabel(f'{sliceLabel} {newSlice.percentage()*100:.1f}%')
            newSlice.setLabelColor(QColor(45, 46, 54, 255) if self.userData.get('lightMode') == 0 else QColor(1, 1, 1, 255))
            newSlice.setColor(AttackPieChart.pieChartLabelDict.get(attackType)[2])
            setattr(self.ui, f'{''.join(attackType.split(' '))}PieChartSlice', newSlice) #add new slice to ui

        # set the title to be empty (hide the title) if there is at least one attack detection in history
        if series.count() > 0:
            self.ui.pieChart.setTitle('')
        
        # update the text data of legends and slice labels
        UpdatePieChartLegendsAndSlices(self)
        
        # update pieChartData dictionary in userData
        self.userData.get('pieChartData').setdefault(attackType, 0)
        self.userData['pieChartData'][attackType] += 1

    except Exception as e:
        ShowMessageBox('Error Updating Pie Chart', 'Error occurred while updating pie chart after attack, try again later.', 'Critical')


# method for updating the text of the pie chart legends and slice labels
def UpdatePieChartLegendsAndSlices(self):
    try:
        # creating a new dict with legend names like: sliceName: legendName
        pieChartAttackNames = {pieChartValues[0] : pieChartValues[1] for pieChartValues in AttackPieChart.pieChartLabelDict.values()}
        
        # update the legend and slice text for all slices
        for slice in self.ui.pieChart.series()[0].slices():
            # update the slice text with correct values
            sliceSplit = slice.label().split(' ')
            sliceAttackName = ' '.join([sliceSplit[0], sliceSplit[1]]) if 'Port' in sliceSplit[0] else sliceSplit[0]
            slice.setLabel(f'{sliceAttackName} {slice.percentage()*100:.1f}%')

            # update the legend text to match current slice
            legendLabelText = f'{pieChartAttackNames.get(sliceAttackName)} {slice.percentage()*100:.1f}%'
            legendLabelName = f'{pieChartAttackNames.get(sliceAttackName).replace(' ', '')}LegendLabel' 
            legendLabelObject = self.findChild(QLabel, legendLabelName)
            legendLabelObject.setText(legendLabelText)

    except Exception as e:
        ShowMessageBox('Error Updating Pie Chart Legends', 'Error occurred while updating pie chart legends, try again later.', 'Critical')


# method for updating the pie chart after user login with data from database
def UpdatePieChartAfterLogin(self, pieChartData):
    try:
        # check if there's at least one attack in pieChartData dictionary
        if any(attackCount > 0 for attackCount in pieChartData.values()):
            # remove current series from pie chart if exists
            if self.ui.pieChart.series():
                self.ui.pieChart.removeSeries(self.ui.pieChart.series()[0])

            # create a new series for pie chart with database data
            newSeries = QPieSeries()
            for attackType, attackCount in pieChartData.items():
                # check if attack count is greater then zero
                if attackCount > 0:
                    # add new slice for attack and update the css of the slice label
                    sliceFont = QFont('Cairo', 11, QFont.Bold, False)
                    newSlice = newSeries.append(AttackPieChart.pieChartLabelDict.get(attackType)[0], attackCount)
                    newSlice.setLabelFont(sliceFont)
                    newSlice.setLabelVisible(True)
                    newSlice.setLabelArmLengthFactor(0.075)
                    newSlice.setLabelColor(QColor(45, 46, 54, 255) if self.userData.get('lightMode') == 0 else QColor(1, 1, 1, 255))
                    newSlice.setColor(AttackPieChart.pieChartLabelDict.get(attackType)[2])
                    setattr(self.ui, f'{''.join(attackType.split(' '))}PieChartSlice', newSlice) #add new slice to ui

            # add the new series to the chart and update the GUI
            self.ui.pieChart.addSeries(newSeries)
            self.ui.pieChart.setTitle('') #remove the default title if exists
            UpdatePieChartLegendsAndSlices(self)

    except Exception as e:
        ShowMessageBox('Error Updating Pie Chart', 'Error occurred while updating pie chart after login, try again later.', 'Critical')


# method for updating pie chart color mode based on chosen color mode in ui
def UpdatePieChartColorMode(self):
    try:
        # set our desired label color based on ui color mode
        labelColor = QColor(45, 46, 54, 255) if self.userData.get('lightMode') == 0 else QColor(1, 1, 1, 255)

        # set the background color for the pie chart
        if hasattr(self.ui, 'pieChart') and self.ui.pieChart:
            self.ui.pieChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#c1d0ef'))

        # set the label color for pie chart slices
        for attackType in AttackPieChart.pieChartLabelDict:
            # check if attack name label has a slice, if so set its label color
            pieChartSlice = getattr(self.ui, f'{''.join(attackType.split(' '))}PieChartSlice', None)
            # if not none we apply color label
            if pieChartSlice:
                pieChartSlice.setLabelColor(labelColor)

    except Exception as e:
        ShowMessageBox('Error Updating Pie Chart Color Mode', 'Error occurred while updating pie chart color mode, try again later.', 'Critical')


# method for clearing the pie chart and resetting to default empty pie chart
def ResetPieChartToDefault(self):
    try:
        # clear the pie chart data and set the default title
        self.ui.pieChart.series()[0].clear()
        self.ui.pieChart.setTitle('No Data To Display...')

        # update the legend text and set it to the default values of 0%
        for attackType, sliceLegendNames in AttackPieChart.pieChartLabelDict.items():
            legendLabelText = f'{sliceLegendNames[1]} 0%'
            legendLabelName = f'{sliceLegendNames[1].replace(' ', '')}LegendLabel' 
            legendLabelObject = self.findChild(QLabel, legendLabelName)
            legendLabelObject.setText(legendLabelText)

            # check if slice is present in ui, if so we delete it
            if hasattr(self.ui, f'{''.join(attackType.split(' '))}PieChartSlice'):
                delattr(self.ui, f'{''.join(attackType.split(' '))}PieChartSlice')

    except Exception as e:
        ShowMessageBox('Error Clearing Pie Chart', 'Error occurred while clearing pie chart, try again later.', 'Critical')

#------------------------------------------ATTACK-PIE-CHART-END----------------------------------------------#

#---------------------------------------------HISTOGRAM-CHART------------------------------------------------#

# class for initializing the Histogram on the Analytics page
class AnalyticsHistogramChart():
    # define our attack types and their colors and the months of the year to show in the chart
    histogramChartAttackTypes = [attackType for attackType in AttackPieChart.pieChartLabelDict]
    histogramChartAttackColors = [color[2] for color in AttackPieChart.pieChartLabelDict.values()]
    histogramChartMonths = ['January', 'February', 'March', 'April', 'May', 'June', 
                                'July', 'August', 'September', 'October', 'November', 'December']

    # method for initializing the histogram chart
    def InitAnalyticsHistogramChart(self):
        try:
            # create the chart object and set fonts and colors
            self.ui.histogramChart = QChart()
            self.ui.histogramChart.legend().setVisible(True)
            self.ui.histogramChart.legend().setFont(QFont('Cairo', 9, QFont.Bold))
            self.ui.histogramChart.legend().setContentsMargins(0, 0, 0, 0)
            self.ui.histogramChart.legend().layout().setContentsMargins(0, 0, 0, 0)
            self.ui.histogramChart.legend().setBackgroundVisible(False)
            self.ui.histogramChart.legend().setAlignment(Qt.AlignTop)
            self.ui.histogramChart.legend().setLabelColor(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
            self.ui.histogramChart.layout().setContentsMargins(0, 0, 0, 0)
            self.ui.histogramChart.setMargins(QMargins(0, 0, 0, 0))
            self.ui.histogramChart.setBackgroundRoundness(0)
            self.ui.histogramChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#ebeff7'))
            self.ui.histogramChart.setTitle('No Data To Display...')
            self.ui.histogramChart.setTitleFont(QFont('Cairo', 18, QFont.Bold, False))
            self.ui.histogramChart.setTitleBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
            self.ui.histogramChart.setAnimationOptions(QChart.SeriesAnimations)

            # create a separate QLabel for the title (will be visible when there is no data to display)
            self.ui.histogramChartTitleLabel = QLabel('No Data To Display...')
            self.ui.histogramChartTitleLabel.setAlignment(Qt.AlignCenter)
            self.ui.histogramChartTitleLabel.setFont(QFont('Cairo', 18, QFont.Bold))
            self.ui.histogramChartTitleLabel.setObjectName('histogramChartTitleLabel')
            self.ui.histogramChartTitleLabel.setAlignment(Qt.AlignHCenter)  # Start centered
            self.ui.histogramChartTitleLabel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

            # create the chartView object
            self.ui.histogramChartView = QChartView(self.ui.histogramChart)
            self.ui.histogramChartView.setRenderHint(QPainter.Antialiasing)

            # create a VBoxLayout that the histogram chart and title will sit in
            VBoxLayout = QVBoxLayout()
            VBoxLayout.setSpacing(0)
            VBoxLayout.setContentsMargins(6, 6, 6, 6)
            VBoxLayout.addWidget(self.ui.histogramChartTitleLabel) #adding title
            VBoxLayout.addWidget(self.ui.histogramChartView) #adding histogram chart

            # add the VBoxLayout to the ui frame
            self.ui.histogramChartVerticalFrame.setLayout(VBoxLayout)
            self.ui.histogramChartVerticalFrame.update()

            # hide the chart and show the title
            self.ui.histogramChartTitleLabel.show()
            self.ui.histogramChartView.hide()

        except Exception as e:
            ShowMessageBox('Error In Histogram Chart Initialization', 'Error occurred in histogram chart initialization, try again later.', 'Critical')


    # method for showing a tooltip on each bar of the histogram chart when the user hovers it with the mouse
    def ShowTooltip(self, state, index, barSet):
        if state:
            # get class name, value and month and show tooltip text
            attackType = barSet.label()
            value = barSet.at(index) 
            month = AnalyticsHistogramChart.histogramChartMonths[index] 
            QToolTip.showText(QCursor.pos(), f'Attack: {attackType}\nCount: {int(value)}\nMonth: {month}', self)


# method for updating the grid lines and ticks based on the given maximum value in histogram chart
def UpdateHistogramChartLines(self, newValue):
    try:
        # set desired lines to be five lines for fixed uniform look
        desiredLines = 5 #set to five lines in total
        intervals = desiredLines - 1 #set intervals based on number of lines

        # use ceiling division to get the smallest step that will cover newValue
        step = ((newValue + 2) + (intervals - 1)) // intervals
        adjustedMax = step * intervals

        # set the tick interval for histogram Y-axis
        self.ui.histogramAxisY.setRange(0, adjustedMax)
        self.ui.histogramAxisY.setTickInterval(step)
        self.ui.histogramAxisY.setTickCount(desiredLines)

    except Exception as e:
        ShowMessageBox('Error Updating Histogram Chart Lines', 'Error occurred while updating histogram chart lines, try again later.', 'Critical')


# method for creating the histogram chart data, axies and bars using the diven data dict, if data dict is None then create an empty histogram chart
def CreateHistogramChartData(self, histogramChartData=None):
    try:
        # get valid months based on the current month and get selected year from year combobox
        yearComboboxSelection = self.ui.analyticsYearComboBox.currentText()
        validMonths = AnalyticsHistogramChart.histogramChartMonths

        # check if year combobox is set to current year, if so we update the histogram chart months based on valid months
        if yearComboboxSelection == str(datetime.now().year):
            currentMonth = datetime.now().month #get current month
            validMonths = AnalyticsHistogramChart.histogramChartMonths[:currentMonth] #get all the valid months from January untill current month

        # hide the title and show the chart
        self.ui.histogramChart.setTitle(f'Monthly Network Attacks For Year {yearComboboxSelection}')
        self.ui.histogramChartTitleLabel.hide()
        self.ui.histogramChartView.show()
        self.ui.histogramChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#ebeff7'))

        # create histogram bar series
        histogramBarSeries = QBarSeries()
        histogramMonthsLength = len(AnalyticsHistogramChart.histogramChartMonths)

        # iterate over each class name in our histogram attack types
        for i, attackType in enumerate(AnalyticsHistogramChart.histogramChartAttackTypes):
            # define bar set and set bar set color
            barSet = QBarSet(attackType)
            barSet.setColor(AnalyticsHistogramChart.histogramChartAttackColors[i]) #set predefined color
            barSet.setPen(QPen(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'), 1))
            setattr(self.ui, f'{''.join(attackType.split(' '))}HistogramChartBarSet', barSet) #add new bar set to ui

            # connect hovered signal to custom slot
            barSet.hovered.connect(lambda state, index, barSet=barSet: AnalyticsHistogramChart.ShowTooltip(self, state, index, barSet))

            # check if there is data to add to the chart, if not then the chart will be empty
            if histogramChartData and yearComboboxSelection in histogramChartData:
                # iterate over all months in the histogramChartData dictionary
                for month in histogramChartData.get(yearComboboxSelection):
                    barSet.append(histogramChartData.get(yearComboboxSelection).get(month).get(attackType, 0)) #append attack counter value
            else:
                # insert bar set values list with zeros to initialize empty histogram chart
                barSetValues = [0] * histogramMonthsLength #list for appending zero values to chart
                barSet.append(barSetValues) #append zero values to chart

            # append bar set into our histogram bar series
            histogramBarSeries.append(barSet)

         # add histogram bar series to histogram chart
        self.ui.histogramChart.addSeries(histogramBarSeries)

        # create X-axis months
        self.ui.histogramAxisX = QBarCategoryAxis()
        self.ui.histogramAxisX.append(validMonths)
        self.ui.histogramAxisX.setTitleText('Month')
        self.ui.histogramAxisX.setTitleBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.histogramAxisX.setLabelsFont(QFont('Cairo', 9, QFont.Bold, True))
        self.ui.histogramAxisX.setLabelsBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.histogramAxisX.setTitleFont(QFont('Cairo', 12, QFont.Bold, False))
        self.ui.histogramAxisX.setGridLineColor(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.histogramAxisX.setLinePen(QPen(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'), 1))
        self.ui.histogramChart.addAxis(self.ui.histogramAxisX, Qt.AlignBottom)
        self.ui.histogramChart.series()[0].attachAxis(self.ui.histogramAxisX)

        # create Y-axis values
        self.ui.histogramAxisY = QValueAxis()
        self.ui.histogramAxisY.setTitleText('Number of Attacks')
        self.ui.histogramAxisY.setTitleBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.histogramAxisY.setLabelsFont(QFont('Cairo', 9, QFont.Bold, False))
        self.ui.histogramAxisY.setLabelsBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.histogramAxisY.setTitleFont(QFont('Cairo', 11, QFont.Bold, False))
        self.ui.histogramAxisY.setGridLineColor(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.histogramAxisY.setLinePen(QPen(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'), 1))
        self.ui.histogramAxisY.setTickInterval(1)
        self.ui.histogramAxisY.setLabelFormat('%d') #integer labels
        self.ui.histogramChart.addAxis(self.ui.histogramAxisY, Qt.AlignLeft)
        self.ui.histogramChart.series()[0].attachAxis(self.ui.histogramAxisY)

        # update histogram chart lines based on max value in axis
        UpdateHistogramChartLines(self, self.ui.histogramAxisY.max())

        # remove the old axis from chart and add the adjusted axies to the chart
        if self.ui.histogramAxisY:
            self.ui.histogramChart.series()[0].detachAxis(self.ui.histogramAxisY)
            self.ui.histogramChart.removeAxis(self.ui.histogramAxisY)
        self.ui.histogramChart.addAxis(self.ui.histogramAxisY, Qt.AlignLeft)
        self.ui.histogramChart.series()[0].attachAxis(self.ui.histogramAxisY)
        self.ui.histogramChartVerticalFrame.update()

    except Exception as e:
        ShowMessageBox('Error Creating Histogram Chart', 'Error occurred while creating histogram chart with given data, try again later.', 'Critical')


# method for updating the histogram chart after an attack was detected, expects an attack name like in database: 'ARP Spoofing', 'Port Scan', etc.
def UpdateHistogramChartAfterAttack(self, attackType):
    try:
        # get selected year from year combobox
        yearComboboxSelection = self.ui.analyticsYearComboBox.currentText()

        # updating the histogram chart if the user year selection is the current year
        if yearComboboxSelection == str(datetime.now().year):
            currentMonth = datetime.now().month #get current month

            # checking in there is any histogram chart data already or not, if not then we need to create the data
            if not self.ui.histogramChart.series():
                CreateHistogramChartData(self)

            # check if we got into a new month, if so we rebuild the X-axis month labels
            if currentMonth > self.ui.histogramAxisX.count():
                # get the updated valid months based on current month and update our month labels with new month
                validMonths = AnalyticsHistogramChart.histogramChartMonths[:currentMonth]
                self.ui.histogramAxisX.clear()
                self.ui.histogramAxisX.append(validMonths)
                self.ui.histogramChart.series()[0].attachAxis(self.ui.histogramAxisX)

            # updating the histogram data for the given attack type in the current month index
            barSet =  self.ui.histogramChart.series()[0].barSets()[AnalyticsHistogramChart.histogramChartAttackTypes.index(attackType)]
            monthIndex = currentMonth - 1
            newValue = barSet.at(monthIndex) + 1
            barSet.replace(monthIndex, newValue)

            # check if we need to update the Y-axis range, need to update if the new value is equal or larger than the max value
            if newValue >= self.ui.histogramAxisY.max():
                # detach the series from the chart and axes
                self.ui.histogramChart.series()[0].detachAxis(self.ui.histogramAxisY)
                self.ui.histogramChart.series()[0].detachAxis(self.ui.histogramAxisX)
                self.ui.histogramChart.removeAxis(self.ui.histogramAxisY)

                # create a new Y-axis
                self.ui.histogramAxisY = QValueAxis()
                self.ui.histogramAxisY.setTitleText('Number of Attacks')
                self.ui.histogramAxisY.setTitleBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
                self.ui.histogramAxisY.setLabelsFont(QFont('Cairo', 9, QFont.Bold, False))
                self.ui.histogramAxisY.setLabelsBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
                self.ui.histogramAxisY.setTitleFont(QFont('Cairo', 11, QFont.Bold, False))
                self.ui.histogramAxisY.setGridLineColor(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
                self.ui.histogramAxisY.setLinePen(QPen(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'), 1))
                self.ui.histogramAxisY.setLabelFormat('%d') #integer labels

                # update histogram chart lines based on new value
                UpdateHistogramChartLines(self, newValue)

                # attach the new axis and series back to the chart
                self.ui.histogramChart.addAxis(self.ui.histogramAxisY, Qt.AlignLeft)
                self.ui.histogramChart.series()[0].attachAxis(self.ui.histogramAxisX)
                self.ui.histogramChart.series()[0].attachAxis(self.ui.histogramAxisY)

            self.ui.histogramChartVerticalFrame.update() #ensure the chart updates

        # update histogramChartData dictionary in userData
        self.userData.get('analyticsChartData').get('histogramChartData').get(yearComboboxSelection).get(datetime.now().month).setdefault(attackType, 0)
        self.userData['analyticsChartData']['histogramChartData'][yearComboboxSelection][datetime.now().month][attackType] += 1

    except Exception as e:
        ShowMessageBox('Error Updating Histogram Chart', 'Error occurred while updating histogram chart after attack, try again later.', 'Critical')


# method for updating the histogram chart after user login with data from database
def UpdateHistogramChartAfterLogin(self, histogramChartData):
    try:
        # check if there's at least one attack in histogramChartData dictionary
        if any(attackCount > 0 for yearData in histogramChartData.values() for monthData in yearData.values() for attackCount in monthData.values()):
            CreateHistogramChartData(self, histogramChartData)
        else:
            ResetHistogramChartToDefault(self)

    except Exception as e:
        ShowMessageBox('Error Updating Histogram Chart', 'Error occurred while updating histogram chart after login, try again later.', 'Critical')


# method for updating histogram chart color mode based on chosen color mode in ui
def UpdateHistogramChartColorMode(self):
    try:
        # set our desired label color based on ui color mode
        labelColor = QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519')

        # set the background color for the histogram chart
        if hasattr(self.ui, 'histogramChart') and self.ui.histogramChart:
            self.ui.histogramChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#ebeff7'))
            self.ui.histogramChart.legend().setLabelColor(labelColor)
            self.ui.histogramChart.setTitleBrush(labelColor)

        # set the background color for the histogram chart X-axis
        if hasattr(self.ui, 'histogramAxisX') and self.ui.histogramAxisX:
            self.ui.histogramAxisX.setTitleBrush(labelColor)
            self.ui.histogramAxisX.setLabelsBrush(labelColor)
            self.ui.histogramAxisX.setGridLineColor(labelColor)
            self.ui.histogramAxisX.setLinePen(QPen(labelColor, 1))

        # set the background color for the histogram chart Y-axis
        if hasattr(self.ui, 'histogramAxisY') and self.ui.histogramAxisY:
            self.ui.histogramAxisY.setTitleBrush(labelColor)
            self.ui.histogramAxisY.setLabelsBrush(labelColor)
            self.ui.histogramAxisY.setGridLineColor(labelColor)
            self.ui.histogramAxisY.setLinePen(QPen(labelColor))

        # set the border color for the histogram chart bar sets
        for attackType in AnalyticsHistogramChart.histogramChartAttackTypes:
            # check if class name label has a bar set, if so set its border color
            histogramChartBarSet = getattr(self.ui, f'{''.join(attackType.split(' '))}HistogramChartBarSet', None)
            # if not none we apply border color
            if histogramChartBarSet:
                histogramChartBarSet.setPen(QPen(labelColor, 1))

    except Exception as e:
        ShowMessageBox('Error Updating Histogram Chart Color Mode', 'Error occurred while updating histogram chart color mode, try again later.', 'Critical')


# method for clearing the histogram chart and resetting to default empty histogram chart
def ResetHistogramChartToDefault(self, hideChart=True):
    try:
        # clear the histogram chart data and set the default title
        for series in self.ui.histogramChart.series():
            self.ui.histogramChart.removeSeries(series)

        # clear all axes and grid lines and reset the title
        for axis in self.ui.histogramChart.axes():
            self.ui.histogramChart.removeAxis(axis)

        # clear all histogram chart bar sets in ui if exists
        for attackType in AnalyticsHistogramChart.histogramChartAttackTypes:
            # check if bar set is present in ui, if so we delete it
            if hasattr(self.ui, f'{''.join(attackType.split(' '))}HistogramChartBarSet'):
                delattr(self.ui, f'{''.join(attackType.split(' '))}HistogramChartBarSet')

        # clear histogram chart X-axis if exists
        if hasattr(self.ui, 'histogramAxisX'):
            delattr(self.ui, 'histogramAxisX')

        # clear histogram chart Y-axis if exists
        if hasattr(self.ui, 'histogramAxisY'):
            delattr(self.ui, 'histogramAxisY')

        # hide the chart and show the title
        if hideChart:
            self.ui.histogramChartTitleLabel.setText('No Data To Display...')
            self.ui.histogramChartTitleLabel.show()
            self.ui.histogramChartView.hide()

        # validate that the background color matches the current users preference
        self.ui.histogramChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#ebeff7'))

    except Exception as e:
        ShowMessageBox('Error Clearing Histogram Chart', 'Error occurred while clearing histogram chart, try again later.', 'Critical')

#-------------------------------------------HISTOGRAM-CHART-END----------------------------------------------#

#-------------------------------------------HORIZONTAL-BAR-CHART---------------------------------------------#

# class for initializing the horizontal bar chart on the Analytics page
class AnalyticsBarChart():
    # define our attack types and their colors to show in the bar chart
    barChartAttackTypes = [attackType for attackType in AttackPieChart.pieChartLabelDict]
    barChartAttackColors = [color[2] for color in AttackPieChart.pieChartLabelDict.values()]

    # method for initializing the hhorizontal bar chart
    def InitAnalyticsBarChart(self):
        try:
            # create the chart object and set fonts and colors
            self.ui.barChart = QChart()
            self.ui.barChart.legend().setVisible(True)
            self.ui.barChart.legend().setFont(QFont('Cairo', 9, QFont.Bold))
            self.ui.barChart.legend().setContentsMargins(0, 0, 0, 0)
            self.ui.barChart.legend().layout().setContentsMargins(0, 0, 0, 0)
            self.ui.barChart.legend().setBackgroundVisible(False)
            self.ui.barChart.legend().setAlignment(Qt.AlignTop)
            self.ui.barChart.legend().setLabelColor(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
            self.ui.barChart.layout().setContentsMargins(0, 0, 0, 0)
            self.ui.barChart.setMargins(QMargins(0, 0, 0, 0))
            self.ui.barChart.setBackgroundRoundness(0)
            self.ui.barChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#ebeff7'))
            self.ui.barChart.setTitle('No Data To Display...')
            self.ui.barChart.setTitleFont(QFont('Cairo', 18, QFont.Bold, False))
            self.ui.barChart.setTitleBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
            self.ui.barChart.setAnimationOptions(QChart.SeriesAnimations)

            # create a separate QLabel for the title (will be visible when there is no data to display)
            self.ui.barChartTitleLabel = QLabel('No Data To Display...')
            self.ui.barChartTitleLabel.setAlignment(Qt.AlignCenter)
            self.ui.barChartTitleLabel.setFont(QFont('Cairo', 18, QFont.Bold))
            self.ui.barChartTitleLabel.setObjectName('barChartTitleLabel')
            self.ui.barChartTitleLabel.setAlignment(Qt.AlignHCenter)  # Start centered
            self.ui.barChartTitleLabel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

            # create the chartView object
            self.ui.barChartView  = QChartView(self.ui.barChart)
            self.ui.barChartView.setRenderHint(QPainter.Antialiasing)

            # create a VBoxLayout that the bar chart and title will sit in
            VBoxLayout = QVBoxLayout()
            VBoxLayout.setSpacing(0)
            VBoxLayout.setContentsMargins(6, 6, 6, 6)
            VBoxLayout.addWidget(self.ui.barChartTitleLabel) #adding title
            VBoxLayout.addWidget(self.ui.barChartView) #adding bar chart
            
            # add the VBoxLayout to the ui frame
            self.ui.barChartVerticalFrame.setLayout(VBoxLayout)
            self.ui.barChartVerticalFrame.update()

            # hide the chart and show the title
            self.ui.barChartTitleLabel.show()
            self.ui.barChartView.hide()

        except Exception as e:
            ShowMessageBox('Error In Bar Chart Initialization', 'Error occurred in bar chart initialization, try again later.', 'Critical')


    # method for showing a tooltip on each bar of the bar chart when the user hovers it with the mouse
    def ShowTooltip(self, state, index, barSet):
        if state:
            # get class name and value and show tooltip text
            attackType = barSet.label()
            value = barSet.at(index) 
            QToolTip.showText(QCursor.pos(), f'Attack: {attackType}\nCount: {int(value)}', self)


# method for updating the grid lines and ticks based on the given maximum value in bar chart
def UpdateBarChartLines(self, newValue):
    try:
        # set desired lines to be five lines for fixed uniform look
        desiredLines = 5 #set to five lines in total
        intervals = desiredLines - 1 #set intervals based on number of lines

        # use ceiling division to get the smallest step that will cover newValue
        step = ((newValue + 2) + (intervals - 1)) // intervals
        adjustedMax = step * intervals

        # set the tick interval for bar chart X-axis
        self.ui.barChartAxisX.setRange(0, adjustedMax)
        self.ui.barChartAxisX.setTickInterval(step)
        self.ui.barChartAxisX.setTickCount(desiredLines)

    except Exception as e:
        ShowMessageBox('Error Updating Bar Chart Lines', 'Error occurred while updating bar chart lines, try again later.', 'Critical')


# method for creating the bar chart data, axies and bars using the diven data dict, if data dict is None then create an empty bar chart
def CreateBarChartData(self, barChartData=None):
    try:
        # get selected year from year combobox
        yearComboboxSelection = self.ui.analyticsYearComboBox.currentText()

        # hide the title and show the chart
        self.ui.barChart.setTitle(f'Network Attacks For Year {yearComboboxSelection}')
        self.ui.barChartTitleLabel.hide()
        self.ui.barChartView.show()
        self.ui.barChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#ebeff7'))

        # create horizontal stacked bar series
        barChartBarSeries = QHorizontalStackedBarSeries()
        barChartAttackTypesLength = len(AnalyticsBarChart.barChartAttackTypes)

        # iterate over each class name in our bar chart attack types
        for i, attackType in enumerate(AnalyticsBarChart.barChartAttackTypes):
            # define bar set and bar set values list and set bar set color
            barSet = QBarSet(attackType)
            barSetValues = [0] * barChartAttackTypesLength #list for appending values in right position in chart
            barSet.setColor(AnalyticsBarChart.barChartAttackColors[i]) #set predefined color
            barSet.setPen(QPen(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'), 1))
            setattr(self.ui, f'{''.join(attackType.split(' '))}BarChartBarSet', barSet) #add new bar set to ui

            # connect hovered signal to custom slot
            barSet.hovered.connect(lambda state, index, barSet=barSet: AnalyticsBarChart.ShowTooltip(self, state, index, barSet))

            # check if there is data to add to the chart, if not then the chart will be empty
            if barChartData and yearComboboxSelection in barChartData:
                barSetValues[i] = barChartData[yearComboboxSelection].get(attackType, 0) #append attack counter value

            # insert bar set values list based on value given if bar chart data is set else with zeros to initialize empty bar chart
            barSet.append(barSetValues)

            # append bar set into our bar chart bar series
            barChartBarSeries.append(barSet)

        # add bar chart bar series to bar chart
        self.ui.barChart.addSeries(barChartBarSeries)

        # create X-axis values
        self.ui.barChartAxisX = QValueAxis()
        self.ui.barChartAxisX.setTitleText('Number of Attacks')
        self.ui.barChartAxisX.setTitleBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.barChartAxisX.setLabelsFont(QFont('Cairo', 9, QFont.Bold, False))
        self.ui.barChartAxisX.setLabelsBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.barChartAxisX.setTitleFont(QFont('Cairo', 11, QFont.Bold, False))
        self.ui.barChartAxisX.setGridLineColor(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.barChartAxisX.setLinePen(QPen(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'), 1))
        self.ui.barChartAxisX.setTickInterval(1)
        self.ui.barChartAxisX.setLabelFormat('%d') #integer labels
        self.ui.barChart.addAxis(self.ui.barChartAxisX, Qt.AlignBottom)
        self.ui.barChart.series()[0].attachAxis(self.ui.barChartAxisX)

        # create Y-axis attack types
        self.ui.barChartAxisY = QBarCategoryAxis()
        self.ui.barChartAxisY.append(AnalyticsBarChart.barChartAttackTypes)
        self.ui.barChartAxisY.setTitleText('Attack Types')
        self.ui.barChartAxisY.setTitleBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.barChartAxisY.setLabelsFont(QFont('Cairo', 9, QFont.Bold, True))
        self.ui.barChartAxisY.setLabelsBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.barChartAxisY.setTitleFont(QFont('Cairo', 12, QFont.Bold, False))
        self.ui.barChartAxisY.setGridLineColor(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
        self.ui.barChartAxisY.setLinePen(QPen(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'), 1))
        self.ui.barChart.addAxis(self.ui.barChartAxisY, Qt.AlignLeft)
        self.ui.barChart.series()[0].attachAxis(self.ui.barChartAxisY)

        # update bar chart lines based on max value in axis
        UpdateBarChartLines(self, self.ui.barChartAxisX.max())

        # remove the old axis from chart and add the adjusted axies to the chart
        if self.ui.barChartAxisX:
            self.ui.barChart.series()[0].detachAxis(self.ui.barChartAxisX)
            self.ui.barChart.removeAxis(self.ui.barChartAxisX)
        self.ui.barChart.addAxis(self.ui.barChartAxisX, Qt.AlignBottom)
        self.ui.barChart.series()[0].attachAxis(self.ui.barChartAxisX)
        self.ui.barChartVerticalFrame.update()

    except Exception as e:
        ShowMessageBox('Error Creating Bar Chart', 'Error occurred while creating bar chart with given data, try again later.', 'Critical')


# method for updating the bar chart after an attack was detected, expects an attack name like in database: 'ARP Spoofing', 'Port Scan', etc.
def UpdateBarChartAfterAttack(self, attackType):
    try:
        # get selected year from year combobox
        yearComboboxSelection = self.ui.analyticsYearComboBox.currentText()

        # updating the bar chart if the user year selection is the current year
        if yearComboboxSelection == str(datetime.now().year):
            # checking in there is any bar chart data already or not, if not then we need to create the data
            if not self.ui.barChart.series():
                CreateBarChartData(self)

            # updating the bar data for the given attack type in the current attack index
            barSet = self.ui.barChart.series()[0].barSets()[AnalyticsBarChart.barChartAttackTypes.index(attackType)]
            attackIndex = AnalyticsBarChart.barChartAttackTypes.index(attackType)
            newValue = barSet.at(attackIndex) + 1
            barSet.replace(attackIndex, newValue)

            # check if we need to update the X-axis range, need to update if the new value is equal or larger than the max value
            if newValue >= self.ui.barChartAxisX.max():
                # detach the series from the chart and axes
                self.ui.barChart.series()[0].detachAxis(self.ui.barChartAxisY)
                self.ui.barChart.series()[0].detachAxis(self.ui.barChartAxisX)
                self.ui.barChart.removeAxis(self.ui.barChartAxisX)

                # create a new X-axis
                self.ui.barChartAxisX = QValueAxis()
                self.ui.barChartAxisX.setTitleText('Number of Attacks')
                self.ui.barChartAxisX.setTitleBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
                self.ui.barChartAxisX.setLabelsFont(QFont('Cairo', 9, QFont.Bold, False))
                self.ui.barChartAxisX.setLabelsBrush(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
                self.ui.barChartAxisX.setTitleFont(QFont('Cairo', 11, QFont.Bold, False))
                self.ui.barChartAxisX.setGridLineColor(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'))
                self.ui.barChartAxisX.setLinePen(QPen(QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519'), 1))
                self.ui.barChartAxisX.setLabelFormat('%d') #integer labels

                # update bar chart lines based on new value
                UpdateBarChartLines(self, newValue)

                # attach the new axis and series back to the chart
                self.ui.barChart.addAxis(self.ui.barChartAxisX, Qt.AlignBottom)
                self.ui.barChart.series()[0].attachAxis(self.ui.barChartAxisX)
                self.ui.barChart.series()[0].attachAxis(self.ui.barChartAxisY)

            self.ui.barChartVerticalFrame.update() #ensure the chart updates

        # update histogramChartData dictionary in userData
        self.userData.get('analyticsChartData').get('barChartData').get(yearComboboxSelection).setdefault(attackType, 0)
        self.userData['analyticsChartData']['barChartData'][yearComboboxSelection][attackType] += 1

    except Exception as e:
        ShowMessageBox('Error Updating Bar Chart', 'Error occurred while updating bar chart after attack, try again later.', 'Critical')


# method for updating the bar chart after user login with data from database
def UpdateBarChartAfterLogin(self, barChartData):
    try:
        # check if there's at least one attack in barChartData dictionary
        if any(attackCount > 0 for yearData in barChartData.values() for attackCount in yearData.values()):
            CreateBarChartData(self, barChartData)
        else:
            ResetBarChartToDefault(self)

    except Exception as e:
        ShowMessageBox('Error Updating Bar Chart', 'Error occurred while updating bar chart after login, try again later.', 'Critical')


# method for updating bar chart color mode based on chosen color mode in ui
def UpdateBarChartColorMode(self):
    try:
        # set our desired label color based on ui color mode
        labelColor = QColor('black') if self.userData.get('lightMode') == 0 else QColor('#151519')

        # set the background color for the bar chart
        if hasattr(self.ui, 'barChart') and self.ui.barChart:
            self.ui.barChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#ebeff7'))
            self.ui.barChart.legend().setLabelColor(labelColor)
            self.ui.barChart.setTitleBrush(labelColor)

        # set the background color for the bar chart X-axis
        if hasattr(self.ui, 'barChartAxisX') and self.ui.barChartAxisX:
            self.ui.barChartAxisX.setTitleBrush(labelColor)
            self.ui.barChartAxisX.setLabelsBrush(labelColor)
            self.ui.barChartAxisX.setGridLineColor(labelColor)
            self.ui.barChartAxisX.setLinePen(QPen(labelColor, 1))

        # set the background color for the bar chart Y-axis
        if hasattr(self.ui, 'barChartAxisY') and self.ui.barChartAxisY:
            self.ui.barChartAxisY.setTitleBrush(labelColor)
            self.ui.barChartAxisY.setLabelsBrush(labelColor)
            self.ui.barChartAxisY.setGridLineColor(labelColor)
            self.ui.barChartAxisY.setLinePen(QPen(labelColor, 1))

        # set the border color for the bar chart bar sets
        for attackType in AnalyticsBarChart.barChartAttackTypes:
            # check if class name label has a bar set, if so set its border color
            barChartBarSet = getattr(self.ui, f'{''.join(attackType.split(' '))}BarChartBarSet', None)
            # if not none we apply border color
            if barChartBarSet:
                barChartBarSet.setPen(QPen(labelColor, 1))

    except Exception as e:
        ShowMessageBox('Error Updating Bar Chart Color Mode', 'Error occurred while updating bar chart color mode, try again later.', 'Critical')


# method for clearing the bar chart and resetting to default empty bar chart
def ResetBarChartToDefault(self, hideChart=True):
    try:
        # clear the bar chart data and set the default title
        for series in self.ui.barChart.series():
            self.ui.barChart.removeSeries(series)

        # clear all axes and grid lines and reset the title
        for axis in self.ui.barChart.axes():
            self.ui.barChart.removeAxis(axis)

        # clear all bar chart bar sets in ui if exists
        for attackType in AnalyticsHistogramChart.histogramChartAttackTypes:
            # check if bar set is present in ui, if so we delete it
            if hasattr(self.ui, f'{''.join(attackType.split(' '))}BarChartBarSet'):
                delattr(self.ui, f'{''.join(attackType.split(' '))}BarChartBarSet')

        # clear bar chart X-axis if exists
        if hasattr(self.ui, 'barChartAxisX'):
            delattr(self.ui, 'barChartAxisX')
        
        # clear bar chart Y-axis if exists
        if hasattr(self.ui, 'barChartAxisY'):
            delattr(self.ui, 'barChartAxisY')

        # hide the chart and show the title
        if hideChart:
            self.ui.barChartTitleLabel.setText('No Data To Display...')
            self.ui.barChartTitleLabel.show()
            self.ui.barChartView.hide()

        # validate that the background color matches the current users preference
        self.ui.barChart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor('#ebeff7'))

    except Exception as e:
        ShowMessageBox('Error Clearing Bar Chart', 'Error occurred while clearing bar chart, try again later.', 'Critical')

#------------------------------------------HORIZONTAL-BAR-CHART-END------------------------------------------#

#---------------------------------------------ANALYTICS-CARDS------------------------------------------------#

# method for setting data into the cards section one by one
def SetDataIntoCards(self):
    try:
        currentYear = self.ui.analyticsYearComboBox.currentText()
        if any(attackCount > 0 for attackCount in self.userData.get('analyticsChartData').get('barChartData').get(currentYear).values()):
            # update attacks per month and total number of attacks
            totalNumberOfAttacks = sum(self.userData.get('analyticsChartData').get('barChartData').get(currentYear).values())
            self.ui.totalNumOfAttacksValueLabel.setText(str(totalNumberOfAttacks))
            self.ui.attacksPerMonthValueLabel.setText('{:.2f}'.format(totalNumberOfAttacks / 12))

            # update most popular attack
            mostPopularAttack = max(self.userData.get('analyticsChartData').get('barChartData').get(currentYear), key=self.userData.get('analyticsChartData').get('barChartData').get(currentYear).get)
            mostPopularAttack = '<br>'.join(mostPopularAttack.split()) if ' ' in mostPopularAttack else mostPopularAttack #to ensure that there wont be a crash in case of future attack names
            self.ui.mostPopularAttackValueLabel.setText(mostPopularAttack if 'DoS' not in mostPopularAttack else 'Denial of<br>Service') #ensuring that DoS is displayed as Denial of Service

            # update the font sizes after updating the value
            UpdateFontSizeInLabel(self, self.ui.totalNumOfAttacksValueLabel)
            UpdateFontSizeInLabel(self, self.ui.attacksPerMonthValueLabel)

    except Exception as e:
        ShowMessageBox('Error Setting Cards Data', 'Error occurred while setting data into analytics cards, try again later.', 'Critical')


# method for updating the data in the cards after an attack
def UpdateDataInCardsAfterAttack(self):
    try:
        # only updating the histogram chart if the user year selection is the current year, otherwise it will update when a user changes the combobox value
        yearComboboxSelection = self.ui.analyticsYearComboBox.currentText()
        if yearComboboxSelection == str(datetime.now().year):
            SetDataIntoCards(self)

    except Exception as e:
        ShowMessageBox('Error Updating Cards Data', 'Error occurred while updating analytics cards after attack, try again later.', 'Critical')


# method for resetting the data in the cards section to the default values
def ResertDataInCards(self):
    try:
        self.ui.totalNumOfAttacksValueLabel.setText('0')
        self.ui.attacksPerMonthValueLabel.setText('0')
        self.ui.mostPopularAttackValueLabel.setText('No<br>Data')
        self.ui.mostPopularAttackValueLabel.setStyleSheet(f'''
            margin: 10px;
            margin-top: 10px;
            background-color: transparent;
            color: {'black' if self.userData.get('lightMode') == 0 else '#151519'};
        ''')

    except Exception as e:
        ShowMessageBox('Error Resetting Cards Data', 'Error occurred while resetting data into analytics cards, try again later.', 'Critical')


# method for calculating and resizing the font for the labels in the cards based on the data in them 
def UpdateFontSizeInLabel(self, labelObject):
    try:
        # get the current text in the card and set a default value for font size
        currentLength = len(labelObject.text().replace('.', ''))
        fontSize = 10

        # find the font side and top margin based on the number of digits in the card
        match currentLength:
            case 1:
                fontSize = 60
            case 2:
                fontSize = 50
            case 3:
                fontSize = 40
            case 4:
                fontSize = 33
            case _:
                fontSize = 30

        # apply the styles to the object
        labelObject.setStyleSheet(f'''
            font-size: {fontSize}px;
            margin: 10px;
            background-color: transparent;
            color: {'black' if self.userData.get('lightMode') == 0 else '#151519'};
        ''')

    except Exception as e:
        ShowMessageBox('Error Updating Cards Font', 'Error occurred while updating font for analytics cards, try again later.', 'Critical')

#-------------------------------------------ANALYTICS-CARDS-END----------------------------------------------#

#--------------------------------------------TABLE-VIEW-FILTER-----------------------------------------------#

# Custom Table Model that will sit inside the TableView object in the report page and will contain all the relevant data and methods
class CustomTableModel(QAbstractTableModel):
    reportPreviewColumnHeaders = ['Interface', 'Attack Type', 'Source IP', 'Source MAC', 'Destination IP', 'Destination MAC', 'Protocol', 'Timestamp']
    alertListData = [] #represents our alerts list in table view

    # constructor of table model class
    def __init__(self, data=None, parent=None):
        super().__init__(parent)
        self.alertListData = data


    # overwrite inherited method to get number of rows
    def rowCount(self, parent=None):
        return len(self.alertListData) #get number of rows in the data


    # overwrite inherited method to get number of columns
    def columnCount(self, parent=None):
        return len(self.reportPreviewColumnHeaders) + 1 #get number of columns (includes osType)


    # overwrite inherited method to get data from a specific cell
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        # this will display the data in the table
        if role == Qt.DisplayRole:
            return str(self.alertListData[index.row()][index.column()]) #ensure data is a string

        # this will center-align the text
        elif role == Qt.TextAlignmentRole:
            return Qt.AlignCenter #ensure data is centered
        
        # this will show tooltip with column data
        elif role == Qt.ToolTipRole:
            return str(self.alertListData[index.row()][index.column()]) #ensure data is a string
        
        return None


    # overwrite inherited method to set the column names
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            if section < len(self.reportPreviewColumnHeaders):
                return self.reportPreviewColumnHeaders[section]
        return None
    
        
    # overwrite inherited method to set the data into the column
    def setData(self, index, value, role=Qt.EditRole):
        if role == Qt.EditRole:
            if index.isValid() and 0 <= index.row() < self.rowCount() and 0 <= index.column() < self.columnCount():
                self.alertListData[index.row()][index.column()] = value
                self.dataChanged.emit(index, index, [Qt.DisplayRole])
                return True
        return False


    # method to add row to report preview table at the first index in top row
    def AddRow(self, interface, attackType, srcIp, srcMac, dstIp, dstMac, protocol, osType, timestamp):
        # create new row to insert into report preview table at the first index in top row
        row = [interface, attackType, srcIp, srcMac, dstIp, dstMac, protocol, timestamp, osType]
        self.beginInsertRows(QModelIndex(), 0, 0) #begin insertion at top
        self.alertListData.insert(0, row)
        self.endInsertRows() #end insertion


    # method to add items to a given row by index to report preview table
    def SetRowItem(self, row, column, value):
        # set data at specific row and column
        index = self.index(row, column)
        self.setData(index, value)


    # method to clear out the data from the report preview table
    def ClearRows(self):
        self.beginResetModel() #begin reset model
        self.alertListData.clear() #clear the data list
        self.endResetModel() #end reset model


# Custom Proxy Model for filtering the TableView that is in the report page, this class will hold the filtering logic and methods
class CustomFilterProxyModel(QSortFilterProxyModel):
    # represents our  alertList columns of our table
    alertListColumns = [('interface', 0), ('attackType', 1), ('srcIp', 2), ('srcMac', 3), ('dstIp', 4),
                        ('dstMac', 5), ('protocol', 6), ('osType', 8), ('timestamp', 7)]
    selectedAttacks = set() #represents selected attacks by checkboxes
    timeFilter = None #represents time combobox filther option

    # constructor of filter proxy model class
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selectedAttacks = {'ARP Spoofing', 'Port Scan', 'DoS', 'DNS Tunneling'} #set to all attack types by default
        self.timeFilter = 'All Available Data' #set to all available data by default


    # method to update selected types and refresh filter (for checkboxes)
    def SetSelectedAttacks(self, selectedAttacks):
        self.selectedAttacks = set(selectedAttacks)
        self.invalidateFilter() #triggers re-filtering


    # method to update time filter and refresh the table (for combobox)
    def SetTimeFilter(self, timeFilter):
        self.timeFilter = timeFilter
        self.invalidateFilter() #triggers re-filtering


    # overwrite inherited method that determines if a row should be shown based on filter conditions
    def filterAcceptsRow(self, sourceRow, sourceParent):
        model = self.sourceModel()

        # get timestamp and attack type row data
        timestampValue = model.data(model.index(sourceRow, 7), Qt.DisplayRole) #column 7 is Timestamp
        attackTypeValue = model.data(model.index(sourceRow, 1), Qt.DisplayRole) #column 1 is Attack Type

        # convert timestamp string to datetime object and get current time to check the filter
        rowTimestamp = datetime.strptime(timestampValue, '%H:%M:%S %d/%m/%y')
        currentTime = datetime.now()

        # time filtering logic, if the combobox is selected with 'All Available Data' then it will skip the time filter
        if self.timeFilter == 'Last Day' and rowTimestamp < currentTime - timedelta(days=1):
            return False
        elif self.timeFilter == 'Last Week' and rowTimestamp < currentTime - timedelta(days=7):
            return False
        elif self.timeFilter == 'Last Month' and rowTimestamp < currentTime - timedelta(days=30):
            return False
        elif self.timeFilter == 'Last Year' and rowTimestamp < currentTime - timedelta(days=365):
            return False

        # attack filtering logic by attack checkboxes
        if not self.selectedAttacks or attackTypeValue not in self.selectedAttacks:
            return False #dont show the row if it did not pass one of the filters

        return True #show current row if it passed all filters


# method that will be called when the user clicks on one of the attack checkboxes in the report page (ARP, Port, DoS, DNS)
def ReportCheckboxToggled(self):
    selectedAttacks = set() #represents a set of all selected attack checkboxes at this point in time

    # checking each checkbox if its clicked or not
    if self.ui.arpSpoofingCheckBox.isChecked():
        selectedAttacks.add('ARP Spoofing')
    if self.ui.portScanningCheckBox.isChecked():
        selectedAttacks.add('Port Scan')
    if self.ui.denialOfServiceCheckBox.isChecked():
        selectedAttacks.add('DoS')
    if self.ui.dnsTunnelingCheckBox.isChecked():
        selectedAttacks.add('DNS Tunneling')

    # passing the selected attacks set to a method that will filter the table view with the current selection of attacks
    self.ui.proxyReportPreviewTableModel.SetSelectedAttacks(selectedAttacks)


# method that will be called when the user selects a different time fillter option in the report page (combobox)
def ReportDurationComboboxChanged(self):
    self.ui.proxyReportPreviewTableModel.SetTimeFilter(self.ui.reportDurationComboBox.currentText())


# method for getting flitered alert list from proxy model
def GetFilteredAlerts(self):
    filteredAlertList = [] #represents our filtered alerts
    
    # iterate over each filtered row from the proxy model
    for row in range(self.ui.proxyReportPreviewTableModel.rowCount()):
        alert = {} #represents our current alert in row

        # iterate over each iltered column from the proxy model
        for header, col in self.ui.proxyReportPreviewTableModel.alertListColumns:
            # get the index from the proxy model
            index = self.ui.proxyReportPreviewTableModel.index(row, col)
            alert[header] = self.ui.proxyReportPreviewTableModel.data(index, Qt.DisplayRole)
        filteredAlertList.append(alert)

    return filteredAlertList


# method for initializing the table view in the report page when the application loads up
def InitReportTableView(self):
    # initialize the report preview table model and custom proxy model for filtering 
    self.ui.reportPreviewTableModel = CustomTableModel(self.userData.get('alertList'))
    self.ui.proxyReportPreviewTableModel = CustomFilterProxyModel()
    self.ui.proxyReportPreviewTableModel.setSourceModel(self.ui.reportPreviewTableModel)

    # set the table attributes for our preffered view in gui
    self.ui.reportPreviewTableView.setModel(self.ui.proxyReportPreviewTableModel)
    self.ui.reportPreviewTableView.setColumnHidden(self.ui.reportPreviewTableModel.columnCount() - 1, True) #hide osType column
    self.ui.reportPreviewTableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) #stretch columns
    self.ui.reportPreviewTableView.verticalHeader().setSectionResizeMode(QHeaderView.Fixed) #fix row heights
    self.ui.reportPreviewTableView.verticalHeader().setStretchLastSection(False) #don't stretch last row
    self.ui.reportPreviewTableView.setSelectionMode(QTableWidget.NoSelection) #set no selection
    self.ui.reportPreviewTableView.setEditTriggers(QTableWidget.NoEditTriggers) #set not editable
    self.ui.reportPreviewTableView.setSortingEnabled(False) #no sorting, comes sorted from database
    self.ui.reportPreviewTableView.setFocusPolicy(Qt.NoFocus) #set no focus
    self.ui.reportPreviewTableView.setTextElideMode(Qt.ElideMiddle) #set elide text in the middle
    self.ui.reportPreviewTableView.setContextMenuPolicy(Qt.CustomContextMenu) #set custom context menu
    self.ui.reportPreviewTableView.customContextMenuRequested.connect(lambda position: ShowContextMenu(self, self.ui.reportPreviewTableView, position))

#------------------------------------------TABLE-VIEW-FILTER-END---------------------------------------------#

#---------------------------------------------SYSTEM-TRAY-ICON-----------------------------------------------#

# system tray icon class that will be used to show alert messages in operation system from system tray icon
class SystemTrayIcon():
    isTrayMessageShown = False #represents flag for indicating if tray message is shown
    trayMessageQueue = [] #represents tray message queue for showing tray messages

    # method for initializing system tray icon for various alert messages
    def InitTrayIcon(self):
        # check if system tray is available
        if QSystemTrayIcon.isSystemTrayAvailable():
            # create tray icon
            self.ui.trayIcon = QSystemTrayIcon(self)
            self.ui.trayIcon.setIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))
            self.ui.trayIcon.setVisible(True)

            # set hover tooltip for the tray icon
            self.ui.trayIcon.setToolTip('NetSpect™ IDS')

            # initialize menu for the tray icon
            self.ui.trayIconMenu = QMenu()
            self.ui.trayIconMenu.setObjectName('trayIconMenu')

            # start/stop detection
            self.ui.trayIcon.toggleDetectionAction = QAction('Start Detection', self)
            self.ui.trayIcon.toggleDetectionAction.triggered.connect(lambda event: self.StartStopButtonClicked())
            self.ui.trayIconMenu.addAction(self.ui.trayIcon.toggleDetectionAction)
            self.ui.trayIconMenu.addSeparator()

            # open homepage page
            self.ui.trayIcon.openHomepageAction = QAction('Homepage', self)
            self.ui.trayIcon.openHomepageAction.triggered.connect(lambda event: ChangePageIndex(self, 0))
            self.ui.trayIconMenu.addAction(self.ui.trayIcon.openHomepageAction)

            # open analytics page
            self.ui.trayIcon.openAnalyticsAction = QAction('Analytics', self)
            self.ui.trayIcon.openAnalyticsAction.triggered.connect(lambda event: ChangePageIndex(self, 1))
            self.ui.trayIconMenu.addAction(self.ui.trayIcon.openAnalyticsAction)

            # open report preview page
            self.ui.trayIcon.openReportPreviewAction = QAction('Report Preview', self)
            self.ui.trayIcon.openReportPreviewAction.triggered.connect(lambda event: ChangePageIndex(self, 2))
            self.ui.trayIconMenu.addAction(self.ui.trayIcon.openReportPreviewAction)

            # open information page
            self.ui.trayIcon.openInformationAction = QAction('Information', self)
            self.ui.trayIcon.openInformationAction.triggered.connect(lambda event: ChangePageIndex(self, 3))
            self.ui.trayIconMenu.addAction(self.ui.trayIcon.openInformationAction)

            # open settings page
            self.ui.trayIcon.openSettingsAction = QAction('Settings', self)
            self.ui.trayIcon.openSettingsAction.triggered.connect(lambda event: ChangePageIndex(self, 4))
            self.ui.trayIconMenu.addAction(self.ui.trayIcon.openSettingsAction)
            self.ui.trayIconMenu.addSeparator()

            # exit application
            self.ui.trayIcon.exitAction = QAction('Exit', self)
            self.ui.trayIcon.exitAction.triggered.connect(lambda event: self.close())
            self.ui.trayIconMenu.addAction(self.ui.trayIcon.exitAction)

            # attach context menu to the tray icon
            self.ui.trayIcon.setContextMenu(self.ui.trayIconMenu)


    # method to map the iconType to the appropriate QSystemTrayIcon
    def GetTrayIcon(self, iconType):
        if iconType == 'Warning':
            return QSystemTrayIcon.Warning
        elif iconType == 'Critical':
            return QSystemTrayIcon.Critical
        return QSystemTrayIcon.Information


    # method for showing queued tray messages
    def ShowNextTrayMessage(self):
        # check if tray message queue is not empty
        if SystemTrayIcon.trayMessageQueue:
            SystemTrayIcon.isTrayMessageShown = True #set flag to true

            # pop first tray message and show it in operation system
            title, message, icon, duration = SystemTrayIcon.trayMessageQueue.pop(0)
            self.ui.trayIcon.showMessage(title, message, icon, duration)

            # schedule the next tray message and repeat until we have shown all queued tray messages
            QTimer.singleShot(100, lambda: SystemTrayIcon.ShowNextTrayMessage(self))
        # else we don't have any queued tray messages
        else:
            SystemTrayIcon.isTrayMessageShown = False #set flag to false


# method for showing tray icon messages in operating system
def ShowTrayMessage(self, title, message, iconType='Information', duration=5000):
    # get desired tray icon for tray message
    icon = SystemTrayIcon.GetTrayIcon(self, iconType)
    # append tray message to tray message queue
    SystemTrayIcon.trayMessageQueue.append((title, message, icon, duration))
    # show tray message if not shown
    if not SystemTrayIcon.isTrayMessageShown:
        SystemTrayIcon.ShowNextTrayMessage(self)

#-------------------------------------------SYSTEM-TRAY-ICON-END---------------------------------------------#

#----------------------------------------------MAIN-FUNCTION-------------------------------------------------#

# main method that sets up all the ui elements on startup
def InitUserInterface(self):
    # set the title and icon for main window
    self.setWindowTitle('NetSpect™')
    self.setWindowIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))

    # set initial width of elements
    self.ui.loginRegisterVerticalFrame.setFixedWidth(0)
    self.ui.registerFrame.hide()
    self.ui.resetPasswordFrame.hide()
    self.ui.sideFrame.setFixedWidth(70)

    # hide the verify code in reset password side frame
    ToggleBetweenEmailAndCodeResetPassword(self, True)

    # initialize system tray icon
    SystemTrayIcon.InitTrayIcon(self)

    # initilize charts in GUI
    AttackPieChart.InitAttackPieChart(self)
    AnalyticsHistogramChart.InitAnalyticsHistogramChart(self)
    AnalyticsBarChart.InitAnalyticsBarChart(self)

    # initilize report preview table view and initialize selected attacks and time filter
    InitReportTableView(self)

    # enable context menu on mac address and ip addresses list widgets and on history table widget
    EnableContextMenuMacAddressListWidget(self)
    EnableContextMenuIpAddressesListWidget(self)
    EnableContextMenuHistoryTableWidget(self)

    # hide side bar labels and icons and toggle user interface
    HideSideBarLabels(self)
    ShowSideBarMenuIcon(self)
    ToggleUserInterface(self, False)

    # apply shadow to the left side bar
    ApplyShadowSidebar(self)

    # initialize eye buttons for password line edits
    InitPasswordLineEditEyeButtons(self)

#--------------------------------------------MAIN-FUNCTION-END-----------------------------------------------#