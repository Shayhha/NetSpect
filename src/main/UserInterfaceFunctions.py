from PySide6 import QtWidgets
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QEasingCurve, QSortFilterProxyModel, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import QApplication, QMenu, QTableWidget, QWidget, QDialog, QLabel, QLineEdit, QStyle, QPushButton, QGridLayout, QHeaderView, QSystemTrayIcon, QVBoxLayout, QHBoxLayout, QGraphicsDropShadowEffect
from PySide6.QtGui import QAction, QColor, QIcon, QPixmap, QFont, QCursor, QPainter
from PySide6.QtCharts import QChart, QChartView, QPieSeries
from datetime import datetime, timedelta
from pathlib import Path

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located

#-------------------------------------------ANIMATION-FUNCTIONS----------------------------------------------#

# function for openning the left sideframe with an animation
def OpenSideFrame(self):
    animation = QPropertyAnimation(self.ui.sideFrame, b'minimumWidth')
    animation.setDuration(500)
    animation.setEasingCurve(QEasingCurve.InOutQuad)
    animation.setStartValue(70)
    animation.setEndValue(210)
                
    # start the animation
    animation.start()

    # show sidebar labels
    self.ui.menuIcon.hide()
    self.ui.closeMenuIcon.show()
    self.ui.homePageLabel.show()
    self.ui.analyticsLabel.show()
    self.ui.reportLabel.show()
    self.ui.infoLabel.show()

    # store the animation reference
    self.ui.sideFrame.currentAnimation = animation


# function for closing the left sideframe with an animation
def CloseSideFrame(self):
    # create animation for minimumWidth
    animation = QPropertyAnimation(self.ui.sideFrame, b'minimumWidth')
    animation.setDuration(500)
    animation.setEasingCurve(QEasingCurve.OutQuad)
    animation.setStartValue(210)
    animation.setEndValue(70)
    
    # start the animation
    animation.start()

    # add delayed animations to icons and labels
    QTimer.singleShot(100, lambda: HideSideBarLabels(self))
    QTimer.singleShot(400, lambda: ShowSideBarMenuIcon(self))
    self.ui.sideFrame.setMaximumWidth(70)
    self.ui.menuIcon.setFixedWidth(50)
    
    # store the animation reference
    self.ui.sideFrame.currentAnimation = animation


# function for opening the login/register side frame after clicking the account icon
def AccountIconClicked(self):
    # create animation object for the frame
    animation = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    animation.setDuration(500) #duration in milliseconds (500ms = 0.5 seconds)
    animation.setEasingCurve(QEasingCurve.InOutQuad) #smooth easing curve
    
    if self.ui.loginRegisterVerticalFrame.width() == 0: #fade in animation
        animation.setStartValue(0)
        animation.setEndValue(303)
        self.ui.loginUsernameLineEdit.setFocus() if self.ui.loginFrame.isVisible() else self.ui.registerEmailLineEdit.setFocus()
        if self.ui.resetPasswordFrame.isVisible():
            self.ui.resetPasswordFrame.hide()
            self.ui.loginFrame.show()
            self.ui.loginUsernameLineEdit.setFocus()
            ClearResetPasswordLineEdits(self)

    else: #fade out animation
        animation.setStartValue(303)
        animation.setEndValue(0)
        self.ui.loginUsernameLineEdit.clearFocus()
        self.ui.registerEmailLineEdit.clearFocus()

    
    # start the animation
    animation.start()
    ApplyShadowLoginRegister(self)

    # keep the animation object alive by storing it
    self.ui.loginRegisterVerticalFrame.currentAnimation = animation


# function for changing between the login and register sideframes
def SwitchBetweenLoginAndRegister(self, showRegister=True):
    # first animation: Close the frame
    anim1 = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    anim1.setDuration(200)
    anim1.setEasingCurve(QEasingCurve.InOutQuad)
    
    # use the current width as the start value
    currentWidth = self.ui.loginRegisterVerticalFrame.width()
    anim1.setStartValue(currentWidth)
    anim1.setEndValue(0)
    
    # start the first animation and chain the second animation to start after the first finishes
    anim1.start()
    self.ui.loginRegisterVerticalFrame.currentAnimation = anim1
    anim1.finished.connect(lambda: ReopenRegistryFrame(self, showRegister)) 


# function for changing between the login and reset password sideframes
def SwitchBetweenLoginAndForgotPassword(self, showResetPassword):
    # first animation: Close the frame
    anim1 = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    anim1.setDuration(200)
    anim1.setEasingCurve(QEasingCurve.InOutQuad)
    
    # use the current width as the start value
    currentWidth = self.ui.loginRegisterVerticalFrame.width()
    anim1.setStartValue(currentWidth)
    anim1.setEndValue(0)
    
    # start the first animation and chain the second animation to start after the first finishes
    anim1.start()
    self.ui.loginRegisterVerticalFrame.currentAnimation = anim1
    anim1.finished.connect(lambda: ReopenResetPasswordFrame(self, showResetPassword)) 


# this is the second animation and visibility switch for the login register side frame
def ReopenRegistryFrame(self, showRegister):
    # switch visibility
    if showRegister:
        self.ui.loginFrame.hide()
        self.ui.registerFrame.show()
        self.ui.loginUsernameLineEdit.clearFocus()
        self.ui.registerEmailLineEdit.setFocus()
    else:
        self.ui.registerFrame.hide()
        self.ui.loginFrame.show()
        self.ui.loginUsernameLineEdit.setFocus()
        self.ui.registerEmailLineEdit.clearFocus()
    
    # second animation: Open the frame
    anim2 = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    anim2.setDuration(375)
    anim2.setEasingCurve(QEasingCurve.InOutQuad)
    anim2.setStartValue(0)
    anim2.setEndValue(303)
    anim2.start()
    self.ui.loginRegisterVerticalFrame.currentAnimation = anim2


# this is the second animation and visibility switch for the login register side frame
def ReopenResetPasswordFrame(self, showResetPassword):
    # switch visibility
    if showResetPassword:
        self.ui.loginFrame.hide()
        self.ui.resetPasswordFrame.show()
        self.ui.loginUsernameLineEdit.clearFocus()
        self.ui.resetPasswordEmailLineEdit.setFocus()
    else:
        self.ui.resetPasswordFrame.hide()
        self.ui.loginFrame.show()
        self.ui.loginUsernameLineEdit.setFocus()
        self.ui.resetPasswordEmailLineEdit.clearFocus()
        ClearResetPasswordLineEdits(self)
    
    # show the correct line edit and push button
    ToggleBetweenEmailAndCodeResetPassword(self, showResetPassword)

    # second animation: Open the frame
    anim2 = QPropertyAnimation(self.ui.loginRegisterVerticalFrame, b'maximumWidth')
    anim2.setDuration(375)
    anim2.setEasingCurve(QEasingCurve.InOutQuad)
    anim2.setStartValue(0)
    anim2.setEndValue(303)
    anim2.start()
    self.ui.loginRegisterVerticalFrame.currentAnimation = anim2

#-----------------------------------------ANIMATION-FUNCTIONS-END--------------------------------------------#

#---------------------------------------------CLICK-FUNCTIONS------------------------------------------------#

# function for hiding some labels
def HideSideBarLabels(self):
    self.ui.homePageLabel.hide()
    self.ui.analyticsLabel.hide()
    self.ui.reportLabel.hide()
    self.ui.infoLabel.hide()


# function for showing some icons
def ShowSideBarMenuIcon(self):
    self.ui.menuIcon.show()
    self.ui.closeMenuIcon.hide()


# function for changing between enter email and enter code screens in reset password
def ToggleBetweenEmailAndCodeResetPassword(self, isEmail=True):
    if isEmail:
        # show email section
        self.ui.resetPasswordEmailLineEdit.show()
        self.ui.resetPasswordEmailErrorMessageLabel.hide()
        self.ui.sendCodeButtonFrame.show()

        # hide the email section
        self.ui.resetPasswordCodeLineEdit.hide()
        self.ui.resetPasswordCodeErrorMessageLabel.hide()
        self.ui.verifyCodeButtonFrame.hide()
    else:
        # hide email section
        self.ui.resetPasswordEmailLineEdit.hide()
        self.ui.resetPasswordEmailErrorMessageLabel.hide()
        self.ui.sendCodeButtonFrame.hide()

        # show the email section
        self.ui.resetPasswordCodeLineEdit.show()
        self.ui.resetPasswordCodeErrorMessageLabel.hide()
        self.ui.verifyCodeButtonFrame.show()


# function for showing and hiding user interface
def ToggleUserInterface(self, state):
    # if true we need to show user logged in labels
    if state:
        self.ui.accountIcon.hide()
        self.ui.reportDurationComboBox.setEnabled(True)
        self.ui.welcomeLabel.show()
        self.ui.logoutIcon.show()
        ShowSettingsInputFields(self)

    # else we hide user labels
    else:
        HideSettingsInputFields(self)
        self.ui.logoutIcon.hide()
        self.ui.welcomeLabel.hide()
        self.ui.reportDurationComboBox.setEnabled(False)
        self.ui.welcomeLabel.clear()
        self.ui.accountIcon.show()
        self.ui.colorModeComboBox.setCurrentIndex(0) #reset the color combobox if the user has logged out
        self.ui.operationModeComboBox.setCurrentIndex(0) #reset the operation mode combobox if the user has logged out

    #clear history and report tables and blacklist and pie chart
    self.ui.historyTableWidget.setRowCount(0)
    self.ui.reportPreviewTableModel.ClearRows()
    self.ui.macAddressListWidget.clear()
    ResetChartToDefault(self) #reset our pie chart

    #set combobox and checkboxes default state
    self.ui.reportDurationComboBox.setCurrentIndex(3)
    self.ui.arpSpoofingCheckBox.setChecked(True)
    self.ui.portScanningCheckBox.setChecked(True)
    self.ui.denialOfServiceCheckBox.setChecked(True)
    self.ui.dnsTunnelingCheckBox.setChecked(True)
    self.ui.machineInfoCheckBox.setChecked(False)
    ToggleReportInterface(self, False) #reset the styles of report interface back to default state
    ToggleColorMode(self) #reset the styles to match the selected index in the color mode combobox
    ToggleOperationMode(self) #reset the styles to match the selected index in the operation mode combobox

    #clear settings, login and register line edits and reset number of detections
    self.ui.numberOfDetectionsCounter.setText('0')
    self.ui.emailLineEdit.clear()
    self.ui.usernameLineEdit.clear()
    self.ui.oldPasswordLineEdit.clear()
    self.ui.newPasswordLineEdit.clear()
    self.ui.confirmPasswordLineEdit.clear()
    self.ui.macAddressLineEdit.clear()
    self.ui.loginUsernameLineEdit.clear()
    self.ui.loginPasswordLineEdit.clear()
    self.ui.registerEmailLineEdit.clear()
    self.ui.registerUsernameLineEdit.clear()
    self.ui.registerPasswordLineEdit.clear()
    self.ui.saveEmailErrorMessageLabel.clear()
    self.ui.saveUsernameErrorMessageLabel.clear()
    self.ui.savePasswordErrorMessageLabel.clear()
    self.ui.macAddressBlacklistErrorMessageLabel.clear()
    self.ui.registerEmailLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits(self, 'registerEmailLineEdit'))
    self.ui.registerUsernameLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits(self, 'registerUsernameLineEdit'))
    self.ui.registerPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits(self, 'registerPasswordLineEdit'))
    self.ui.oldPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits(self, 'oldPasswordLineEdit'))
    self.ui.newPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits(self, 'newPasswordLineEdit'))
    self.ui.confirmPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits(self, 'confirmPasswordLineEdit'))


# function for showing and hiding report interface
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


# function for toggling between detection and collection interfaces
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


# function for chaning the current page index on the stack widget
def ChangePageIndex(self, index):
    # clear focus from all line edits
    self.ui.emailLineEdit.clearFocus()
    self.ui.usernameLineEdit.clearFocus()
    self.ui.oldPasswordLineEdit.clearFocus()
    self.ui.newPasswordLineEdit.clearFocus()
    self.ui.confirmPasswordLineEdit.clearFocus()
    self.ui.macAddressLineEdit.clearFocus()
    self.ui.stackedWidget.setCurrentIndex(index)


# function for toggling the password visibility using an icon
def TogglePasswordVisibility(lineEditWidget, eyeIcon):
    if lineEditWidget.echoMode() == QLineEdit.Password:
        lineEditWidget.setEchoMode(QLineEdit.Normal) #show the password
        eyeIcon.setIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'EyeClosed.png'))) #change to open eye icon
    else:
        lineEditWidget.setEchoMode(QLineEdit.Password) #hide the password
        eyeIcon.setIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'EyeOpen.png'))) #change to closed eye icon


# function for toggling between detection or collection states and setting startStop button stylesheet accordingly
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


# function for toggling between light and dark mode by the user (also used when logging in and out of an account)
def ToggleColorMode(self):
    # clear existing css from each element in the ui file (needed to make sure that no style changes are transferred from previous color mode selection)
    self.setStyleSheet('') #clear css from main element
    for child in self.findChildren(QWidget): #clear css from all child elements
        child.setStyleSheet('')

    # apply default dark mode or light mode theme to the application based on users selection
    if self.ui.colorModeComboBox.currentText() == 'Dark Mode':
        self.userData['lightMode'] = 0
        self.ui.accountIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'AccountLight.png')))
        self.ui.settingsIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'SettingsLight.png')))
        self.ui.logoutIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'LogoutLight.png')))
        self.ui.menuIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'BulletedMenuLight.png')))
        self.ui.closeMenuIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'BulletedMenuLightRotated.png')))
        self.ui.homePageIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'WorkStationLight.png')))
        self.ui.analyticsIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'AnalyticsLight.png')))
        self.ui.reportIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'DocumentLight.png')))
        self.ui.infoIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'InfoLight.png')))
        self.ui.githubInfoLabel.setText('''
            <html>
                <head/>
                <body>
                    <p>
                        <a href='https://github.com/Shayhha/NetSpect'>
                            <span style="text-decoration: underline; color: #f3f3f3;">Visit NetSpect Page</span>
                        </a>
                    </p>
                </body>
            </html>
        ''')
        self.ui.piChart.setBackgroundBrush(QColor(204, 204, 204, 153))
        with open(currentDir.parent / 'interface' / 'darkModeStyles.qss', 'r') as stylesFile: #load styles from file
            self.setStyleSheet(stylesFile.read())
    else:
        self.userData['lightMode'] = 1
        self.ui.accountIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'AccountDark.png')))
        self.ui.settingsIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'SettingsDark.png')))
        self.ui.logoutIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'LogoutDark.png')))
        self.ui.menuIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'BulletedMenuDark.png')))
        self.ui.closeMenuIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'BulletedMenuDarkRotated.png')))
        self.ui.homePageIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'WorkStationDark.png')))
        self.ui.analyticsIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'AnalyticsDark.png')))
        self.ui.reportIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'DocumentDark.png')))
        self.ui.infoIcon.setPixmap(QPixmap(str(currentDir.parent / 'interface' / 'Icons' / 'InfoDark.png')))
        self.ui.githubInfoLabel.setText('''
            <html>
                <head/>
                <body>
                    <p>
                        <a href='https://github.com/Shayhha/NetSpect'>
                            <span style="text-decoration: underline; color: #151519;">Visit NetSpect Page</span>
                        </a>
                    </p>
                </body>
            </html>
        ''')
        self.ui.piChart.setBackgroundBrush(QColor(193, 208, 239))
        with open(currentDir.parent / 'interface' / 'lightModeStyles.qss', 'r') as stylesFile: #load styles from file
            self.setStyleSheet(stylesFile.read())

#-------------------------------------------CLICK-FUNCTIONS-END----------------------------------------------#

#---------------------------------------------OTHER-FUNCTIONS------------------------------------------------#

# function for clearing the reset password line edits end error messages
def ClearResetPasswordLineEdits(self):
    self.ui.resetPasswordEmailLineEdit.clear()
    self.ui.resetPasswordCodeLineEdit.clear()
    self.ui.resetPasswordEmailErrorMessageLabel.clear()
    self.ui.resetPasswordCodeErrorMessageLabel.clear()


# function for adding a box shadow to the login/register side popup frame
def ApplyShadowLoginRegister(self):
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(15) #no blur, sharp shadow (like blur: 0 in CSS)
    shadow.setXOffset(-8) #horizontal offset: -15px (left)
    shadow.setYOffset(0) #vertical offset: 10px (down)
    shadow.setColor(QColor(0, 0, 0, 85)) #RGBA(56, 60, 170, 0.5) -> alpha 0.5 = 128/255
    self.ui.loginRegisterVerticalFrame.setGraphicsEffect(shadow)


# function for adding a box shadow to the left side bar
def ApplyShadowSidebar(self):
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(5) # No blur, sharp shadow (like blur: 0 in CSS)
    shadow.setXOffset(5) # Horizontal offset: -15px (left)
    shadow.setYOffset(0) # Vertical offset: 10px (down)
    shadow.setColor(QColor(0, 0, 0, 50)) # RGBA(56, 60, 170, 0.5) -> alpha 0.5 = 128/255
    self.ui.sideFrame.setGraphicsEffect(shadow)


# function that shows right-click menu for copying and deleting items in mac
def ShowContextMenu(self, position):
    if self.ui.macAddressListWidget.count() == 0:
        return #do nothing if there are no items

    item = self.ui.macAddressListWidget.itemAt(position)
    if item:
        menu = QMenu()
        copyAction = QAction('Copy')
        copyAction.triggered.connect(lambda: CopyToClipboard(item.text()))
        deleteAction = QAction('Delete')
        deleteAction.triggered.connect(lambda: self.DeleteMacAddressButtonClicked(item))
        menu.addAction(copyAction)
        menu.addAction(deleteAction)
        menu.exec(self.ui.macAddressListWidget.viewport().mapToGlobal(position))


# function that copies the item text to the clipborad
def CopyToClipboard(text):
    clipboard = QApplication.clipboard()  
    clipboard.setText(text)


# function for disabling selecion and editing on history table widget and enable some other features
def DisableSelectionHistoryTableWidget(self):
    # disable selection and editing on history table
    self.ui.historyTableWidget.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.ui.historyTableWidget.setEditTriggers(QTableWidget.NoEditTriggers) #disable editing
    self.ui.historyTableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch) #distribute column widths equally
    self.ui.historyTableWidget.setTextElideMode(Qt.ElideMiddle) #set elide in middle


# function for setting the text of an error message like login/register/change email/ etc.
def ChangeErrorMessageText(errorMessageObject, message):
    errorMessageObject.setText('<p style="line-height: 0.7;">' + message + '</p>')
    errorMessageObject.show()


# fucntion for clearing error message of error message label
def ClearErrorMessageText(errorMessageObject):
    errorMessageObject.setText('')
    errorMessageObject.hide()


# hide the change email, username, password and color mode from settings page 
def HideSettingsInputFields(self):
    self.ui.settingsChangeVerticalFrame.hide()
    self.ui.opperationModeHorizontalFrame.hide()
    self.ui.deleteAccoutPushButton.hide()
    self.ui.settingsInterfaceMacButtonsVerticalFrame.setContentsMargins(40, 0, 0, 0) 


# show the change email, username, password and color mode from settings page 
def ShowSettingsInputFields(self):
    self.ui.settingsChangeVerticalFrame.show()
    self.ui.opperationModeHorizontalFrame.show()
    self.ui.deleteAccoutPushButton.show()
    self.ui.settingsInterfaceMacButtonsVerticalFrame.setContentsMargins(0, 10, 0, 0) #returning the default values


# function for returning the default style sheet of the line edits in the settings page
def GetDefaultStyleSheetSettingsLineEdits(self, lineEditName):
    defaultStylesheet = f''' 
        #{lineEditName} {{
            {'background-color: #f3f3f3;' if self.userData.get('lightMode') == 0 else 'background-color: #ebeff7;'}
            {'border: 2px solid lightgray;' if self.userData.get('lightMode') == 0 else 'border: 2px solid #899fce;'}
            border-radius: 10px;
            padding: 5px;
            color: black;
            margin: 0px 0px 0px 0px; 
        }}
    '''
    return defaultStylesheet


# function for returning the default style sheet of the line edits in register
def GetDefaultStyleSheetRegisterLineEdits(self, lineEditName):
    defaultStylesheet = f''' 
        #{lineEditName} {{
            {f'background-color: #f3f3f3;' if self.userData.get('lightMode') == 0 else f'background-color: {'#fbfcfd' if any(prefix in lineEditName for prefix in ['login', 'register', 'reset']) else '#ebeff7'};'}
            {'border: 2px solid lightgray;' if self.userData.get('lightMode') == 0 else 'border: 2px solid #899fce;'}
            border-radius: 10px;
            padding: 5px;
            color: black;
            {'margin: 0px 5px 0px 5px;' if ('Password' in lineEditName) else 'margin: 0px 5px 10px 5px;'}
        }}
    '''
    return defaultStylesheet

#-------------------------------------------OTHER-FUNCTIONS-END----------------------------------------------#

#--------------------------------------------CUSTOM-MESSAGEBOX-----------------------------------------------#

# custom message box class that will be used to show error messages to the user at certain times
class CustomMessageBox(QDialog):
    isMessageBox = False #represents flag for indicating if messagebox already exists

    # constructor of custom message box class
    def __init__(self, title, message, iconType, isSelectable=False):
        super().__init__()

        # set the message box window title and icon
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))
        # self.setFont(QFont('Cairo', 13))

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
            QDialog {
                background-color: #f3f3f3;
            }
                        
            QLabel {
                color: black;
                font-family: 'Cairo';
                font-size: 18px;
            }

            QLabel[alignment='Qt::AlignVCenter|Qt::AlignLeft'] {
                margin-left: 10px;
            }
                        
            QPushButton {
                background-color: #3a8e32;
                border: 1px solid black;
                border-radius: 10px;
                font-family: 'Cairo';
                font-size: 16px;
                font-weight: bold;
                color: #f3f3f3;
                min-width: 80px;
            }
                           
            QPushButton:hover {
                background-color: #4d9946;
            }
                           
            QPushButton:pressed {
                background-color: #2e7128;
            }
                        
            QPushButton[text='No'] {
                background-color: #d84f4f;
                border: 1px solid black;
                border-radius: 10px;
                font-family: 'Cairo';
                font-size: 16px;
                font-weight: bold;      
                color: #f3f3f3;
                min-width: 80px;
            }
                           
            QPushButton[text='No']:hover {
                background-color: #db6060;
            }
                           
            QPushButton[text='No']:pressed {
                background-color: #ac3f3f;
            }
        ''')
    
        # set dialog properties non-resizable but sized to content
        self.setMinimumSize(350, 150) #set a reasonable minimum size
        self.adjustSize() #adjust the size based on content
        self.setFixedSize(self.size()) #lock the size to prevent resizing


    # method for overriting the original accept function and setting isMessageBox flag
    def accept(self):
        CustomMessageBox.isMessageBox = False
        super().accept()


    # method for overriting the original reject function and setting isMessageBox flag
    def reject(self):
        CustomMessageBox.isMessageBox = False
        super().reject()
    

    # method for mapping the iconType to the appropriate StandardPixmap icon
    def GetMessageBoxIcon(self, iconType):
        if iconType == 'Warning':
            QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning)
        elif iconType == 'Critical':
            return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxCritical)
        elif iconType == 'Question':
            return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxQuestion)
        return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)


# function for showing message box window
def ShowMessageBox(title, message, iconType='Information', isSelectable=False):
    # iconType options can be Information, Warning, Critical, Question, NoIcon
    if not CustomMessageBox.isMessageBox:
        messageBox = CustomMessageBox(title, message, iconType, isSelectable)

        # set isMessageBox and show messag ebox
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
        'ARP Spoofing': ('ARP', 'ARP Spoofing', '#90cfef'),
        'Port Scan': ('Port Scan', 'Port Scanning', '#209fdf'),
        'DoS': ('DoS', 'Denial of Service', '#15668f'),
        'DNS Tunneling': ('DNS', 'DNS Tunneling', '#092d40')
    }

    # method for creating and initializing an empty attack pie chart
    def InitAttackPieChart(self):
        try:
            # create pie chart
            series = QPieSeries()
            chart = QChart()
            chart.addSeries(series)

            # create font for title
            titleFont = QFont('Cairo', 16, QFont.Bold, False) 

            # create a legend widget
            legendWidget = QWidget()
            self.ui.legendLayout = QGridLayout(legendWidget)
            legendWidget.setObjectName('legendWidget')

            # setup the base chart widget
            chart.legend().setVisible(False)
            chart.layout().setContentsMargins(0, 0, 0, 0)
            chart.setAnimationOptions(QChart.AllAnimations)
            chart.setBackgroundRoundness(0)
            chart.setBackgroundBrush(QColor(204, 204, 204, 153) if self.userData.get('lightMode') == 0 else QColor(193, 208, 239))
            chart.setTitle('No Data To Display...')
            chart.setTitleFont(titleFont)
            
            # create chart view and vbox layout
            chartView = QChartView(chart)
            chartView.setRenderHint(QPainter.Antialiasing)
            chartView.setMinimumSize(440, 260)

            VBoxLayout = QVBoxLayout()
            VBoxLayout.setSpacing(0)
            VBoxLayout.setContentsMargins(0, 0, 0, 0)

            # add stles to the title
            titleLabel = QLabel('Attacks Distribution')
            titleLabel.setObjectName('pieChartTitleLabel') 

            # setup the pie chart legends in advance
            for i, (sliceName, legendName, sliceColor) in enumerate(AttackPieChart.pieChartLabelDict.values()):
                legendFont = QFont('Cairo', 12, QFont.Bold, False) # font settings for legend (defined once)
                legendLabel = QLabel(f'{legendName} 0%')
                legendLabel.setFont(legendFont)
                legendLabel.setObjectName(f'{legendName.replace(' ', '')}LegendLabel') #for example: ARPSpoofingLegendLabel

                colorLabel = QLabel()
                colorLabel.setObjectName(f'{legendName.replace(' ', '')}LegendColorLabel')
                colorLabel.setStyleSheet(f'background-color: {sliceColor}; border: 1px solid black;')
                colorLabel.setFixedSize(20, 20)

                row = i // 2
                col = (i % 2) * 2
                self.ui.legendLayout.addWidget(colorLabel, row, col)
                self.ui.legendLayout.addWidget(legendLabel, row, col + 1)

            # add items to the chart VBox
            VBoxLayout.addWidget(titleLabel)
            VBoxLayout.addWidget(chartView)
            VBoxLayout.addWidget(legendWidget)

            # save the chart object in self.ui (NetSpect object) for later use
            self.ui.chartVerticalFrame.setLayout(VBoxLayout)
            self.ui.chartVerticalFrame.update()
            self.ui.piChart = chart

        except Exception as e:
            ShowMessageBox('Error In Pie Chart Initialization', 'Error occurred in pie chart initialization, try again later.', 'Critical')


# function for updating the pie chart after an attack was detected, expects an attack name like: ARP, DNS, Port Scan, DoS
def UpdateChartAfterAttack(self, attackName):
    try:
        sliceLable = AttackPieChart.pieChartLabelDict.get(attackName)[0]
        series = self.ui.piChart.series()[0]

        # increment the value of the attack slice based on given attack name
        found = False
        for slice in series.slices():
            if sliceLable in slice.label():  
                slice.setValue(slice.value() + 1)
                found = True
                break
        
        # if slice does not exist, then create a new slice and add it to the pie chart
        if not found:
            sliceFont = QFont('Cairo', 11, QFont.Bold, False)
            newSlice = series.append(sliceLable, 1)
            newSlice.setLabelFont(sliceFont)
            newSlice.setLabelVisible(True)
            newSlice.setLabelArmLengthFactor(0.075)
            newSlice.setLabel(f'{sliceLable} {newSlice.percentage()*100:.1f}%')
            newSlice.setLabelColor(QColor(45, 46, 54, 255) if self.userData.get('lightMode') == 0 else QColor(1, 1, 1, 255))
            newSlice.setColor(QColor(AttackPieChart.pieChartLabelDict.get(attackName)[2]))

        # set the title to be empty (hide the title) if there is at least one attack detection in history
        if series.count() > 0:
            self.ui.piChart.setTitle('')
        
        UpdateChartLegendsAndSlices(self) #update the text data of legends and slice labels

    except Exception as e:
        ShowMessageBox('Error Updating Pie Chart', 'Error occurred while updating pie chart, try again later.', 'Critical')

    
#  function for updating the text of the pie chart legends and slice labels
def UpdateChartLegendsAndSlices(self):
    try:
        # creating a new dict with legend names like: sliceName: legendName
        pieChartNames = {pieChartValues[0] : pieChartValues[1] for pieChartValues in AttackPieChart.pieChartLabelDict.values()} 
        series = self.ui.piChart.series()[0] #get the pie chart object
        
        # update the legend and slice text for all slices
        for slice in series.slices():
            # update the slice text with correct values
            sliceSplit = slice.label().split(' ')
            sliceAttackName = ' '.join([sliceSplit[0], sliceSplit[1]]) if 'Port' in sliceSplit[0] else sliceSplit[0]
            slice.setLabel(f'{sliceAttackName} {slice.percentage()*100:.1f}%')

            # update the legend text to match current slice
            legendLabelText = f'{pieChartNames.get(sliceAttackName)} {slice.percentage()*100:.1f}%'
            legendLabelName = f'{pieChartNames.get(sliceAttackName).replace(' ', '')}LegendLabel' 
            legendLabelObject = self.findChild(QLabel, legendLabelName)
            legendLabelObject.setText(legendLabelText)

    except Exception as e:
        ShowMessageBox('Error Updating Pie Chart', 'Error occurred while updating pie chart, try again later.', 'Critical')


# function for updating the pie chart after user login with data from database
def UpdateChartAfterLogin(self, pieChartData):
    try:
        # check if there's at least one attack in pieChartData dictionary
        if any(attackCount > 0 for attackCount in pieChartData.values()):
            # remove current series from pie chart if exists
            if self.ui.piChart.series():
                self.ui.piChart.removeSeries(self.ui.piChart.series()[0])

            # create a new series for pie chart with database data
            newSeries = QPieSeries()
            for attackName, attackCount in pieChartData.items():
                # check if attack count is greater then zero
                if attackCount > 0:
                    # add new slice for attack and update the css of the slice label
                    sliceFont = QFont('Cairo', 11, QFont.Bold, False)
                    newSlice = newSeries.append(AttackPieChart.pieChartLabelDict.get(attackName)[0], attackCount)
                    newSlice.setLabelFont(sliceFont)
                    newSlice.setLabelVisible(True)
                    newSlice.setLabelArmLengthFactor(0.075)
                    newSlice.setLabelColor(QColor(45, 46, 54, 255) if self.userData.get('lightMode') == 0 else QColor(1, 1, 1, 255))
                    newSlice.setColor(QColor(AttackPieChart.pieChartLabelDict.get(attackName)[2]))

            # add the new series to the chart and update the GUI
            self.ui.piChart.addSeries(newSeries)
            self.ui.piChart.setTitle('') #remove the default title if exists
            UpdateChartLegendsAndSlices(self)

    except Exception as e:
        ShowMessageBox('Error Updating Pie Chart', 'Error occurred while updating pie chart, try again later.', 'Critical')


# function for clearing the pie chart and resetting to default empty pie chart
def ResetChartToDefault(self):
    try:
        # clear the pie chart data and set the default title
        self.ui.piChart.series()[0].clear()
        self.ui.piChart.setTitle('No Data To Display...')

        # update the legend text and set it to the default values of 0%
        for legendName in AttackPieChart.pieChartLabelDict.values():
            legendLabelText = f'{legendName[1]} 0%'
            legendLabelName = f'{legendName[1].replace(' ', '')}LegendLabel' 
            legendLabelObject = self.findChild(QLabel, legendLabelName)
            legendLabelObject.setText(legendLabelText)

    except Exception as e:
        ShowMessageBox('Error Clearing Pie Chart', 'Error occurred while clearing pie chart, try again later.', 'Critical')

#------------------------------------------ATTACK-PIE-CHART-END----------------------------------------------#

#--------------------------------------------TABLE-VIEW-FILTER-----------------------------------------------#

# Custom Table Model that will sit inside the TableView object in the report page and will contain all the relevant data and functions
class CustomTableModel(QAbstractTableModel):
    reportPreviewColumnHeaders = ['Interface', 'Attack Type', 'Source IP', 'Source Mac', 'Destination IP', 'Destination Mac', 'Protocol', 'Timestamp']
    alertListData = [] #represents our alerts list in table view

    # constructor of table model class
    def __init__(self, data=None, parent=None):
        super().__init__(parent)
        self.alertListData = data


    # overwrite inherited function to get number of rows
    def rowCount(self, parent=None):
        return len(self.alertListData) #get number of rows in the data


    # overwrite inherited function to get number of columns
    def columnCount(self, parent=None):
        return len(self.reportPreviewColumnHeaders) + 1 #get number of columns (includes osType)


    # overwrite inherited function to get data from a specific cell
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


    # overwrite inherited function to set the column names
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            if section < len(self.reportPreviewColumnHeaders):
                return self.reportPreviewColumnHeaders[section]
        return None
    
        
    # overwrite inherited function to set the data into the column
    def setData(self, index, value, role=Qt.EditRole):
        if role == Qt.EditRole:
            if index.isValid() and 0 <= index.row() < self.rowCount() and 0 <= index.column() < self.columnCount():
                self.alertListData[index.row()][index.column()] = value
                self.dataChanged.emit(index, index, [Qt.DisplayRole])
                return True
        return False


    # function to add row to report preview table at the first index in top row
    def AddRow(self, interface, attackType, srcIp, srcMac, dstIp, dstMac, protocol, osType, timestamp):
        # create new row to insert into report preview table at the first index in top row
        row = [interface, attackType, srcIp, srcMac, dstIp, dstMac, protocol, timestamp, osType]
        self.beginInsertRows(QModelIndex(), 0, 0) #begin insertion at top
        self.alertListData.insert(0, row)
        self.endInsertRows() #end insertion


    # function to add items to a given row by index to report preview table
    def SetRowItem(self, row, column, value):
        # set data at specific row and column
        index = self.index(row, column)
        self.setData(index, value)


    # function to clear out the data from the report preview table
    def ClearRows(self):
        self.beginResetModel() #begin reset model
        self.alertListData.clear() #clear the data list
        self.endResetModel() #end reset model


# Custom Proxy Model for filtering the TableView that is in the report page, this class will hold the filtering logic and functions
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


    # function to update selected classes and refresh filter (for checkboxes)
    def SetSelectedAttacks(self, selectedAttacks):
        self.selectedAttacks = set(selectedAttacks)
        self.invalidateFilter() #triggers re-filtering


    # function to update time filter and refresh the table (for combobox)
    def SetTimeFilter(self, timeFilter):
        self.timeFilter = timeFilter
        self.invalidateFilter() #triggers re-filtering


    # overwrite inherited function that determines if a row should be shown based on filter conditions
    def filterAcceptsRow(self, sourceRow, sourceParent):
        model = self.sourceModel()

        # get timestamp and attack type row data
        timestampValue = model.data(model.index(sourceRow, 7), Qt.DisplayRole) #column 7 is Timestamp
        attackTypeValue = model.data(model.index(sourceRow, 1), Qt.DisplayRole) #column 1 is Attack Type

        # convert timestamp string to datetime object and get current time to check the filter
        rowTimestamp = datetime.strptime(timestampValue, '%H:%M:%S %d/%m/%y')
        currentTime = datetime.now()

        # time filtering logic, if the combobox is selected with 'All Available Data' then it will skip the time filter
        if self.timeFilter == 'Last 24 Hours' and rowTimestamp < currentTime - timedelta(days=1):
            return False
        elif self.timeFilter == 'Last 7 Days' and rowTimestamp < currentTime - timedelta(days=7):
            return False
        elif self.timeFilter == 'Last 30 Days' and rowTimestamp < currentTime - timedelta(days=30):
            return False

        # attack filtering logic by attack checkboxes
        if not self.selectedAttacks or attackTypeValue not in self.selectedAttacks:
            return False #dont show the row if it did not pass one of the filters

        return True #show current row if it passed all filters


# function that will be called when the user clicks on one of the attack checkboxes in the report page (ARP, Port, DoS, DNS)
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


# function that will be called when the user selects a different time fillter option in the report page (combobox)
def ReportDurationComboboxChanged(self):
    self.ui.proxyReportPreviewTableModel.SetTimeFilter(self.ui.reportDurationComboBox.currentText())


# function for getting flitered alert list from proxy model
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


# function for initializing the table view in the report page when the application loads up
def InitReportTableView(self):
    # initialize the Table View and custom table filter
    self.ui.reportPreviewTableModel = CustomTableModel(self.userData.get('alertList'))
    self.ui.proxyReportPreviewTableModel = CustomFilterProxyModel()
    self.ui.proxyReportPreviewTableModel.setSourceModel(self.ui.reportPreviewTableModel)

    # change some of the table attributes to make it look how we want it
    self.ui.reportPreviewTableView.setModel(self.ui.proxyReportPreviewTableModel)
    self.ui.reportPreviewTableView.setColumnHidden(self.ui.reportPreviewTableModel.columnCount() - 1, True) #hide osType column
    self.ui.reportPreviewTableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) #distribute column widths equally
    self.ui.reportPreviewTableView.verticalHeader().setDefaultSectionSize(30) #set max row height to 30px
    self.ui.reportPreviewTableView.verticalHeader().setSectionResizeMode(QHeaderView.Fixed) #fix row heights
    self.ui.reportPreviewTableView.verticalHeader().setStretchLastSection(False) #don't stretch last row
    self.ui.reportPreviewTableView.setTextElideMode(Qt.ElideMiddle)
    self.ui.reportPreviewTableView.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.ui.reportPreviewTableView.setFocusPolicy(Qt.NoFocus)
    self.ui.reportPreviewTableView.setEditTriggers(QTableWidget.NoEditTriggers)
    self.ui.reportPreviewTableView.setSortingEnabled(False)

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

            # initialize context menu for the tray icon
            trayMenu = QMenu()

            # start/stop detection
            self.ui.trayIcon.toggleDetectionAction = QAction('Start Detection', self)
            self.ui.trayIcon.toggleDetectionAction.triggered.connect(lambda event: self.StartStopButtonClicked())
            trayMenu.addAction(self.ui.trayIcon.toggleDetectionAction)
            trayMenu.addSeparator()

            # open homepage page
            self.ui.trayIcon.openHomepageAction = QAction('Homepage', self)
            self.ui.trayIcon.openHomepageAction.triggered.connect(lambda event: ChangePageIndex(self, 0))
            trayMenu.addAction(self.ui.trayIcon.openHomepageAction)

            # open analytics page
            self.ui.trayIcon.openAnalyticsAction = QAction('Analytics', self)
            self.ui.trayIcon.openAnalyticsAction.triggered.connect(lambda event: ChangePageIndex(self, 1))
            trayMenu.addAction(self.ui.trayIcon.openAnalyticsAction)

            # open report preview page
            self.ui.trayIcon.openReportPreviewAction = QAction('Report Preview', self)
            self.ui.trayIcon.openReportPreviewAction.triggered.connect(lambda event: ChangePageIndex(self, 2))
            trayMenu.addAction(self.ui.trayIcon.openReportPreviewAction)

            # open information page
            self.ui.trayIcon.openInformationAction = QAction('Information', self)
            self.ui.trayIcon.openInformationAction.triggered.connect(lambda event: ChangePageIndex(self, 3))
            trayMenu.addAction(self.ui.trayIcon.openInformationAction)

            # open settings page
            self.ui.trayIcon.openSettingsAction = QAction('Settings', self)
            self.ui.trayIcon.openSettingsAction.triggered.connect(lambda event: ChangePageIndex(self, 4))
            trayMenu.addAction(self.ui.trayIcon.openSettingsAction)
            trayMenu.addSeparator()

            # exit application
            self.ui.trayIcon.exitAction = QAction('Exit', self)
            self.ui.trayIcon.exitAction.triggered.connect(lambda event: self.close())
            trayMenu.addAction(self.ui.trayIcon.exitAction)

            # attach context menu to the tray icon
            self.ui.trayIcon.setContextMenu(trayMenu)


    # fucntion to map the iconType to the appropriate QSystemTrayIcon
    def GetTrayIcon(self, iconType):
        if iconType == 'Warning':
            return QSystemTrayIcon.Warning
        elif iconType == 'Critical':
            return QSystemTrayIcon.Critical
        return QSystemTrayIcon.Information


    # function for showing queued tray messages
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

# main function that sets up all the ui elements on startup
def InitAnimationsUI(self):
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

    # initilize attack pie chart in GUI
    AttackPieChart.InitAttackPieChart(self)

    # initilize report preview table view and initialize selected attacks and time filter
    InitReportTableView(self)

    # disable selection on history table
    DisableSelectionHistoryTableWidget(self)

    # hide side bar labels and icons and toggle user interface
    HideSideBarLabels(self)
    ShowSideBarMenuIcon(self)
    ToggleUserInterface(self, False)

    # apply shadow to the left side bar
    ApplyShadowSidebar(self)

    # add a context menu to items that are in the mac address list widget on Settings Page
    self.ui.macAddressListWidget.setContextMenuPolicy(Qt.CustomContextMenu)
    self.ui.macAddressListWidget.customContextMenuRequested.connect(lambda position : ShowContextMenu(self, position))

    # set the toggle password visability icon in the login and register
    icon = QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'EyeOpen.png'))
    self.ui.loginEyeButton = self.ui.loginPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.ui.loginEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.loginPasswordLineEdit, self.ui.loginEyeButton))
    self.ui.registerEyeButton = self.ui.registerPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.ui.registerEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.registerPasswordLineEdit, self.ui.registerEyeButton))

    # set the toggle password cisability icon in the settings page for change password section
    self.ui.oldPasswordEyeButton = self.ui.oldPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.ui.oldPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.oldPasswordLineEdit, self.ui.oldPasswordEyeButton))
    self.ui.newPasswordEyeButton = self.ui.newPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.ui.newPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.newPasswordLineEdit, self.ui.newPasswordEyeButton))
    self.ui.confirmPasswordEyeButton = self.ui.confirmPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.ui.confirmPasswordEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.ui.confirmPasswordLineEdit, self.ui.confirmPasswordEyeButton))

    # hide the error messages in the settings page
    self.ui.saveEmailErrorMessageLabel.hide()
    self.ui.saveUsernameErrorMessageLabel.hide()
    self.ui.savePasswordErrorMessageLabel.hide()
    self.ui.macAddressBlacklistErrorMessageLabel.hide()

#--------------------------------------------MAIN-FUNCTION-END-----------------------------------------------#