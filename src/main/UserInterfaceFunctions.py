from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QEasingCurve, QTimer, QSortFilterProxyModel, QAbstractTableModel, QModelIndex
from PyQt5.QtWidgets import QGraphicsDropShadowEffect, QApplication, QAction, QMenu, QTableWidget, QWidget, QGridLayout, QLineEdit, QHeaderView, QMessageBox, QSystemTrayIcon, QDesktopWidget, QDialog, QLabel, QPushButton, QVBoxLayout, QHBoxLayout
from PyQt5.QtGui import QColor, QIcon, QPixmap, QFont, QCursor, QPainter
from PyQt5.QtChart import QChart, QChartView, QPieSeries
from datetime import datetime, timedelta
from pathlib import Path

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located

#-------------------------------------------ANIMATION-FUNCTIONS----------------------------------------------#

# function for openning the left sideframe with an animation
def OpenSideFrame(self):
    animation = QPropertyAnimation(self.sideFrame, b'minimumWidth')
    animation.setDuration(500)
    animation.setEasingCurve(QEasingCurve.InOutQuad)
    animation.setStartValue(70)
    animation.setEndValue(210)
                
    # start the animation
    animation.start()

    # show sidebar labels
    self.menuIcon.hide()
    self.closeMenuIcon.show()
    self.homePageLabel.show()
    self.reportLabel.show()
    self.infoLabel.show()

    # store the animation reference
    self.sideFrame.currentAnimation = animation


# function for closing the left sideframe with an animation
def CloseSideFrame(self):
    # create animation for minimumWidth
    animation = QPropertyAnimation(self.sideFrame, b'minimumWidth')
    animation.setDuration(500)
    animation.setEasingCurve(QEasingCurve.OutQuad)
    animation.setStartValue(210)
    animation.setEndValue(70)
    
    # start the animation
    animation.start()

    # add delayed animations to icons and labels
    QTimer.singleShot(100, lambda: HideSideBarLabels(self))
    QTimer.singleShot(400, lambda: ShowSideBarMenuIcon(self))
    self.sideFrame.setMaximumWidth(70)
    self.menuIcon.setFixedWidth(50)
    
    # store the animation reference
    self.sideFrame.currentAnimation = animation


# function for opening the login/register side frame after clicking the account icon
def AccountIconClicked(self):
    # create animation object for the frame
    animation = QPropertyAnimation(self.loginRegisterVerticalFrame, b'maximumWidth')
    animation.setDuration(500) #duration in milliseconds (500ms = 0.5 seconds)
    animation.setEasingCurve(QEasingCurve.InOutQuad) #smooth easing curve
    
    if self.loginRegisterVerticalFrame.width() == 0: #fade in animation
        animation.setStartValue(0)
        animation.setEndValue(303)
        self.loginUsernameLineEdit.setFocus() if self.loginFrame.isVisible() else self.registerEmailLineEdit.setFocus()
    else: #fade out animation
        animation.setStartValue(303)
        animation.setEndValue(0)
        self.loginUsernameLineEdit.clearFocus()
        self.registerEmailLineEdit.clearFocus()

    
    # start the animation
    animation.start()
    ApplyShadowLoginRegister(self)

    # keep the animation object alive by storing it
    self.loginRegisterVerticalFrame.currentAnimation = animation


# function for changing between the login and register sideframes
def SwitchBetweenLoginAndRegister(self, showRegister=True):
    # first animation: Close the frame
    anim1 = QPropertyAnimation(self.loginRegisterVerticalFrame, b'maximumWidth')
    anim1.setDuration(200)
    anim1.setEasingCurve(QEasingCurve.InOutQuad)
    
    # use the current width as the start value
    currentWidth = self.loginRegisterVerticalFrame.width()
    anim1.setStartValue(currentWidth)
    anim1.setEndValue(0)
    
    # start the first animation and chain the second animation to start after the first finishes
    anim1.start()
    self.loginRegisterVerticalFrame.currentAnimation = anim1
    anim1.finished.connect(lambda: ReopenRegistryFrame(self, showRegister)) 


# this is the second animation and visibility switch for the login register side frame
def ReopenRegistryFrame(self, showRegister):
    # switch visibility
    if showRegister:
        self.loginFrame.hide()
        self.registerFrame.show()
        self.loginUsernameLineEdit.clearFocus()
        self.registerEmailLineEdit.setFocus()
    else:
        self.registerFrame.hide()
        self.loginFrame.show()
        self.loginUsernameLineEdit.setFocus()
        self.registerEmailLineEdit.clearFocus()
    
    # second animation: Open the frame
    anim2 = QPropertyAnimation(self.loginRegisterVerticalFrame, b'maximumWidth')
    anim2.setDuration(375)
    anim2.setEasingCurve(QEasingCurve.InOutQuad)
    anim2.setStartValue(0)
    anim2.setEndValue(303)
    anim2.start()
    self.loginRegisterVerticalFrame.currentAnimation = anim2

#-----------------------------------------ANIMATION-FUNCTIONS-END--------------------------------------------#

#---------------------------------------------CLICK-FUNCTIONS------------------------------------------------#

# helper function for hiding some labels
def HideSideBarLabels(self):
    self.homePageLabel.hide()
    self.reportLabel.hide()
    self.infoLabel.hide()


# helper function for showing some icons
def ShowSideBarMenuIcon(self):
    self.menuIcon.show()
    self.closeMenuIcon.hide()


# helper function for showing and hiding user interface
def ToggleUserInterface(self, state):
    # if true we need to show user logged in labels
    if state:
        self.accountIcon.hide()
        self.reportDurationComboBox.setEnabled(True)
        self.welcomeLabel.show()
        self.logoutIcon.show()
        ShowSettingsInputFields(self)

    # else we hide user labels
    else:
        HideSettingsInputFields(self)
        self.logoutIcon.hide()
        self.welcomeLabel.hide()
        self.reportDurationComboBox.setEnabled(False)
        self.welcomeLabel.clear()
        self.accountIcon.show()

    #clear history and report tables and blacklist and pie chart
    self.historyTableWidget.setRowCount(0)
    self.reportPreviewTableModel.ClearReportTable()
    self.macAddressListWidget.clear()
    ResetChartToDefault(self) #reset our pie chart

    #set combobox and checkboxes default state
    self.reportDurationComboBox.setCurrentIndex(3)
    self.colorModeComboBox.setCurrentIndex(0)
    self.arpSpoofingCheckBox.setChecked(True)
    self.portScanningCheckBox.setChecked(True)
    self.denialOfServiceCheckBox.setChecked(True)
    self.dnsTunnelingCheckBox.setChecked(True)
    self.machineInfoCheckBox.setChecked(False)

    #clear settings, login and register line edits and reset number of detections
    self.numberOfDetectionsCounter.setText('0')
    self.emailLineEdit.clear()
    self.usernameLineEdit.clear()
    self.oldPasswordLineEdit.clear()
    self.newPasswordLineEdit.clear()
    self.confirmPasswordLineEdit.clear()
    self.macAddressLineEdit.clear()
    self.loginUsernameLineEdit.clear()
    self.loginPasswordLineEdit.clear()
    self.registerEmailLineEdit.clear()
    self.registerUsernameLineEdit.clear()
    self.registerPasswordLineEdit.clear()
    self.saveEmailErrorMessageLabel.clear()
    self.saveUsernameErrorMessageLabel.clear()
    self.savePasswordErrorMessageLabel.clear()
    self.macAddressBlacklistErrorMessageLabel.clear()
    ToggleReportInterface(self, False)
    self.registerEmailLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits('registerEmailLineEdit'))
    self.registerUsernameLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits('registerUsernameLineEdit'))
    self.registerPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits('registerPasswordLineEdit'))
    self.oldPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits('oldPasswordLineEdit'))
    self.newPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits('newPasswordLineEdit'))
    self.confirmPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits('confirmPasswordLineEdit'))


# helper function for showing and hiding report interface
def ToggleReportInterface(self, state):
    # if true we need to show report interface
    if state:
        self.downloadReportPushButton.hide()
        self.cancelReportPushButton.show()
        self.reportProgressBar.setValue(0)
        self.reportProgressBar.show()
    # else we hide report interface
    else:
        self.reportProgressBar.hide()
        self.reportProgressBar.setValue(0)
        self.cancelReportPushButton.hide()
        self.downloadReportPushButton.show()


# helper function for chaning the current page index on the stack widget
def ChangePageIndex(self, index):
    # clear focus from all line edits
    self.emailLineEdit.clearFocus()
    self.usernameLineEdit.clearFocus()
    self.oldPasswordLineEdit.clearFocus()
    self.newPasswordLineEdit.clearFocus()
    self.confirmPasswordLineEdit.clearFocus()
    self.macAddressLineEdit.clearFocus()
    self.stackedWidget.setCurrentIndex(index)


# function for toggling the password visibility using an icon
def TogglePasswordVisibility(lineEditWidget, eyeIcon):
    openEyePath = currentDir.parent / 'interface' / 'Icons' / 'EyeOpen.png'
    closedEyePath = currentDir.parent / 'interface' / 'Icons' / 'EyeClosed.png'
    if lineEditWidget.echoMode() == QLineEdit.Password:
        lineEditWidget.setEchoMode(QLineEdit.Normal) #show the password
        eyeIcon.setIcon(QIcon(str(closedEyePath))) #change to open eye icon
    else:
        lineEditWidget.setEchoMode(QLineEdit.Password) #hide the password
        eyeIcon.setIcon(QIcon(str(openEyePath))) #change to closed eye icon


#-------------------------------------------CLICK-FUNCTIONS-END----------------------------------------------#

#---------------------------------------------OTHER-FUNCTIONS------------------------------------------------#

# function for adding a box shadow to the login/register side popup frame
def ApplyShadowLoginRegister(self):
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(15) #no blur, sharp shadow (like blur: 0 in CSS)
    shadow.setXOffset(-8) #horizontal offset: -15px (left)
    shadow.setYOffset(0) #vertical offset: 10px (down)
    shadow.setColor(QColor(0, 0, 0, 85)) #RGBA(56, 60, 170, 0.5) -> alpha 0.5 = 128/255
    self.loginRegisterVerticalFrame.setGraphicsEffect(shadow)


# function for adding a box shadow to the left side bar
def ApplyShadowSidebar(self):
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(5) # No blur, sharp shadow (like blur: 0 in CSS)
    shadow.setXOffset(5) # Horizontal offset: -15px (left)
    shadow.setYOffset(0) # Vertical offset: 10px (down)
    shadow.setColor(QColor(0, 0, 0, 50)) # RGBA(56, 60, 170, 0.5) -> alpha 0.5 = 128/255
    self.sideFrame.setGraphicsEffect(shadow)


# function that shows right-click menu for copying and deleting items in mac
def ShowContextMenu(self, position):
    if self.macAddressListWidget.count() == 0:
        return #do nothing if there are no items

    item = self.macAddressListWidget.itemAt(position)
    if item:
        menu = QMenu()
        copyAction = QAction('Copy')
        copyAction.triggered.connect(lambda: CopyToClipboard(item.text()))
        deleteAction = QAction('Delete')
        deleteAction.triggered.connect(lambda: self.DeleteMacAddressButtonClicked(item))
        menu.addAction(copyAction)
        menu.addAction(deleteAction)
        menu.exec_(self.macAddressListWidget.viewport().mapToGlobal(position))


# function that copies the item text to the clipborad
def CopyToClipboard(text):
    clipboard = QApplication.clipboard()  
    clipboard.setText(text)
    

# function the removes an item 
def RemoveItem(self, item):
    self.macAddressListWidget.takeItem(self.macAddressListWidget.row(item))


# function for centering a specific row in the tabels:
def CenterSpecificTableRowText(tableObject): #tableObject = self.historyTableWidget  or  self.reportPreviewTableWidget
    for col in range(tableObject.columnCount()):
        if item := tableObject.item(0, col): #check if item exists
            item.setTextAlignment(Qt.AlignCenter)
            cellText = item.text()
            tooltipText = cellText if cellText else 'Empty cell'
            item.setToolTip(tooltipText)


# helper function for setting the items in the list of ip addresses to not interactable, it removes the hover and click effects
def DisableSelectionIpListWidget(self):
    # disable selection on ip address list widget
    for row in range(self.ipAddressesListWidget.count()):
        item = self.ipAddressesListWidget.item(row)
        item.setFlags(item.flags() & ~Qt.ItemIsSelectable & ~Qt.ItemIsEnabled)


# helper function for setting the text of an error message like login/register/change email/ etc.
def ChangeErrorMessageText(errorMessageObject, message):
    errorMessagePrefix = '<p style="line-height: 0.7;">'
    errorMessageSuffix = '</p>'
    errorMessageObject.setText(errorMessagePrefix + message + errorMessageSuffix)
    errorMessageObject.show()


# helper fucntion for clearing error message of error message label
def ClearErrorMessageText(errorMessageObject):
    errorMessageObject.setText('')
    errorMessageObject.hide()


# hide the change email, username, password and color mode from settings page 
def HideSettingsInputFields(self):
    self.settingsChangeVerticalFrame.hide()
    self.deleteAccoutPushButton.hide()
    self.settingsInterfaceMacButtonsVerticalFrame.setContentsMargins(40, 0, 0, 0) 


# show the change email, username, password and color mode from settings page 
def ShowSettingsInputFields(self):
    self.settingsChangeVerticalFrame.show()
    self.deleteAccoutPushButton.show()
    self.settingsInterfaceMacButtonsVerticalFrame.setContentsMargins(0, 10, 0, 0) #returning the default values


# helper function for returning the default style sheet of the line edits in the settings page
def GetDefaultStyleSheetSettingsLineEdits(lineEditName):
    defaultStylesheet = f''' 
        #{lineEditName} {{
            background-color: #f0f0f0;
            border: 2px solid lightgray;
            border-radius: 10px;
            padding: 5px;
            color: black;
            {'margin: 0px 0px 10px 0px;' if (('old' in lineEditName) or ('new' in lineEditName)) else 'margin: 0px 0px 0px 0px;'}
        }}
    '''
    return defaultStylesheet


# helper function for returning the default style sheet of the line edits in register
def GetDefaultStyleSheetRegisterLineEdits(lineEditName):
    defaultStylesheet = f''' 
        #{lineEditName} {{
            background-color: #f0f0f0;
            border: 2px solid lightgray;
            border-radius: 10px;
            padding: 5px;
            color: black;
            {'margin: 0px 5px 0px 5px;' if ('Password' in lineEditName) else 'margin: 0px 5px 10px 5px;'}
        }}
    '''
    return defaultStylesheet

#-------------------------------------------OTHER-FUNCTIONS-END----------------------------------------------#

#----------------------------------------------POPUP-WINDOW--------------------------------------------------#

# custom popup message box class that will be used to show error messages to the user at certain times
class CustomMessageBox(QDialog):
    isShown = False #represents flag for indicating if popup is shown

    # constructor that gets the title, message and icon type (will be shown inside) of the message box pop up window
    def __init__(self, title, message, iconType):
        super().__init__()

        # setting the title and message
        self.setWindowTitle(title)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setGeometry(0, 0, 0, 0)

        # set the popup window icon
        self.setWindowIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))

        # create the main layout (vertical)
        layout = QVBoxLayout()

        # create a horizontal layout for the icon and message
        horizontalLayout = QHBoxLayout()

        # get the built-in icon using QMessageBox
        iconLabel = QLabel()
        icon = self.GetBuiltInIcon(iconType) #use the method to get the icon
        
        # handle the icon (it might return a QPixmap or QIcon depending on Qt version)
        if isinstance(icon, QPixmap):
            pixmap = icon.scaled(32, 32, Qt.KeepAspectRatio)
        else:
            pixmap = icon.pixmap(32, 32)
        iconLabel.setPixmap(pixmap)
        iconLabel.setContentsMargins(15, 0, 15, 0)
        iconLabel.setAlignment(Qt.AlignCenter) #center the icon vertically

        # set the message
        messageLabel = QLabel(message)
        messageLabel.setWordWrap(True) #ensure long messages wrap properly
        messageLabel.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter) #vertically center the text
        messageLabel.setContentsMargins(0, 0, 0, 0)

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
            okButton.clicked.connect(self.reject)
            buttonLayout.addWidget(okButton)

        # apply layout to the dialog
        layout.addLayout(buttonLayout)
        self.setLayout(layout)

        # set dialog properties (non-resizable but sized to content)
        self.setMinimumSize(350, 150) #set a reasonable minimum size
        self.adjustSize() #adjust the size based on content
        self.setFixedSize(self.size()) #lock the size to prevent resizing

        # set custom stylesheet
        self.setStyleSheet('''
            QDialog {
                background-color: #f3f3f3;
            }
                        
            QLabel {
                color: black;
                font-size: 16px;
            }

            QLabel[alignment='Qt::AlignVCenter|Qt::AlignLeft'] {
                margin-left: 10px;
            }
                        
            QPushButton {
                background-color: #3a8e32; 
                border: 1px solid black;  
                border-radius: 10px;         
                padding: 5px;              
                font-size: 14px; 
                font-weight: bold;          
                color: #f3f3f3;   
                min-width: 80px;  
            }
                           
            QPushButton:hover {
                background-color: #4D9946;
            }
                           
            QPushButton:pressed {
                background-color: #2E7128;
            }
                        
            QPushButton[text='No']  {
                background-color: #D84F4F; 
                border: 1px solid black;  
                border-radius: 10px;         
                padding: 5px;              
                font-size: 14px; 
                font-weight: bold;          
                color: #f3f3f3;    
                min-width: 80px;    
            }
                           
            QPushButton[text='No']:hover {
                background-color: #DB6060;
            }
                           
            QPushButton[text='No']:pressed {
                background-color: #AC3f3F;
            }
        ''')
    

    # overriting the original reject function for when the user closes the popup window to add some new functionality
    def reject(self):
        CustomMessageBox.isShown = False
        super().reject() 
    

    # helper fucntion to map the iconType to the appropriate built-in QIcon
    def GetBuiltInIcon(self, iconType):
        icon = QMessageBox.standardIcon(QMessageBox.Information)
        if iconType == 'Warning':
            icon = QMessageBox.standardIcon(QMessageBox.Warning)
        elif iconType == 'Critical':
            icon = QMessageBox.standardIcon(QMessageBox.Critical)
        elif iconType == 'Question':
            icon = QMessageBox.standardIcon(QMessageBox.Question)
        return icon


# helper function to show a popup window
def ShowPopup(title, message, iconType='Warning'):
    #iconType options are: Information, Warning, Critical, Question
    if not CustomMessageBox.isShown:
        popup = CustomMessageBox(title, message, iconType)

        # center the popup window
        cp = QDesktopWidget().availableGeometry()
        qr = popup.frameGeometry()
        centerPosition = cp.center() - qr.center()
        popup.move(centerPosition) #move to the center

        # set isShown and show messagebox
        CustomMessageBox.isShown = True
        result = popup.exec_()

        # return result value for question messagebox, else none
        return result == QDialog.Accepted if iconType == 'Question' else None

#---------------------------------------------POPUP-WINDOW-END-----------------------------------------------#

#------------------------------------------------PIE-CHART---------------------------------------------------#

# dictionary for mapping attack names, key is the slice label text and the value is the legend text
pieChartLabelDict = {
    'ARP': 'ARP Spoofing',
    'Port Scan': 'Port Scanning',
    'DoS': 'Denial of Service',
    'DNS': 'DNS Tunneling'
}

# inverted dictionary for mapping attack names, key is the attack name as seen by database and the value is attack names as written in pie chart legends
invertedPieChartLabelDict = {
    'ARP Spoofing': 'ARP',
    'Port Scan': 'Port Scan',
    'DoS': 'DoS',
    'DNS Tunneling': 'DNS'
}

# dictionary with default blue colors for the pie chart slices for each attack by name
defaultPieChartSliceColors = {
    'ARP Spoofing': '#90cfef',
    'Port Scan': '#209fdf',
    'DoS': '#15668f',
    'DNS Tunneling': '#092d40'
}

# function for creating and initializing an empty pie chart
def InitPieChart(self):
    try:
        # create pie chart
        series = QPieSeries()
        chart = QChart()
        chart.addSeries(series)

        # create font for title
        titleFont = QFont('Cairo', 16, QFont.Bold, False) 

        # create a legend widget
        legendWidget = QWidget()
        self.legendLayout = QGridLayout(legendWidget)
        legendWidget.setStyleSheet('''
            background-color: transparent;
            color: black;
            border-top: 1px solid black;
        ''')

        # setup the base chart widget
        chart.legend().setVisible(False)
        chart.layout().setContentsMargins(0, 0, 0, 0)
        chart.setBackgroundRoundness(0)
        chart.setBackgroundBrush(QColor(204, 204, 204, 153)) 
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
        titleLabel.setStyleSheet('''       
            QLabel {
                background-color: transparent;
                color: black;
                font-size: 24px;
                font-family: Cairo;
                font-weight: bold;
                padding: 0px;
                padding-left: 5px;
                margin: 0px;
            }
        ''')

        # setup the pie chart legends in advance
        for i, (attackName, sliceColor) in enumerate(zip(pieChartLabelDict.values(), defaultPieChartSliceColors.values())):
            legendFont = QFont('Cairo', 12, QFont.Bold, False) # font settings for legend (defined once)
            legendLabel = QLabel(f'{attackName} 0%')
            legendLabel.setFont(legendFont)
            legendLabel.setStyleSheet('''padding-left: 5px; background-color: transparent; border: none;''')
            legendLabel.setObjectName(f'{attackName.replace(' ', '')}LegendLabel') #for example: ARPSpoofingLegendLabel
            
            colorLabel = QLabel()
            colorLabel.setFixedSize(20, 20)
            colorLabel.setStyleSheet(f'background-color: {sliceColor}; border: 1px solid black;')

            row = i // 2
            col = (i % 2) * 2
            self.legendLayout.addWidget(colorLabel, row, col)
            self.legendLayout.addWidget(legendLabel, row, col + 1)

        # add items to the chart VBox
        VBoxLayout.addWidget(titleLabel)
        VBoxLayout.addWidget(chartView)
        VBoxLayout.addWidget(legendWidget)

        # save the chart object in self (NetSpect object) for later use
        self.chartVerticalFrame.setLayout(VBoxLayout)
        self.chartVerticalFrame.update()
        self.piChart = chart

    except Exception as e:
        ShowPopup('Error In Pie Chart Initialization', 'Error occurred in pie chart initialization, try again later.', 'Critical')


# function for updating the pie chart after an attack was detected, expects an attack name like: ARP, DNS, Port Scan, DoS
def UpdateChartAfterAttack(self, attackName):
    try:
        correctAttackName = invertedPieChartLabelDict.get(attackName)
        series = self.piChart.series()[0]

        # increment the value of the attack slice based on given attack name
        found = False
        for slice in series.slices():
            if correctAttackName in slice.label():  
                slice.setValue(slice.value() + 1)
                found = True
                break
        
        # if slice does not exist, then create a new slice and add it to the pie chart
        if not found:
            sliceFont = QFont('Cairo', 11, QFont.Bold, False)
            newSlice = series.append(correctAttackName, 1)
            newSlice.setLabelFont(sliceFont)
            newSlice.setLabelVisible(True)
            newSlice.setLabelArmLengthFactor(0.075)
            newSlice.setLabel(f'{correctAttackName} {newSlice.percentage()*100:.1f}%')
            newSlice.setLabelColor(QColor(1, 1, 1, 255))
            newSlice.setColor(QColor(defaultPieChartSliceColors.get(attackName)))

        # set the title to be empty (hide the title) if there is atleast one attack detection in history
        if series.count() > 0:
            self.piChart.setTitle('')
        
        UpdateChartLegendsAndSlices(self) #update the text data of legends and slice labels

    except Exception as e:
        ShowPopup('Error Updating Pie Chart', 'Error occurred while updating pie chart, try again later.', 'Critical')

    
# helper function for updating the text of the pie chart legends and slice labels
def UpdateChartLegendsAndSlices(self):
    try:
        series = self.piChart.series()[0] #get the pie chart object
        
        # update the legend and slice text for all slices
        for slice in series.slices():
            # update the slice text with correct values
            sliceSplit = slice.label().split(' ')
            sliceAttackName = ' '.join([sliceSplit[0], sliceSplit[1]]) if 'Port' in sliceSplit[0] else sliceSplit[0]
            slice.setLabel(f'{sliceAttackName} {slice.percentage()*100:.1f}%')

            # update the legend text to match current slice
            legendLabelText = f'{pieChartLabelDict.get(sliceAttackName)} {slice.percentage()*100:.1f}%'
            legendLabelName = f'{pieChartLabelDict.get(sliceAttackName).replace(' ', '')}LegendLabel' 
            legendLabelObject = self.findChild(QLabel, legendLabelName)
            legendLabelObject.setText(legendLabelText)

    except Exception as e:
        ShowPopup('Error Updating Pie Chart', 'Error occurred while updating pie chart, try again later.', 'Critical')


# function for updating the pie chart after user login with data from database
def UpdateChartAfterLogin(self, pieChartData):
    try:
        # remove the current series
        series = self.piChart.series()[0]
        self.piChart.removeSeries(series)

        # create a new series with database data
        newSeries = QPieSeries()
        for attackName, attackCount in pieChartData.items():
            newSeries.append(attackName, attackCount)

        # add the new series to the chart and update the GUI
        self.piChart.addSeries(newSeries)
        self.piChart.setTitle('') #remove the default title if exists
        if all(attackCount == 0 for attackCount in pieChartData.values()):
            self.piChart.setTitle('No Data To Display...') #leave the default title if there is no data to display
        UpdateChartLegendsAndSlices(self)

        # update the css of the slice labels because we created new ones right here
        for slice, attackName in zip(self.piChart.series()[0].slices(), pieChartData.keys()):
            sliceFont = QFont('Cairo', 11, QFont.Bold, False)
            slice.setLabelFont(sliceFont)
            slice.setLabelVisible(True)
            slice.setLabelArmLengthFactor(0.075)
            slice.setLabelColor(QColor(1, 1, 1, 255))
            slice.setColor(QColor(defaultPieChartSliceColors.get(attackName)))

    except Exception as e:
        ShowPopup('Error Updating Pie Chart', 'Error occurred while updating pie chart, try again later.', 'Critical')


# function for clearing the pie chart and resetting to default empty pie chart
def ResetChartToDefault(self):
    try:
        # clear the pie chart data and show the default title
        self.piChart.series()[0].clear()
        self.piChart.setTitle('No Data To Display...')

        # update the legend text and set it to the default values of 0%
        for attackName in pieChartLabelDict.keys():
            legendLabelText = f'{pieChartLabelDict.get(attackName)} 0%'
            legendLabelName = f'{pieChartLabelDict.get(attackName).replace(' ', '')}LegendLabel' 
            legendLabelObject = self.findChild(QLabel, legendLabelName)
            legendLabelObject.setText(legendLabelText)

    except Exception as e:
        ShowPopup('Error Clearing Pie Chart', 'Error occurred while clearing pie chart, try again later.', 'Critical')

#----------------------------------------------PIE-CHART-END-------------------------------------------------#

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
        if role == Qt.TextAlignmentRole:
            return Qt.AlignCenter 
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
                return True
        return False


    # helper function to add rows to the table at the top of the table every time
    def AddRowToReportTable(self): 
        self.beginInsertRows(QModelIndex(), 0, 0) #correctly notify start of insert
        self.alertListData.insert(0, [None] * self.columnCount()) #add new row at the start
        self.endInsertRows()
        return 0


    # helper function to add items to a given row by index
    def SetRowItemReportTable(self, row, column, value):
        # set data at specific row and column
        index = self.index(row, column)
        self.setData(index, value)


    # helper function to clear out the data from the table
    def ClearReportTable(self):
        self.beginResetModel()
        self.alertListData.clear() #clear the data list
        self.endResetModel()


# Custom Proxy Model for filtering the TableView that is in the report page, this class will hold the filtering logic and functions
class CustomFilterProxyModel(QSortFilterProxyModel):
    # represents our  alertList columns of our table
    alertListColumns = [('interface', 0), ('attackType', 1), ('srcIp', 2), ('srcMac', 3), ('dstIp', 4),
                        ('dstMac', 5), ('protocol', 6), ('osType', 8), ('timestamp', 7)]
    selectedAttacks = set() #stores selected attacks by checkboxes
    timeFilter = None #represents time combobox filther option

    # constructor of filter proxy class
    def __init__(self, parent=None):
        super().__init__(parent)
        self.timeFilter = 'All Available Data' #set to all available data by default


    # update selected classes and refresh filter (for checkboxes)
    def SetSelectedAttacks(self, selectedAttacks):
        self.selectedAttacks = set(selectedAttacks)
        self.invalidateFilter() #triggers re-filtering


    # update time filter and refresh the table (for combobox)
    def SetTimeFilter(self, timeFilter):
        self.timeFilter = timeFilter
        self.invalidateFilter()


    # determines if a row should be shown based on filter conditions
    def filterAcceptsRow(self, sourceRow, sourceParent):
        model = self.sourceModel()

        # get timestamp and attack type row data
        timestampValue = model.data(model.index(sourceRow, 7), Qt.DisplayRole) #column 7 = Timestamp
        attackTypeValue = model.data(model.index(sourceRow, 1), Qt.DisplayRole) #column 1 = Attack Type
        
        # validate that the data the this method gets is valid before continuing with the filter
        if timestampValue == 'None' or attackTypeValue == 'None':
            return False

        # convert timestamp string to datetime object and get current time to check the filter
        rowTimestamp = datetime.strptime(timestampValue, '%H:%M:%S %d/%m/%y')
        currentTime = datetime.now()

        # time filtering logic, if the combobox is selected with 'All Available Data' then it will skip the time filter
        if self.timeFilter == 'Last 24 Hours' and rowTimestamp < currentTime - timedelta(days=1):
            return False
        if self.timeFilter == 'Last 7 Days' and rowTimestamp < currentTime - timedelta(days=7):
            return False
        if self.timeFilter == 'Last 30 Days' and rowTimestamp < currentTime - timedelta(days=30):
            return False

        # attack filtering logic by attack checkboxes
        if not self.selectedAttacks or attackTypeValue not in self.selectedAttacks:
            return False #dont show the row if it did not pass one of the filters

        return True #show current row if it passed all filters


# helper function that will be called when the user clicks on one of the attack checkboxes in the report page (ARP, Port, DoS, DNS)
def ReportCheckboxToggled(self):
    selectedAttacks = set() #represents a set of all selected attack checkboxes at this point in time

    # checking each checkbox if its clicked or not
    if self.arpSpoofingCheckBox.isChecked():
        selectedAttacks.add('ARP Spoofing')
    if self.portScanningCheckBox.isChecked():
        selectedAttacks.add('Port Scan')
    if self.denialOfServiceCheckBox.isChecked():
        selectedAttacks.add('DoS')
    if self.dnsTunnelingCheckBox.isChecked():
        selectedAttacks.add('DNS Tunneling')

    # passing the selected attacks set to a method that will filter the table view with the current selection of attacks
    self.proxyReportPreviewTableModel.SetSelectedAttacks(selectedAttacks)


# helper function that will be called when the user selects a different time fillter option in the report page (combobox)
def ReportDurationComboboxChanged(self):
    self.proxyReportPreviewTableModel.SetTimeFilter(self.reportDurationComboBox.currentText())


# helper function for getting flitered alert list from proxy model
def GetFilteredAlerts(self):
    filteredAlertList = []
    
    # iterate over each filtered row from the proxy model
    for row in range(self.proxyReportPreviewTableModel.rowCount()):
        alert = {} #represents our current alert in row

        # iterate over each iltered column from the proxy model
        for header, col in self.proxyReportPreviewTableModel.alertListColumns:
            # get the index from the proxy model
            index = self.proxyReportPreviewTableModel.index(row, col)
            alert[header] = self.proxyReportPreviewTableModel.data(index, Qt.DisplayRole)
        filteredAlertList.append(alert)

    return filteredAlertList


# helper function for initializing the table view in the report page when the application loads up
def InitReportTableView(self):
    # initialize the Table View and custom table filter
    self.reportPreviewTableModel = CustomTableModel(self.userData.get('alertList'))
    self.proxyReportPreviewTableModel = CustomFilterProxyModel()
    self.proxyReportPreviewTableModel.setSourceModel(self.reportPreviewTableModel)

    # change some of the table attributes to make it look how we want it
    self.reportPreviewTableView.setModel(self.proxyReportPreviewTableModel)
    self.reportPreviewTableView.setColumnHidden(self.reportPreviewTableModel.columnCount() - 1, True) #hide osType column
    self.reportPreviewTableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) #distribute column widths equally
    self.reportPreviewTableView.verticalHeader().setDefaultSectionSize(30) #set max row height to 30px
    self.reportPreviewTableView.verticalHeader().setSectionResizeMode(QHeaderView.Fixed) #fix row heights
    self.reportPreviewTableView.verticalHeader().setStretchLastSection(False) #don't stretch last row
    self.reportPreviewTableView.setTextElideMode(Qt.ElideMiddle)
    self.reportPreviewTableView.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.reportPreviewTableView.setFocusPolicy(Qt.NoFocus)
    self.reportPreviewTableView.setEditTriggers(QTableWidget.NoEditTriggers)
    self.reportPreviewTableView.setSortingEnabled(False)

#------------------------------------------TABLE-VIEW-FILTER-END---------------------------------------------#

#---------------------------------------------SYSTEM-TRAY-ICON-----------------------------------------------#

# method for initializing system tray icon for various alert messages
def InitTrayIcon(self):
    # check if system tray is available
    if QSystemTrayIcon.isSystemTrayAvailable():
        # create tray icon
        self.trayIcon = QSystemTrayIcon(self)
        self.trayIcon.setIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))
        self.trayIcon.setVisible(True)

        # set hover tooltip for the tray icon
        self.trayIcon.setToolTip('NetSpect™ IDS')

        # initialize context menu for the tray icon
        trayMenu = QMenu()

        # start/stop detection
        self.toggleDetection = QAction('Start Detection', self)
        self.toggleDetection.triggered.connect(lambda event: ToggleDetection(self))
        trayMenu.addAction(self.toggleDetection)

        # open homepage page
        self.openHomepageAction = QAction('Homepage', self)
        self.openHomepageAction.triggered.connect(lambda event: ChangePageIndex(self, 0))
        trayMenu.addAction(self.openHomepageAction)

        # open report preview page
        self.openReportPreviewAction = QAction('Report Preview', self)
        self.openReportPreviewAction.triggered.connect(lambda event: ChangePageIndex(self, 1))
        trayMenu.addAction(self.openReportPreviewAction)

        # open information page
        self.openInformationAction = QAction('Information', self)
        self.openInformationAction.triggered.connect(lambda event: ChangePageIndex(self, 2))
        trayMenu.addAction(self.openInformationAction)

        # open settings page
        self.openSettingsAction = QAction('Settings', self)
        self.openSettingsAction.triggered.connect(lambda event: ChangePageIndex(self, 3))
        trayMenu.addAction(self.openSettingsAction)

        # exit application
        self.exitAction = QAction('Exit', self)
        self.exitAction.triggered.connect(lambda event: self.close())
        trayMenu.addAction(self.exitAction)

        # attach context menu to the tray icon
        self.trayIcon.setContextMenu(trayMenu)


# method for starting or stopping detection
def ToggleDetection(self):
    # if detection active we stop it
    if self.isDetection:
        self.StartStopButtonClicked()
        self.toggleDetection.setText('Start Detection')
    # else means no detection active, we start new detection
    else:
        self.StartStopButtonClicked()
        self.toggleDetection.setText('Stop Detection')


# method for showing tray icon messages in operating system
def ShowTrayMessage(self, title, message, iconType='Information', duration=5000):
    icon = GetTrayIcon(self, iconType)
    self.trayIcon.showMessage(title, message, icon, duration)


# helper fucntion to map the iconType to the appropriate QSystemTrayIcon
def GetTrayIcon(self, iconType):
    icon = QSystemTrayIcon.Information
    if iconType == 'Warning':
        icon = QSystemTrayIcon.Warning
    elif iconType == 'Critical':
        icon = QSystemTrayIcon.Critical
    return icon

#-------------------------------------------SYSTEM-TRAY-ICON-END---------------------------------------------#

#----------------------------------------------MAIN-FUNCTION-------------------------------------------------#

# main function that sets up all the ui elements on startup
def InitAnimationsUI(self):
    # set initial width of elements
    self.loginRegisterVerticalFrame.setFixedWidth(0)
    self.registerFrame.hide()
    self.sideFrame.setFixedWidth(70)

    #initialize system tray icon
    InitTrayIcon(self)

    # initilize pie chart on screen
    InitPieChart(self)

    # initilize report preview table view and initialize selected attacks and time filter
    InitReportTableView(self)
    ReportDurationComboboxChanged(self)
    ReportCheckboxToggled(self)

    # hide some labels and icons
    HideSideBarLabels(self)
    ShowSideBarMenuIcon(self)
    ToggleUserInterface(self, False)

    # apply shadow to the left side bar
    ApplyShadowSidebar(self)

    # disable selection on ip address list widget
    DisableSelectionIpListWidget(self)

    # add a context menu to items that are in the mac address list widget on Settings Page
    self.macAddressListWidget.setContextMenuPolicy(Qt.CustomContextMenu)
    self.macAddressListWidget.customContextMenuRequested.connect(lambda position : ShowContextMenu(self, position))

    # disable selection on both history table and report preview table
    self.historyTableWidget.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.historyTableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
    self.historyTableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch) #distribute column widths equally
    self.historyTableWidget.setTextElideMode(Qt.ElideMiddle)

    # set the toggle password visability icon in the login and register
    openEyePath = currentDir.parent / 'interface' / 'Icons' / 'EyeOpen.png'
    icon = QIcon(str(openEyePath))
    self.loginEyeButton = self.loginPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.loginEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.loginPasswordLineEdit, self.loginEyeButton))
    self.registerEyeButton = self.registerPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.registerEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.registerPasswordLineEdit, self.registerEyeButton))

    # set the main window icon
    self.setWindowIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))

    # hide the error messages in the settings page
    self.saveEmailErrorMessageLabel.hide()
    self.saveUsernameErrorMessageLabel.hide()
    self.savePasswordErrorMessageLabel.hide()
    self.macAddressBlacklistErrorMessageLabel.hide()

#--------------------------------------------MAIN-FUNCTION-END-----------------------------------------------#