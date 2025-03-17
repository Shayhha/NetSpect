from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QEasingCurve, QTimer
from PyQt5.QtWidgets import QGraphicsDropShadowEffect, QApplication, QAction, QMenu, QTableWidget, QWidget, QGridLayout, QLineEdit, QMessageBox, QDesktopWidget, QDialog, QLabel, QPushButton, QVBoxLayout, QHBoxLayout
from PyQt5.QtGui import QColor, QIcon, QPixmap, QFont, QCursor, QPainter
from PyQt5.QtChart import QChart, QChartView, QPieSeries
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
        self.reportDurationComboBox.setCurrentIndex(0)
        self.welcomeLabel.show()
        self.logoutIcon.show()
        ShowSettingsInputFields(self)

    # else we hide user labels
    else:
        HideSettingsInputFields(self)
        self.logoutIcon.hide()
        self.welcomeLabel.hide()
        self.reportDurationComboBox.setCurrentIndex(3)
        self.reportDurationComboBox.setEnabled(False)
        self.welcomeLabel.clear()
        self.accountIcon.show()

    #clear history and report tables and blacklist and pie chart
    self.historyTableWidget.setRowCount(0)
    self.reportPreviewTableWidget.setRowCount(0)
    self.macAddressListWidget.clear()
    ResetChartToDefault(self) #reset our pie chart

    #set combobox and checkboxes default state
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
    self.registerEmailLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits('registerEmailLineEdit'))
    self.registerUsernameLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits('registerUsernameLineEdit'))
    self.registerPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetRegisterLineEdits('registerPasswordLineEdit'))
    self.oldPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits('oldPasswordLineEdit'))
    self.newPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits('newPasswordLineEdit'))
    self.confirmPasswordLineEdit.setStyleSheet(GetDefaultStyleSheetSettingsLineEdits('confirmPasswordLineEdit'))


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


# function for centering all the texts in every cell of all the tables in the ui
def CenterAllTableRowText(self): 
    # center all the text in the history table widget on Home Page
    for row in range(self.historyTableWidget.rowCount()):
        for col in range(self.historyTableWidget.columnCount()):
            if item := self.historyTableWidget.item(row, col): #check if item exists
                item.setTextAlignment(Qt.AlignCenter)
                cellText = item.text()
                tooltipText = cellText if cellText else 'Empty cell'
                item.setToolTip(tooltipText)

    self.historyTableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch) #distribute column widths equally
    self.historyTableWidget.setTextElideMode(Qt.ElideMiddle)

    # center all the text in the report preview table widget on Report Page
    for row in range(self.reportPreviewTableWidget.rowCount()):
        for col in range(self.reportPreviewTableWidget.columnCount()):
            if item := self.reportPreviewTableWidget.item(row, col): #check if item exists
                item.setTextAlignment(Qt.AlignCenter)
                cellText = item.text()
                tooltipText = cellText if cellText else 'Empty cell'
                item.setToolTip(tooltipText)

    self.reportPreviewTableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch) #distribute column widths equally
    self.reportPreviewTableWidget.setTextElideMode(Qt.ElideMiddle)


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
            font-size: 14px;            
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
            font-size: 14px;            
            color: black;             
            {'margin: 0px 5px 0px 5px;' if ('Password' in lineEditName) else 'margin: 0px 5px 10px 5px;'}
        }}
    '''
    return defaultStylesheet

#-------------------------------------------OTHER-FUNCTIONS-END----------------------------------------------#

#----------------------------------------------POPUP-WINDOW--------------------------------------------------#

# custom popup message box class that will be used to show error messages to the user at certain times
class CustomMessageBox(QDialog):
    isShown = False 

    # ctor that gets the title, message and icon type (will be shown inside) of the message box pop up window.
    def __init__(self, title, message, iconType):
        super().__init__()

        # setting the title and message
        self.setWindowTitle(title)
        self.setGeometry(0, 0, 0, 0)

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
        else:  # Assuming QIcon
            pixmap = icon.pixmap(32, 32)
        iconLabel.setPixmap(pixmap)
        iconLabel.setAlignment(Qt.AlignCenter) #center the icon vertically

        # set the popup window icon
        self.setWindowIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))

        # set the message
        messageLabel = QLabel(message)
        messageLabel.setWordWrap(True) #ensure long messages wrap properly
        messageLabel.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter) #vertically center the text
        messageLabel.setContentsMargins(0, 0, 0, 0)

        # add the icon and message to the horizontal layout with spacing
        horizontalLayout.addWidget(iconLabel)
        horizontalLayout.addSpacing(15) #add spacing between icon and text
        horizontalLayout.addWidget(messageLabel)
        horizontalLayout.setAlignment(Qt.AlignCenter) #center the entire horizontalLayout

        # add stretchable space around the horizontalLayout to center it vertically in the dialog
        layout.addStretch(1) #add stretch before the content
        layout.addLayout(horizontalLayout)
        layout.addStretch(1) #add stretch after the content

        # add buttons
        buttonLayout = QHBoxLayout()
        buttonLayout.setAlignment(Qt.AlignCenter) #center the buttons
        button = QPushButton('OK')
        button.setCursor(QCursor(Qt.PointingHandCursor))
        button.clicked.connect(self.reject)
        buttonLayout.addWidget(button)

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
                        
            QPushButton[text='OK']  {
                background-color: #3a8e32; 
                border: 1px solid black;  
                border-radius: 10px;         
                padding: 5px;              
                font-size: 14px; 
                font-weight: bold;          
                color: #f3f3f3;   
                min-width: 80px;  
            }
            QPushButton[text='OK']:hover {
                background-color: #4D9946;
            }
            QPushButton[text='OK']:pressed {
                background-color: #2E7128;
            }
                        
            QPushButton[text='Cancel']  {
                background-color: #D84F4F; 
                border: 1px solid black;  
                border-radius: 10px;         
                padding: 5px;              
                font-size: 14px; 
                font-weight: bold;          
                color: #f3f3f3;    
                min-width: 80px;    
            }
            QPushButton[text='Cancel']:hover {
                background-color: #DB6060;
            }
            QPushButton[text='Cancel']:pressed {
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

        CustomMessageBox.isShown = True
        popup.exec_()

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

#----------------------------------------------MAIN-FUNCTION-------------------------------------------------#

# main function that sets up all the ui elements on startup
def InitAnimationsUI(self):
    # set initial width of elements
    self.loginRegisterVerticalFrame.setFixedWidth(0)
    self.registerFrame.hide()
    self.sideFrame.setFixedWidth(70)

    # initilize pie chart on screen
    InitPieChart(self)

    # hide some labels and icons
    HideSideBarLabels(self)
    ShowSideBarMenuIcon(self)
    ToggleUserInterface(self, False)

    # apply shadow to the left side bar
    ApplyShadowSidebar(self)

    # center table cell text on all tables
    CenterAllTableRowText(self)

    # disable selection on ip address list widget
    DisableSelectionIpListWidget(self)

    # add a context menu to items that are in the mac address list widget on Settings Page
    self.macAddressListWidget.setContextMenuPolicy(Qt.CustomContextMenu)
    self.macAddressListWidget.customContextMenuRequested.connect(lambda position : ShowContextMenu(self, position))

    # disable selection on both history table and report preview table
    self.historyTableWidget.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.historyTableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
    self.reportPreviewTableWidget.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.reportPreviewTableWidget.setEditTriggers(QTableWidget.NoEditTriggers)

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