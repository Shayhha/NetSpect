from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QEasingCurve, QTimer, QSize
from PyQt5.QtWidgets import QGraphicsDropShadowEffect, QApplication, QAction, QMenu, QTableWidget, QLineEdit, QMessageBox, QDesktopWidget, QDialog, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QSizePolicy, QListWidget
from PyQt5.QtGui import QColor, QIcon, QPixmap
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
    self.workstationLabel.show()
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
    else: #fade out animation
        animation.setStartValue(303)
        animation.setEndValue(0)
    
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
    else:
        self.registerFrame.hide()
        self.loginFrame.show()
    
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

# helper function for showing some labels
def LoginButtonClicked(self):
    self.welcomeLabel.show()
    self.logoutIcon.show()
    self.accountIcon.hide()


# helper function for hiding some labels
def HideSideBarLabels(self):
    self.workstationLabel.hide()
    self.reportLabel.hide()
    self.infoLabel.hide()


# helper function for showing some icons
def ShowSideBarMenuIcon(self):
    self.menuIcon.show()
    self.closeMenuIcon.hide()


# helper function for hiding some icons
def HideLogoutIcon(self):
    self.accountIcon.show()
    self.welcomeLabel.hide()
    self.logoutIcon.hide()


# helper function for chaning the current page index on the stack widget
def ChangePageIndex(self, index):
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
        copyAction.triggered.connect(lambda: CopyToClipboard(self, item.text()))
        deleteAction = QAction('Delete')
        deleteAction.triggered.connect(lambda: RemoveItem(self, item))
        menu.addAction(copyAction)
        menu.addAction(deleteAction)
        menu.exec_(self.macAddressListWidget.viewport().mapToGlobal(position))


# function that copies the item text to the clipborad
def CopyToClipboard(self, text):
    clipboard = QApplication.clipboard()  
    clipboard.setText(text)
    

# function the removes an item 
def RemoveItem(self, item):
    self.macAddressListWidget.takeItem(self.macAddressListWidget.row(item))


# function for centering all the texts in every cell of all the tables in the ui
def CenterTableCellText(self):
    # center all the text in the history table widget on Home Page
    for row in range(self.historyTableWidget.rowCount()):
        for col in range(self.historyTableWidget.columnCount()):
            if item := self.historyTableWidget.item(row, col): #check if item exists
                item.setTextAlignment(Qt.AlignCenter)

    self.historyTableWidget.resizeColumnsToContents() #resize columns to fit content
    self.historyTableWidget.resizeRowsToContents() #resize rows to fit content
    self.historyTableWidget.horizontalHeader().setStretchLastSection(True) #stretch last column
    self.historyTableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch) #distribute column widths equally

    # center all the text in the report preview table widget on Report Page
    for row in range(self.reportPreviewTableWidget.rowCount()):
        for col in range(self.reportPreviewTableWidget.columnCount()):
            if item := self.reportPreviewTableWidget.item(row, col): #check if item exists
                item.setTextAlignment(Qt.AlignCenter)

    self.reportPreviewTableWidget.resizeColumnsToContents() #resize columns to fit content
    self.reportPreviewTableWidget.resizeRowsToContents() #resize rows to fit content
    self.reportPreviewTableWidget.horizontalHeader().setStretchLastSection(True) #stretch last column
    self.reportPreviewTableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch) #distribute column widths equally


# custom popup message box class that will be used to show error messages to the user at certain times
class CustomMessageBox(QDialog):
    # ctor that gets the title, message and icon type (will be shown inside) of the message box pop up window.
    def __init__(self, title, message, iconType):
        super().__init__()

        # Setting the title and message
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

        # add the icon and message to the horizontal layout with spacing
        horizontalLayout.addWidget(iconLabel)
        horizontalLayout.addSpacing(25) #add spacing between icon and text
        horizontalLayout.addWidget(messageLabel)
        horizontalLayout.setAlignment(Qt.AlignCenter) #center the entire horizontalLayout

        # add stretchable space around the horizontalLayout to center it vertically in the dialog
        layout.addStretch(1) #add stretch before the content
        layout.addLayout(horizontalLayout)
        layout.addStretch(1) #add stretch after the content

        # add buttons
        buttonLayout = QHBoxLayout()
        buttonLayout.setAlignment(Qt.AlignCenter) #center the buttons
        button = QPushButton("Ok")
        button.clicked.connect(self.reject)
        buttonLayout.addWidget(button)

        # apply layout to the dialog
        layout.addLayout(buttonLayout)
        self.setLayout(layout)

        # set dialog properties (resizeable)
        self.setMinimumSize(350, 150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # set custom stylesheet
        self.setStyleSheet("""
            QDialog {
                background-color: #f3f3f3;
            }
                        
            QLabel {
                color: black;
                font-size: 16px;
            }

            QLabel[alignment="Qt::AlignVCenter|Qt::AlignLeft"] {
                margin-left: 10px;
            }
                        
            QPushButton[text="OK"]  {
                background-color: #3a8e32; 
                border: 1px solid black;  
                border-radius: 10px;         
                padding: 5px;              
                font-size: 14px; 
                font-weight: bold;          
                color: #f3f3f3;       
            }
            QPushButton[text="OK"]:hover {
                background-color: #4D9946;
            }
            QPushButton[text="OK"]:pressed {
                background-color: #2E7128;
            }
                        
            QPushButton[text="Cancel"]  {
                background-color: #D84F4F; 
                border: 1px solid black;  
                border-radius: 10px;         
                padding: 5px;              
                font-size: 14px; 
                font-weight: bold;          
                color: #f3f3f3;       
            }
            QPushButton[text="Cancel"]:hover {
                background-color: #DB6060;
            }
            QPushButton[text="Cancel"]:pressed {
                background-color: #AC3f3F;
            }
        """)
    
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
def ShowPopup(self, title, message, iconType='Warning'):
    #iconType options are: Information, Warning, Critical, Question
    popup = CustomMessageBox(title, message, iconType)

    # center the popup window
    cp = QDesktopWidget().availableGeometry()
    qr = popup.frameGeometry()
    centerPosition = cp.center() - qr.center()
    popup.move(centerPosition) #move to the center

    popup.exec_()


# main function that sets up all the ui elements on startup
def InitAnimationsUI(self):
    # set initial width of elements
    self.loginRegisterVerticalFrame.setFixedWidth(0)
    self.registerFrame.hide()
    self.sideFrame.setFixedWidth(70)

    # hide some labels and icons
    HideSideBarLabels(self)
    ShowSideBarMenuIcon(self)
    HideLogoutIcon(self)

    # apply shadow to the left side bar
    ApplyShadowSidebar(self)

    # center table cell text on all tables
    CenterTableCellText(self)

    # add a context menu to items that are in the mac address list widget on Settings Page
    self.macAddressListWidget.setContextMenuPolicy(Qt.CustomContextMenu)
    self.macAddressListWidget.customContextMenuRequested.connect(lambda position : ShowContextMenu(self, position))

    # disable selection on both history table and report preview table
    self.historyTableWidget.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.historyTableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
    self.reportPreviewTableWidget.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.reportPreviewTableWidget.setEditTriggers(QTableWidget.NoEditTriggers)

    # disable selection on ip address list widget
    self.ipAddressesListWidget.setSelectionMode(QListWidget.NoSelection)
    for row in range(self.ipAddressesListWidget.count()):
        item = self.ipAddressesListWidget.item(row)
        item.setFlags(item.flags() & ~Qt.ItemIsSelectable & ~Qt.ItemIsEnabled)
        item.setForeground(QColor(0, 0, 0)) #set the color to black

    # set the toggle password visability icon in the login and register
    openEyePath = currentDir.parent / 'interface' / 'Icons' / 'EyeOpen.png'
    icon = QIcon(str(openEyePath))
    self.loginEyeButton = self.loginPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.loginEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.loginPasswordLineEdit, self.loginEyeButton))
    self.registerEyeButton = self.registerPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.registerEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.registerPasswordLineEdit, self.registerEyeButton))

    # set the main window icon
    self.setWindowIcon(QIcon(str(currentDir.parent / 'interface' / 'Icons' / 'NetSpectIconTransparent.png')))

#-------------------------------------------OTHER-FUNCTIONS-END----------------------------------------------#