from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QEasingCurve, QTimer
from PyQt5.QtWidgets import QGraphicsDropShadowEffect, QApplication, QAction, QMenu, QTableWidget, QLineEdit
from PyQt5.QtGui import QColor, QIcon
from pathlib import Path

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located

#-------------------------------------------ANIMATION-FUNCTIONS----------------------------------------------#

# Function for openning the left sideframe with an animation
def OpenSideFrame(self):
    animation = QPropertyAnimation(self.sideFrame, b'minimumWidth')
    animation.setDuration(500)
    animation.setEasingCurve(QEasingCurve.InOutQuad)
    animation.setStartValue(70)
    animation.setEndValue(210)
                
    # Start the animation
    animation.start()

    # Show sidebar labels
    self.menuIcon.hide()
    self.closeMenuIcon.show()
    self.workstationLabel.show()
    self.reportLabel.show()
    self.infoLabel.show()

    # Store the animation reference
    self.sideFrame.currentAnimation = animation


# Function for closing the left sideframe with an animation
def CloseSideFrame(self):
    # Create animation for minimumWidth
    animation = QPropertyAnimation(self.sideFrame, b'minimumWidth')
    animation.setDuration(500)
    animation.setEasingCurve(QEasingCurve.OutQuad)
    animation.setStartValue(210)
    animation.setEndValue(70)
    
    # Start the animation
    animation.start()

    # Add delayed animations to icons and labels
    QTimer.singleShot(100, lambda: HideSideBarLabels(self))
    QTimer.singleShot(400, lambda: ShowSideBarMenuIcon(self))
    self.sideFrame.setMaximumWidth(70)
    self.menuIcon.setFixedWidth(50)
    
    # Store the animation reference
    self.sideFrame.currentAnimation = animation


# Function for opening the login/register side frame after clicking the account icon
def AccountIconClicked(self):
    # Create animation object for the frame
    animation = QPropertyAnimation(self.loginRegisterVerticalFrame, b'maximumWidth')
    animation.setDuration(500) #duration in milliseconds (500ms = 0.5 seconds)
    animation.setEasingCurve(QEasingCurve.InOutQuad) #smooth easing curve
    
    if self.loginRegisterVerticalFrame.width() == 0: #fade in animation
        animation.setStartValue(0)
        animation.setEndValue(303)
    else: #fade out animation
        animation.setStartValue(303)
        animation.setEndValue(0)
    
    # Start the animation
    animation.start()
    ApplyShadowLoginRegister(self)

    # Keep the animation object alive by storing it
    self.loginRegisterVerticalFrame.currentAnimation = animation


# Function for changing between the login and register sideframes
def SwitchBetweenLoginAndRegister(self, showRegister=True):
    # First animation: Close the frame
    anim1 = QPropertyAnimation(self.loginRegisterVerticalFrame, b'maximumWidth')
    anim1.setDuration(200)
    anim1.setEasingCurve(QEasingCurve.InOutQuad)
    
    # Use the current width as the start value
    currentWidth = self.loginRegisterVerticalFrame.width()
    anim1.setStartValue(currentWidth)
    anim1.setEndValue(0)
    
    # Start the first animation and chain the second animation to start after the first finishes
    anim1.start()
    self.loginRegisterVerticalFrame.currentAnimation = anim1
    anim1.finished.connect(lambda: ReopenRegistryFrame(self, showRegister)) 


# This is the second animation and visibility switch for the login register side frame
def ReopenRegistryFrame(self, showRegister):
    # Switch visibility
    if showRegister:
        self.loginFrame.hide()
        self.registerFrame.show()
    else:
        self.registerFrame.hide()
        self.loginFrame.show()
    
    # Second animation: Open the frame
    anim2 = QPropertyAnimation(self.loginRegisterVerticalFrame, b'maximumWidth')
    anim2.setDuration(375)
    anim2.setEasingCurve(QEasingCurve.InOutQuad)
    anim2.setStartValue(0)
    anim2.setEndValue(303)
    anim2.start()
    self.loginRegisterVerticalFrame.currentAnimation = anim2

#-----------------------------------------ANIMATION-FUNCTIONS-END--------------------------------------------#

#---------------------------------------------CLICK-FUNCTIONS------------------------------------------------#

# Helper function for showing some labels
def LoginButtonClicked(self):
    self.welcomeLabel.show()
    self.logoutIcon.show()
    self.accountIcon.hide()


# Helper function for hiding some labels
def HideSideBarLabels(self):
    self.workstationLabel.hide()
    self.reportLabel.hide()
    self.infoLabel.hide()
    # Add your code here to do whatever you need


# Helper function for showing some icons
def ShowSideBarMenuIcon(self):
    self.menuIcon.show()
    self.closeMenuIcon.hide()


# Helper function for hiding some icons
def HideLogoutIcon(self):
    self.accountIcon.show()
    self.welcomeLabel.hide()
    self.logoutIcon.hide()


# Helper function for chaning the current page index on the stack widget
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

# Function for adding a box shadow to the login/register side popup frame
def ApplyShadowLoginRegister(self):
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(15) # No blur, sharp shadow (like blur: 0 in CSS)
    shadow.setXOffset(-8) # Horizontal offset: -15px (left)
    shadow.setYOffset(0) # Vertical offset: 10px (down)
    shadow.setColor(QColor(0, 0, 0, 85)) # RGBA(56, 60, 170, 0.5) -> alpha 0.5 = 128/255
    self.loginRegisterVerticalFrame.setGraphicsEffect(shadow)


# Function for adding a box shadow to the left side bar
def ApplyShadowSidebar(self):
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(5) # No blur, sharp shadow (like blur: 0 in CSS)
    shadow.setXOffset(5) # Horizontal offset: -15px (left)
    shadow.setYOffset(0) # Vertical offset: 10px (down)
    shadow.setColor(QColor(0, 0, 0, 50)) # RGBA(56, 60, 170, 0.5) -> alpha 0.5 = 128/255
    self.sideFrame.setGraphicsEffect(shadow)


# Function that shows right-click menu for copying and deleting items in mac
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


# Function that copies the item text to the clipborad
def CopyToClipboard(self, text):
    clipboard = QApplication.clipboard()  
    clipboard.setText(text)
    

# Function the removes an item 
def RemoveItem(self, item):
    self.macAddressListWidget.takeItem(self.macAddressListWidget.row(item))


# Function for centering all the texts in every cell of all the tables in the ui
def CenterTableCellText(self):
    # Center all the text in the history table widget on Home Page
    for row in range(self.historyTableWidget.rowCount()):
        for col in range(self.historyTableWidget.columnCount()):
            if item := self.historyTableWidget.item(row, col): #check if item exists
                item.setTextAlignment(Qt.AlignCenter)

    self.historyTableWidget.resizeColumnsToContents() #resize columns to fit content
    self.historyTableWidget.resizeRowsToContents() #resize rows to fit content
    self.historyTableWidget.horizontalHeader().setStretchLastSection(True) #stretch last column
    self.historyTableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch) #distribute column widths equally

    # Center all the text in the report preview table widget on Report Page
    for row in range(self.reportPreviewTableWidget.rowCount()):
        for col in range(self.reportPreviewTableWidget.columnCount()):
            if item := self.reportPreviewTableWidget.item(row, col):  # Check if item exists
                item.setTextAlignment(Qt.AlignCenter)

    self.reportPreviewTableWidget.resizeColumnsToContents()  # Resize columns to fit content
    self.reportPreviewTableWidget.resizeRowsToContents()  # Resize rows to fit content
    self.reportPreviewTableWidget.horizontalHeader().setStretchLastSection(True)  # Stretch last column
    self.reportPreviewTableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)  # Distribute column widths equally


# Main function that sets up all the ui elements on startup
def InitAnimationsUI(self):
    # Set initial width of elements
    self.loginRegisterVerticalFrame.setFixedWidth(0)
    self.registerFrame.hide()
    self.sideFrame.setFixedWidth(70)

    # Hide some labels and icons
    HideSideBarLabels(self)
    ShowSideBarMenuIcon(self)
    HideLogoutIcon(self)

    # Apply shadow to the left side bar
    ApplyShadowSidebar(self)

    # Center table cell text on all tables
    CenterTableCellText(self)

    # Add a context menu to items that are in the mac address list widget on Settings Page
    self.macAddressListWidget.setContextMenuPolicy(Qt.CustomContextMenu)
    self.macAddressListWidget.customContextMenuRequested.connect(lambda position : ShowContextMenu(self, position))

    # Disable selection on both history table and report preview table
    self.historyTableWidget.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.historyTableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
    self.reportPreviewTableWidget.setSelectionMode(QTableWidget.NoSelection) #disable selection
    self.reportPreviewTableWidget.setEditTriggers(QTableWidget.NoEditTriggers)

    # Set the toggle password visability icon in the login and register
    openEyePath = currentDir.parent / 'interface' / 'Icons' / 'EyeOpen.png'
    icon = QIcon(str(openEyePath))
    self.loginEyeButton = self.loginPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.loginEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.loginPasswordLineEdit, self.loginEyeButton))
    self.registerEyeButton = self.registerPasswordLineEdit.addAction(icon, QLineEdit.TrailingPosition)
    self.registerEyeButton.triggered.connect(lambda: TogglePasswordVisibility(self.registerPasswordLineEdit, self.registerEyeButton))

#-------------------------------------------OTHER-FUNCTIONS-END----------------------------------------------#