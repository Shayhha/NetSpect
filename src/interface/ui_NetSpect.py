# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'NetSpect.ui'
##
## Created by: Qt User Interface Compiler version 6.9.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox,
    QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLayout, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QProgressBar, QPushButton,
    QSizePolicy, QSpacerItem, QStackedWidget, QTableView,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

class Ui_NetSpect(object):
    def setupUi(self, NetSpect):
        if not NetSpect.objectName():
            NetSpect.setObjectName(u"NetSpect")
        NetSpect.resize(1300, 720)
        NetSpect.setMinimumSize(QSize(1300, 720))
        font = QFont()
        font.setFamilies([u"Cairo"])
        font.setPointSize(16)
        font.setBold(False)
        NetSpect.setFont(font)
        NetSpect.setStyleSheet(u"QWidget {\n"
"    background-color: #3c3d4a;\n"
"}\n"
"\n"
"QScrollBar:vertical, QScrollBar:horizontal {\n"
"    background-color: rgb(250, 250, 250);\n"
"    border: 1px solid rgb(153, 153, 153);\n"
"    width: 10px;\n"
"    height: 10px; \n"
"    margin: 0px 0px 0px 0px;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"QScrollBar::handle:vertical, QScrollBar::handle:horizontal {\n"
"    background-color: black;\n"
"    min-height: 100px;\n"
"    border: 0px solid black;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"QScrollBar::add-line:vertical, QScrollBar::add-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: bottom;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"QScrollBar::sub-line:vertical, QScrollBar::sub-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: top;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"QMenu {\n"
"    background-color: #2d2d2d;\n"
"    color: #f3f3f3;\n"
"    border: 1px solid #555;\n"
"    padding: 5px;\n"
"    border-radius: 6px;\n"
"}\n"
"\n"
"QMen"
                        "u::item {\n"
"    padding: 6px 20px;\n"
"    background-color: transparent;\n"
"}\n"
"\n"
"QMenu::item:selected {\n"
"    background-color: rgba(255, 255, 255, 0.1);\n"
"    color: #ffffff;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"QToolTip { \n"
"   color: rgb(245,245,245);\n"
"   background-color: rgba(46, 47, 56, 0.8);\n"
"   border: 1px solid rgb(102,102,102);\n"
"   padding: 4px;\n"
"}")
        self.centralWidget = QWidget(NetSpect)
        self.centralWidget.setObjectName(u"centralWidget")
        self.centralWidget.setStyleSheet(u"#centralWidget {\n"
"    background-color: rgb(60, 61, 74);\n"
"}\n"
"\n"
"#centralWidget QScrollBar:vertical, #centralWidget QScrollBar:horizontal {\n"
"    background-color: rgb(250, 250, 250);\n"
"    border: 1px solid rgb(153, 153, 153);\n"
"    width: 10px;\n"
"    height: 10px;\n"
"    margin: 0px 0px 0px 0px;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#centralWidget QScrollBar::handle:vertical, #centralWidget QScrollBar::handle:horizontal {\n"
"    background-color: black;\n"
"    min-height: 100px;\n"
"    border: 0px solid black;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#centralWidget QScrollBar::add-line:vertical, #centralWidget QScrollBar::add-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: bottom;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"#centralWidget QScrollBar::sub-line:vertical, #centralWidget QScrollBar::sub-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: top;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"#centralWidget QMenu {\n"
"    bac"
                        "kground-color: #2d2d2d;\n"
"    color: #f3f3f3;\n"
"    border: 1px solid #555;\n"
"    padding: 5px;\n"
"    border-radius: 6px;\n"
"}\n"
"\n"
"#centralWidget QMenu::item {\n"
"    padding: 6px 20px;\n"
"    background-color: transparent;\n"
"}\n"
"\n"
"#centralWidget QMenu::item:selected {\n"
"    background-color: rgba(255, 255, 255, 0.1);\n"
"    color: #ffffff;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#centralWidget QToolTip {\n"
"    color: rgb(245,245,245);\n"
"    background-color: rgba(46, 47, 56, 0.8);\n"
"    border: 1px solid rgb(102,102,102);\n"
"    padding: 4px;\n"
"}")
        self.gridLayout = QGridLayout(self.centralWidget)
        self.gridLayout.setSpacing(0)
        self.gridLayout.setObjectName(u"gridLayout")
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.topFrame = QFrame(self.centralWidget)
        self.topFrame.setObjectName(u"topFrame")
        self.topFrame.setMinimumSize(QSize(1280, 60))
        self.topFrame.setMaximumSize(QSize(16777215, 60))
        font1 = QFont()
        font1.setFamilies([u"Cairo"])
        font1.setPointSize(16)
        self.topFrame.setFont(font1)
        self.topFrame.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.topFrame.setStyleSheet(u"#topFrame {\n"
"    background-color: #1E1E20;\n"
"}")
        self.horizontalLayout = QHBoxLayout(self.topFrame)
        self.horizontalLayout.setSpacing(15)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.horizontalLayout.setSizeConstraint(QLayout.SizeConstraint.SetDefaultConstraint)
        self.horizontalLayout.setContentsMargins(15, 0, 15, 0)
        self.logoLabel = QLabel(self.topFrame)
        self.logoLabel.setObjectName(u"logoLabel")
        self.logoLabel.setMinimumSize(QSize(186, 60))
        self.logoLabel.setMaximumSize(QSize(16777215, 16777215))
        font2 = QFont()
        font2.setFamilies([u"Days One"])
        self.logoLabel.setFont(font2)
        self.logoLabel.setStyleSheet(u"#logoLabel {\n"
"	background-color: transparent;\n"
"  	color: #f3f3f3;\n"
"    font-size: 35px;\n"
"    font-family: Days One;\n"
"}")

        self.horizontalLayout.addWidget(self.logoLabel)

        self.horizontalSpacer = QSpacerItem(378, 55, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout.addItem(self.horizontalSpacer)

        self.welcomeLabel = QLabel(self.topFrame)
        self.welcomeLabel.setObjectName(u"welcomeLabel")
        self.welcomeLabel.setMinimumSize(QSize(0, 40))
        self.welcomeLabel.setMaximumSize(QSize(300, 40))
        font3 = QFont()
        font3.setFamilies([u"Cairo"])
        self.welcomeLabel.setFont(font3)
        self.welcomeLabel.setStyleSheet(u"#welcomeLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"}")
        self.welcomeLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.welcomeLabel.setWordWrap(False)

        self.horizontalLayout.addWidget(self.welcomeLabel)

        self.logoutIcon = QLabel(self.topFrame)
        self.logoutIcon.setObjectName(u"logoutIcon")
        self.logoutIcon.setEnabled(True)
        self.logoutIcon.setMinimumSize(QSize(40, 40))
        self.logoutIcon.setMaximumSize(QSize(40, 40))
        self.logoutIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.logoutIcon.setStyleSheet(u"#logoutIcon {\n"
"	background-color: transparent;\n"
"}")
        self.logoutIcon.setPixmap(QPixmap(u"Icons/LogoutLight.png"))
        self.logoutIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout.addWidget(self.logoutIcon)

        self.accountIcon = QLabel(self.topFrame)
        self.accountIcon.setObjectName(u"accountIcon")
        self.accountIcon.setMinimumSize(QSize(40, 40))
        self.accountIcon.setMaximumSize(QSize(40, 40))
        self.accountIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.accountIcon.setStyleSheet(u"#accountIcon {\n"
"	background-color: transparent;\n"
"}")
        self.accountIcon.setPixmap(QPixmap(u"Icons/AccountLight.png"))
        self.accountIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout.addWidget(self.accountIcon)

        self.settingsIcon = QLabel(self.topFrame)
        self.settingsIcon.setObjectName(u"settingsIcon")
        self.settingsIcon.setMinimumSize(QSize(40, 40))
        self.settingsIcon.setMaximumSize(QSize(40, 40))
        self.settingsIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.settingsIcon.setStyleSheet(u"#settingsIcon {\n"
"	background-color: transparent;\n"
"}")
        self.settingsIcon.setPixmap(QPixmap(u"Icons/SettingsLight.png"))
        self.settingsIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout.addWidget(self.settingsIcon)


        self.gridLayout.addWidget(self.topFrame, 0, 0, 1, 2)

        self.mainWindowHorizontalFrame = QFrame(self.centralWidget)
        self.mainWindowHorizontalFrame.setObjectName(u"mainWindowHorizontalFrame")
        self.mainWindowHorizontalFrame.setMinimumSize(QSize(1300, 660))
        self.mainWindowHorizontalFrame.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.mainWindowHorizontalFrame.setAutoFillBackground(False)
        self.mainWindowHorizontalFrame.setStyleSheet(u"")
        self.mainHorizontalFrame = QHBoxLayout(self.mainWindowHorizontalFrame)
        self.mainHorizontalFrame.setSpacing(0)
        self.mainHorizontalFrame.setObjectName(u"mainHorizontalFrame")
        self.mainHorizontalFrame.setContentsMargins(0, 0, 0, 0)
        self.sideFrame = QFrame(self.mainWindowHorizontalFrame)
        self.sideFrame.setObjectName(u"sideFrame")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.sideFrame.sizePolicy().hasHeightForWidth())
        self.sideFrame.setSizePolicy(sizePolicy)
        self.sideFrame.setMinimumSize(QSize(70, 660))
        self.sideFrame.setStyleSheet(u"#sideFrame {\n"
"    background-color: #2D2E36;\n"
"}\n"
"")
        self.verticalLayout = QVBoxLayout(self.sideFrame)
        self.verticalLayout.setSpacing(20)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setSizeConstraint(QLayout.SizeConstraint.SetDefaultConstraint)
        self.verticalLayout.setContentsMargins(10, 15, 10, 15)
        self.menuIconHorizontalFrame = QFrame(self.sideFrame)
        self.menuIconHorizontalFrame.setObjectName(u"menuIconHorizontalFrame")
        self.menuIconHorizontalFrame.setStyleSheet(u"#menuIconHorizontalFrame {\n"
"	background-color: #2d2e36;\n"
"}\n"
"\n"
"")
        self.horizontalLayout_2 = QHBoxLayout(self.menuIconHorizontalFrame)
        self.horizontalLayout_2.setSpacing(0)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.menuIcon = QLabel(self.menuIconHorizontalFrame)
        self.menuIcon.setObjectName(u"menuIcon")
        self.menuIcon.setMinimumSize(QSize(50, 50))
        self.menuIcon.setMaximumSize(QSize(50, 50))
        self.menuIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.menuIcon.setStyleSheet(u"#menuIcon {\n"
"	background-color: #2d2e36;\n"
"}")
        self.menuIcon.setPixmap(QPixmap(u"Icons/BulletedMenuLight.png"))
        self.menuIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_2.addWidget(self.menuIcon)

        self.horizontalSpacer_2 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer_2)

        self.closeMenuIcon = QLabel(self.menuIconHorizontalFrame)
        self.closeMenuIcon.setObjectName(u"closeMenuIcon")
        self.closeMenuIcon.setMinimumSize(QSize(50, 50))
        self.closeMenuIcon.setMaximumSize(QSize(50, 50))
        self.closeMenuIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.closeMenuIcon.setStyleSheet(u"#closeMenuIcon {\n"
"	background-color: #2d2e36;\n"
"}")
        self.closeMenuIcon.setPixmap(QPixmap(u"Icons/BulletedMenuRotatedLight.png"))
        self.closeMenuIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_2.addWidget(self.closeMenuIcon)


        self.verticalLayout.addWidget(self.menuIconHorizontalFrame)

        self.homePageIconHorizontalFrame = QFrame(self.sideFrame)
        self.homePageIconHorizontalFrame.setObjectName(u"homePageIconHorizontalFrame")
        self.homePageIconHorizontalFrame.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.homePageIconHorizontalFrame.setStyleSheet(u"#homePageIconHorizontalFrame {\n"
"	background-color: #2d2e36;\n"
"}")
        self.horizontalLayout_3 = QHBoxLayout(self.homePageIconHorizontalFrame)
        self.horizontalLayout_3.setSpacing(22)
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.homePageIcon = QLabel(self.homePageIconHorizontalFrame)
        self.homePageIcon.setObjectName(u"homePageIcon")
        self.homePageIcon.setMinimumSize(QSize(50, 50))
        self.homePageIcon.setMaximumSize(QSize(50, 50))
        self.homePageIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.homePageIcon.setStyleSheet(u"#homePageIcon {\n"
"	background-color: #2d2e36;\n"
"\n"
"}")
        self.homePageIcon.setPixmap(QPixmap(u"Icons/WorkstationLight.png"))
        self.homePageIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_3.addWidget(self.homePageIcon)

        self.homePageLabel = QLabel(self.homePageIconHorizontalFrame)
        self.homePageLabel.setObjectName(u"homePageLabel")
        self.homePageLabel.setMinimumSize(QSize(0, 50))
        self.homePageLabel.setMaximumSize(QSize(16777215, 50))
        font4 = QFont()
        font4.setFamilies([u"Cairo"])
        font4.setBold(True)
        self.homePageLabel.setFont(font4)
        self.homePageLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.homePageLabel.setStyleSheet(u"#homePageLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #f3f3f3;\n"
"    font-size: 21px;\n"
"    font-family: Cairo;\n"
"}")
        self.homePageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.homePageLabel.setMargin(0)

        self.horizontalLayout_3.addWidget(self.homePageLabel)

        self.horizontalSpacer_3 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_3)


        self.verticalLayout.addWidget(self.homePageIconHorizontalFrame)

        self.analyticsIconHorizontalFrame = QFrame(self.sideFrame)
        self.analyticsIconHorizontalFrame.setObjectName(u"analyticsIconHorizontalFrame")
        self.analyticsIconHorizontalFrame.setStyleSheet(u"#analyticsIconHorizontalFrame {\n"
"	background-color: #2d2e36;\n"
"}")
        self.horizontalLayout_4 = QHBoxLayout(self.analyticsIconHorizontalFrame)
        self.horizontalLayout_4.setSpacing(32)
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.horizontalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.analyticsIcon = QLabel(self.analyticsIconHorizontalFrame)
        self.analyticsIcon.setObjectName(u"analyticsIcon")
        self.analyticsIcon.setMinimumSize(QSize(50, 50))
        self.analyticsIcon.setMaximumSize(QSize(50, 50))
        self.analyticsIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.analyticsIcon.setStyleSheet(u"#analyticsIcon {\n"
"	background-color: #2d2e36;\n"
"\n"
"}")
        self.analyticsIcon.setPixmap(QPixmap(u"Icons/AnalyticsLight.png"))
        self.analyticsIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_4.addWidget(self.analyticsIcon)

        self.analyticsLabel = QLabel(self.analyticsIconHorizontalFrame)
        self.analyticsLabel.setObjectName(u"analyticsLabel")
        self.analyticsLabel.setMinimumSize(QSize(0, 50))
        self.analyticsLabel.setMaximumSize(QSize(16777215, 50))
        self.analyticsLabel.setFont(font4)
        self.analyticsLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.analyticsLabel.setStyleSheet(u"#analyticsLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #f3f3f3;\n"
"    font-size: 21px;\n"
"    font-family: Cairo;\n"
"}")
        self.analyticsLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.analyticsLabel.setMargin(0)

        self.horizontalLayout_4.addWidget(self.analyticsLabel)

        self.horizontalSpacer_4 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_4.addItem(self.horizontalSpacer_4)


        self.verticalLayout.addWidget(self.analyticsIconHorizontalFrame)

        self.reportIconHorizontalFrame = QFrame(self.sideFrame)
        self.reportIconHorizontalFrame.setObjectName(u"reportIconHorizontalFrame")
        self.reportIconHorizontalFrame.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.reportIconHorizontalFrame.setStyleSheet(u"#reportIconHorizontalFrame {\n"
"	background-color: #2d2e36;\n"
"}")
        self.horizontalLayout_5 = QHBoxLayout(self.reportIconHorizontalFrame)
        self.horizontalLayout_5.setSpacing(38)
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.reportIcon = QLabel(self.reportIconHorizontalFrame)
        self.reportIcon.setObjectName(u"reportIcon")
        self.reportIcon.setMinimumSize(QSize(50, 50))
        self.reportIcon.setMaximumSize(QSize(50, 50))
        self.reportIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.reportIcon.setStyleSheet(u"#reportIcon {\n"
"	background-color: #2d2e36;\n"
"}")
        self.reportIcon.setPixmap(QPixmap(u"Icons/DocumentLight.png"))
        self.reportIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_5.addWidget(self.reportIcon)

        self.reportLabel = QLabel(self.reportIconHorizontalFrame)
        self.reportLabel.setObjectName(u"reportLabel")
        self.reportLabel.setMinimumSize(QSize(0, 50))
        self.reportLabel.setMaximumSize(QSize(16777215, 50))
        self.reportLabel.setFont(font4)
        self.reportLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.reportLabel.setStyleSheet(u"#reportLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #f3f3f3;\n"
"    font-size: 21px;\n"
"    font-family: Cairo;\n"
"\n"
"}")
        self.reportLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.reportLabel.setMargin(0)

        self.horizontalLayout_5.addWidget(self.reportLabel)

        self.horizontalSpacer_5 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_5.addItem(self.horizontalSpacer_5)


        self.verticalLayout.addWidget(self.reportIconHorizontalFrame)

        self.infoIconHorizontalFrame = QFrame(self.sideFrame)
        self.infoIconHorizontalFrame.setObjectName(u"infoIconHorizontalFrame")
        self.infoIconHorizontalFrame.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.infoIconHorizontalFrame.setStyleSheet(u"#infoIconHorizontalFrame {\n"
"	background-color: #2d2e36;\n"
"}")
        self.horizontalLayout_6 = QHBoxLayout(self.infoIconHorizontalFrame)
        self.horizontalLayout_6.setSpacing(22)
        self.horizontalLayout_6.setObjectName(u"horizontalLayout_6")
        self.horizontalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.infoIcon = QLabel(self.infoIconHorizontalFrame)
        self.infoIcon.setObjectName(u"infoIcon")
        self.infoIcon.setMinimumSize(QSize(50, 50))
        self.infoIcon.setMaximumSize(QSize(50, 50))
        self.infoIcon.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.infoIcon.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.infoIcon.setStyleSheet(u"#infoIcon {\n"
"	background-color: #2d2e36;\n"
"}")
        self.infoIcon.setPixmap(QPixmap(u"Icons/InfoLight.png"))
        self.infoIcon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_6.addWidget(self.infoIcon)

        self.infoLabel = QLabel(self.infoIconHorizontalFrame)
        self.infoLabel.setObjectName(u"infoLabel")
        self.infoLabel.setMinimumSize(QSize(0, 50))
        self.infoLabel.setMaximumSize(QSize(16777215, 50))
        self.infoLabel.setFont(font4)
        self.infoLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.infoLabel.setStyleSheet(u"#infoLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #f3f3f3;\n"
"    font-size: 21px;\n"
"    font-family: Cairo;\n"
"\n"
"}")
        self.infoLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.infoLabel.setMargin(0)

        self.horizontalLayout_6.addWidget(self.infoLabel)

        self.horizontalSpacer_6 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_6.addItem(self.horizontalSpacer_6)


        self.verticalLayout.addWidget(self.infoIconHorizontalFrame)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout.addItem(self.verticalSpacer)


        self.mainHorizontalFrame.addWidget(self.sideFrame)

        self.stackedWidget = QStackedWidget(self.mainWindowHorizontalFrame)
        self.stackedWidget.setObjectName(u"stackedWidget")
        sizePolicy.setHeightForWidth(self.stackedWidget.sizePolicy().hasHeightForWidth())
        self.stackedWidget.setSizePolicy(sizePolicy)
        self.stackedWidget.setMinimumSize(QSize(910, 660))
        self.homePage = QWidget()
        self.homePage.setObjectName(u"homePage")
        self.gridLayout_2 = QGridLayout(self.homePage)
        self.gridLayout_2.setSpacing(0)
        self.gridLayout_2.setObjectName(u"gridLayout_2")
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.homepageFrame = QFrame(self.homePage)
        self.homepageFrame.setObjectName(u"homepageFrame")
        self.homepageFrame.setMinimumSize(QSize(0, 660))
        self.horizontalLayout_7 = QHBoxLayout(self.homepageFrame)
        self.horizontalLayout_7.setSpacing(10)
        self.horizontalLayout_7.setObjectName(u"horizontalLayout_7")
        self.horizontalLayout_7.setContentsMargins(15, 10, 10, 10)
        self.leftVerticalFrame = QFrame(self.homepageFrame)
        self.leftVerticalFrame.setObjectName(u"leftVerticalFrame")
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy1.setHorizontalStretch(1)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.leftVerticalFrame.sizePolicy().hasHeightForWidth())
        self.leftVerticalFrame.setSizePolicy(sizePolicy1)
        self.leftVerticalFrame.setMinimumSize(QSize(0, 620))
        self.verticalLayout_2 = QVBoxLayout(self.leftVerticalFrame)
        self.verticalLayout_2.setSpacing(10)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.startVerticalFrame = QFrame(self.leftVerticalFrame)
        self.startVerticalFrame.setObjectName(u"startVerticalFrame")
        self.startVerticalFrame.setMinimumSize(QSize(440, 260))
        self.startVerticalFrame.setMaximumSize(QSize(16777215, 300))
        self.startVerticalFrame.setStyleSheet(u"#startVerticalFrame {\n"
"   background-color: rgba(204, 204, 204, 0.6);;\n"
"   color: black;\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-color: black;	\n"
"   padding: 4px;\n"
"}")
        self.verticalLayout_3 = QVBoxLayout(self.startVerticalFrame)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.initiateDefenceLabel = QLabel(self.startVerticalFrame)
        self.initiateDefenceLabel.setObjectName(u"initiateDefenceLabel")
        self.initiateDefenceLabel.setMinimumSize(QSize(200, 30))
        self.initiateDefenceLabel.setMaximumSize(QSize(16777215, 16777215))
        self.initiateDefenceLabel.setFont(font4)
        self.initiateDefenceLabel.setStyleSheet(u"#initiateDefenceLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"	padding-top: 5px;\n"
"	padding-left: 5px;\n"
"}")
        self.initiateDefenceLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.initiateDefenceLabel.setWordWrap(False)

        self.verticalLayout_3.addWidget(self.initiateDefenceLabel)

        self.startHorizontalFrame = QFrame(self.startVerticalFrame)
        self.startHorizontalFrame.setObjectName(u"startHorizontalFrame")
        self.startHorizontalFrame.setStyleSheet(u"#startHorizontalFrame {\n"
"   background-color: transparent;\n"
"   color: black;\n"
"}")
        self.horizontalLayout_8 = QHBoxLayout(self.startHorizontalFrame)
        self.horizontalLayout_8.setSpacing(15)
        self.horizontalLayout_8.setObjectName(u"horizontalLayout_8")
        self.horizontalLayout_8.setContentsMargins(6, -1, 6, 10)
        self.horizontalSpacer_7 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_8.addItem(self.horizontalSpacer_7)

        self.startStopPushButton = QPushButton(self.startHorizontalFrame)
        self.startStopPushButton.setObjectName(u"startStopPushButton")
        sizePolicy.setHeightForWidth(self.startStopPushButton.sizePolicy().hasHeightForWidth())
        self.startStopPushButton.setSizePolicy(sizePolicy)
        self.startStopPushButton.setMinimumSize(QSize(120, 120))
        self.startStopPushButton.setMaximumSize(QSize(120, 120))
        self.startStopPushButton.setFont(font4)
        self.startStopPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.startStopPushButton.setStyleSheet(u"#startStopPushButton {\n"
"    background-color: #3a8e32;\n"
"    border: 1px solid black;\n"
"    border-radius: 60px;\n"
"    color: black;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}\n"
"\n"
"#startStopPushButton:hover {\n"
"     background-color: #4d9946;\n"
"}\n"
"\n"
"#startStopPushButton:pressed {\n"
"     background-color: #2e7128;\n"
"}")

        self.horizontalLayout_8.addWidget(self.startStopPushButton)

        self.horizontalSpacer_8 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_8.addItem(self.horizontalSpacer_8)

        self.startInfoVerticalFrame = QFrame(self.startHorizontalFrame)
        self.startInfoVerticalFrame.setObjectName(u"startInfoVerticalFrame")
        self.startInfoVerticalFrame.setStyleSheet(u"#startInfoVerticalFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.verticalLayout_4 = QVBoxLayout(self.startInfoVerticalFrame)
        self.verticalLayout_4.setSpacing(20)
        self.verticalLayout_4.setObjectName(u"verticalLayout_4")
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalSpacer_2 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_4.addItem(self.verticalSpacer_2)

        self.networlInterfaceHorizontalFrame = QFrame(self.startInfoVerticalFrame)
        self.networlInterfaceHorizontalFrame.setObjectName(u"networlInterfaceHorizontalFrame")
        self.networlInterfaceHorizontalFrame.setMinimumSize(QSize(0, 35))
        self.networlInterfaceHorizontalFrame.setMaximumSize(QSize(500, 35))
        self.networlInterfaceHorizontalFrame.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.networlInterfaceHorizontalFrame.setStyleSheet(u"#networlInterfaceHorizontalFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_9 = QHBoxLayout(self.networlInterfaceHorizontalFrame)
        self.horizontalLayout_9.setSpacing(6)
        self.horizontalLayout_9.setObjectName(u"horizontalLayout_9")
        self.horizontalLayout_9.setContentsMargins(0, 0, 0, 4)
        self.networkInterfaceLabel = QLabel(self.networlInterfaceHorizontalFrame)
        self.networkInterfaceLabel.setObjectName(u"networkInterfaceLabel")
        self.networkInterfaceLabel.setMinimumSize(QSize(160, 30))
        self.networkInterfaceLabel.setMaximumSize(QSize(16777215, 30))
        font5 = QFont()
        font5.setFamilies([u"Cairo"])
        font5.setBold(False)
        self.networkInterfaceLabel.setFont(font5)
        self.networkInterfaceLabel.setStyleSheet(u"#networkInterfaceLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"}")
        self.networkInterfaceLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.networkInterfaceLabel.setWordWrap(False)
        self.networkInterfaceLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_9.addWidget(self.networkInterfaceLabel)

        self.networkInterfaceComboBoxFrame = QFrame(self.networlInterfaceHorizontalFrame)
        self.networkInterfaceComboBoxFrame.setObjectName(u"networkInterfaceComboBoxFrame")
        self.networkInterfaceComboBoxFrame.setMinimumSize(QSize(120, 32))
        self.networkInterfaceComboBoxFrame.setMaximumSize(QSize(120, 32))
        font6 = QFont()
        font6.setFamilies([u"Cairo"])
        font6.setPointSize(12)
        self.networkInterfaceComboBoxFrame.setFont(font6)
        self.networkInterfaceComboBoxFrame.setStyleSheet(u"#networkInterfaceComboBoxFrame {\n"
"    background-color: #f3f3f3;\n"
"    color: black;\n"
"    border: 2px transparent; \n"
"    border-radius: 10px;\n"
"    padding-left: 5px;\n"
"    height: 29px;\n"
"}")
        self.networkInterfaceComboBoxFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.networkInterfaceComboBoxFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.networkInterfaceComboBoxFrameArrow = QFrame(self.networkInterfaceComboBoxFrame)
        self.networkInterfaceComboBoxFrameArrow.setObjectName(u"networkInterfaceComboBoxFrameArrow")
        self.networkInterfaceComboBoxFrameArrow.setGeometry(QRect(95, 0, 24, 32))
        self.networkInterfaceComboBoxFrameArrow.setMinimumSize(QSize(24, 32))
        self.networkInterfaceComboBoxFrameArrow.setMaximumSize(QSize(22, 32))
        self.networkInterfaceComboBoxFrameArrow.setFont(font6)
        self.networkInterfaceComboBoxFrameArrow.setStyleSheet(u"#networkInterfaceComboBoxFrameArrow {\n"
"    background-color: lightgray;\n"
"    color: black;\n"
"    border-top-right-radius: 10px;\n"
"    border-bottom-right-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.networkInterfaceComboBoxFrameArrow.setFrameShape(QFrame.Shape.StyledPanel)
        self.networkInterfaceComboBoxFrameArrow.setFrameShadow(QFrame.Shadow.Raised)
        self.networkInterfaceComboBox = QComboBox(self.networkInterfaceComboBoxFrame)
        self.networkInterfaceComboBox.addItem("")
        self.networkInterfaceComboBox.addItem("")
        self.networkInterfaceComboBox.addItem("")
        self.networkInterfaceComboBox.addItem("")
        self.networkInterfaceComboBox.setObjectName(u"networkInterfaceComboBox")
        self.networkInterfaceComboBox.setGeometry(QRect(0, 0, 120, 32))
        self.networkInterfaceComboBox.setMinimumSize(QSize(120, 32))
        self.networkInterfaceComboBox.setMaximumSize(QSize(120, 32))
        self.networkInterfaceComboBox.setFont(font3)
        self.networkInterfaceComboBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.networkInterfaceComboBox.setStyleSheet(u"#networkInterfaceComboBox  {\n"
"    background-color: transparent;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"    border: 2px outset transparent;\n"
"    border-radius: 10px;\n"
"    padding: 4px;\n"
"	padding-left: 10px;\n"
"}\n"
"\n"
"#networkInterfaceComboBox QAbstractItemView {\n"
"    background-color:  #f3f3f3;\n"
"    selection-background-color: rgb(95, 97, 109);\n"
"    color: rgb(0, 0, 0);\n"
"    border: 1px solid black;\n"
"    padding: 10px;\n"
"    padding-left: 5px;\n"
"    padding-right: 5px;\n"
"}\n"
"\n"
"#networkInterfaceComboBox QAbstractItemView::item:hover {\n"
"    background-color: rgba(0, 0, 0, 0.07);\n"
"    color: black;\n"
"    border-radius: 6px;\n"
"    padding-left: 8px;\n"
"}\n"
"\n"
"#networkInterfaceComboBox QAbstractItemView::item:selected {\n"
"    color: black;\n"
"    border: none;\n"
"    outline: none;\n"
"}\n"
"\n"
"#networkInterfaceComboBox QListView{\n"
"    outline: 0px;\n"
"}")

        self.horizontalLayout_9.addWidget(self.networkInterfaceComboBoxFrame)

        self.horizontalSpacer_9 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_9.addItem(self.horizontalSpacer_9)


        self.verticalLayout_4.addWidget(self.networlInterfaceHorizontalFrame)

        self.runningTimeHorizontalFrame = QFrame(self.startInfoVerticalFrame)
        self.runningTimeHorizontalFrame.setObjectName(u"runningTimeHorizontalFrame")
        self.runningTimeHorizontalFrame.setMinimumSize(QSize(0, 35))
        self.runningTimeHorizontalFrame.setMaximumSize(QSize(500, 35))
        self.runningTimeHorizontalFrame.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.runningTimeHorizontalFrame.setStyleSheet(u"#runningTimeHorizontalFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_10 = QHBoxLayout(self.runningTimeHorizontalFrame)
        self.horizontalLayout_10.setSpacing(0)
        self.horizontalLayout_10.setObjectName(u"horizontalLayout_10")
        self.horizontalLayout_10.setContentsMargins(0, 0, 0, 3)
        self.runningTimeLabel = QLabel(self.runningTimeHorizontalFrame)
        self.runningTimeLabel.setObjectName(u"runningTimeLabel")
        self.runningTimeLabel.setMinimumSize(QSize(135, 30))
        self.runningTimeLabel.setMaximumSize(QSize(16777215, 30))
        self.runningTimeLabel.setFont(font5)
        self.runningTimeLabel.setStyleSheet(u"#runningTimeLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"}")
        self.runningTimeLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.runningTimeLabel.setWordWrap(False)
        self.runningTimeLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_10.addWidget(self.runningTimeLabel)

        self.runningTimeCounter = QLabel(self.runningTimeHorizontalFrame)
        self.runningTimeCounter.setObjectName(u"runningTimeCounter")
        self.runningTimeCounter.setMinimumSize(QSize(120, 30))
        self.runningTimeCounter.setMaximumSize(QSize(120, 30))
        self.runningTimeCounter.setFont(font5)
        self.runningTimeCounter.setStyleSheet(u"#runningTimeCounter {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"}")
        self.runningTimeCounter.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.runningTimeCounter.setWordWrap(False)
        self.runningTimeCounter.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_10.addWidget(self.runningTimeCounter)

        self.horizontalSpacer_10 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_10.addItem(self.horizontalSpacer_10)


        self.verticalLayout_4.addWidget(self.runningTimeHorizontalFrame)

        self.numberOfDetectionsHorizontalFrame = QFrame(self.startInfoVerticalFrame)
        self.numberOfDetectionsHorizontalFrame.setObjectName(u"numberOfDetectionsHorizontalFrame")
        self.numberOfDetectionsHorizontalFrame.setMinimumSize(QSize(0, 35))
        self.numberOfDetectionsHorizontalFrame.setMaximumSize(QSize(500, 35))
        self.numberOfDetectionsHorizontalFrame.setStyleSheet(u"#numberOfDetectionsHorizontalFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_11 = QHBoxLayout(self.numberOfDetectionsHorizontalFrame)
        self.horizontalLayout_11.setSpacing(0)
        self.horizontalLayout_11.setObjectName(u"horizontalLayout_11")
        self.horizontalLayout_11.setContentsMargins(0, 0, 0, 0)
        self.numberOfDetectionsLabel = QLabel(self.numberOfDetectionsHorizontalFrame)
        self.numberOfDetectionsLabel.setObjectName(u"numberOfDetectionsLabel")
        self.numberOfDetectionsLabel.setMinimumSize(QSize(190, 30))
        self.numberOfDetectionsLabel.setMaximumSize(QSize(16777215, 30))
        self.numberOfDetectionsLabel.setFont(font5)
        self.numberOfDetectionsLabel.setStyleSheet(u"#numberOfDetectionsLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"}")
        self.numberOfDetectionsLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.numberOfDetectionsLabel.setWordWrap(False)
        self.numberOfDetectionsLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_11.addWidget(self.numberOfDetectionsLabel)

        self.numberOfDetectionsCounter = QLabel(self.numberOfDetectionsHorizontalFrame)
        self.numberOfDetectionsCounter.setObjectName(u"numberOfDetectionsCounter")
        self.numberOfDetectionsCounter.setMinimumSize(QSize(60, 30))
        self.numberOfDetectionsCounter.setMaximumSize(QSize(60, 30))
        self.numberOfDetectionsCounter.setFont(font5)
        self.numberOfDetectionsCounter.setStyleSheet(u"#numberOfDetectionsCounter {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"}")
        self.numberOfDetectionsCounter.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.numberOfDetectionsCounter.setWordWrap(False)
        self.numberOfDetectionsCounter.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_11.addWidget(self.numberOfDetectionsCounter)

        self.horizontalSpacer_11 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_11.addItem(self.horizontalSpacer_11)


        self.verticalLayout_4.addWidget(self.numberOfDetectionsHorizontalFrame)

        self.verticalSpacer_3 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_4.addItem(self.verticalSpacer_3)


        self.horizontalLayout_8.addWidget(self.startInfoVerticalFrame)

        self.horizontalSpacer_12 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_8.addItem(self.horizontalSpacer_12)


        self.verticalLayout_3.addWidget(self.startHorizontalFrame)


        self.verticalLayout_2.addWidget(self.startVerticalFrame)

        self.chartVerticalFrame = QFrame(self.leftVerticalFrame)
        self.chartVerticalFrame.setObjectName(u"chartVerticalFrame")
        self.chartVerticalFrame.setMinimumSize(QSize(0, 0))
        self.chartVerticalFrame.setStyleSheet(u"#chartVerticalFrame {\n"
"   background-color: rgba(204, 204, 204, 0.6);\n"
"   color: black;\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-color: black;	\n"
"   padding: 4px;\n"
"}\n"
"")
        self.chartVerticalFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.chartVerticalFrame.setFrameShadow(QFrame.Shadow.Raised)

        self.verticalLayout_2.addWidget(self.chartVerticalFrame)


        self.horizontalLayout_7.addWidget(self.leftVerticalFrame)

        self.rightVerticalFrame = QFrame(self.homepageFrame)
        self.rightVerticalFrame.setObjectName(u"rightVerticalFrame")
        sizePolicy2 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy2.setHorizontalStretch(2)
        sizePolicy2.setVerticalStretch(0)
        sizePolicy2.setHeightForWidth(self.rightVerticalFrame.sizePolicy().hasHeightForWidth())
        self.rightVerticalFrame.setSizePolicy(sizePolicy2)
        self.rightVerticalFrame.setMinimumSize(QSize(0, 0))
        self.rightVerticalFrame.setStyleSheet(u"#rightVerticalFrame {\n"
"   background-color: rgba(204, 204, 204, 0.6);\n"
"   color: black;\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-color: black;	\n"
"}")
        self.verticalLayout_5 = QVBoxLayout(self.rightVerticalFrame)
        self.verticalLayout_5.setSpacing(20)
        self.verticalLayout_5.setObjectName(u"verticalLayout_5")
        self.verticalLayout_5.setSizeConstraint(QLayout.SizeConstraint.SetNoConstraint)
        self.verticalLayout_5.setContentsMargins(1, 5, 1, 7)
        self.historyLabel = QLabel(self.rightVerticalFrame)
        self.historyLabel.setObjectName(u"historyLabel")
        self.historyLabel.setMinimumSize(QSize(165, 30))
        self.historyLabel.setMaximumSize(QSize(16777215, 34))
        self.historyLabel.setFont(font4)
        self.historyLabel.setStyleSheet(u"#historyLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"	padding-top: 5px;\n"
"	padding-left: 5px;\n"
"}")
        self.historyLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.historyLabel.setWordWrap(False)

        self.verticalLayout_5.addWidget(self.historyLabel)

        self.historyTableWidget = QTableWidget(self.rightVerticalFrame)
        if (self.historyTableWidget.columnCount() < 6):
            self.historyTableWidget.setColumnCount(6)
        __qtablewidgetitem = QTableWidgetItem()
        self.historyTableWidget.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.historyTableWidget.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.historyTableWidget.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.historyTableWidget.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        __qtablewidgetitem4 = QTableWidgetItem()
        self.historyTableWidget.setHorizontalHeaderItem(4, __qtablewidgetitem4)
        __qtablewidgetitem5 = QTableWidgetItem()
        self.historyTableWidget.setHorizontalHeaderItem(5, __qtablewidgetitem5)
        self.historyTableWidget.setObjectName(u"historyTableWidget")
        sizePolicy.setHeightForWidth(self.historyTableWidget.sizePolicy().hasHeightForWidth())
        self.historyTableWidget.setSizePolicy(sizePolicy)
        self.historyTableWidget.setMinimumSize(QSize(550, 570))
        self.historyTableWidget.setFont(font3)
        self.historyTableWidget.setMouseTracking(True)
        self.historyTableWidget.setTabletTracking(True)
        self.historyTableWidget.setToolTipDuration(-1)
        self.historyTableWidget.setStyleSheet(u"#historyTableWidget {\n"
"    border-radius: 8px;\n"
"    background-color: transparent;\n"
"    color: black;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"    gridline-color: black;\n"
"    border: none;\n"
"}\n"
"\n"
"#historyTableWidget QHeaderView::section {\n"
"    background-color: rgba(204, 204, 204, 0.6);\n"
"    color: black;\n"
"    font-size: 14px;\n"
"    font-weight: bold;\n"
"    border-right: 1px solid black;\n"
"    border-top: none;\n"
"    border-left: none;\n"
"    border-bottom: 2px solid black;\n"
"}\n"
"\n"
"#historyTableWidget::item {\n"
"    border: none;\n"
"}\n"
"\n"
"#historyTableWidget::item:selected {\n"
"    background: transparent;\n"
"     color: black;\n"
"    border: none;\n"
"}\n"
"\n"
"#historyTableWidget::focus {\n"
"    outline: none;\n"
"}\n"
"\n"
"#historyTableWidget::corner {\n"
"    background-color: #f3f3f3;\n"
"    border-top-left-radius: 8px;\n"
"}\n"
"\n"
"#historyTableWidget QScrollBar:vertical, #historyTableWidget QScrollBar:horizontal {\n"
"    backg"
                        "round-color: rgb(250, 250, 250);\n"
"    border: 1px solid rgb(153, 153, 153);\n"
"    width: 10px;\n"
"    height: 10px; \n"
"    margin: 0px 0px 0px 0px;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#historyTableWidget QScrollBar::handle:vertical,  #historyTableWidget QScrollBar::handle:horizontal {\n"
"    background-color: black;\n"
"    min-height: 100px;\n"
"    border: 0px solid black;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#historyTableWidget QScrollBar::add-line:vertical, #historyTableWidget QScrollBar::add-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: bottom;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"#historyTableWidget QScrollBar::sub-line:vertical, #historyTableWidget QScrollBar::sub-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: top;\n"
"    subcontrol-origin: margin;\n"
"}")
        self.historyTableWidget.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.historyTableWidget.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.historyTableWidget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.historyTableWidget.setTabKeyNavigation(False)
        self.historyTableWidget.setProperty(u"showDropIndicator", False)
        self.historyTableWidget.setDragDropOverwriteMode(False)
        self.historyTableWidget.setAlternatingRowColors(False)
        self.historyTableWidget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.historyTableWidget.setTextElideMode(Qt.TextElideMode.ElideLeft)
        self.historyTableWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.historyTableWidget.horizontalHeader().setMinimumSectionSize(90)
        self.historyTableWidget.horizontalHeader().setDefaultSectionSize(90)
        self.historyTableWidget.horizontalHeader().setProperty(u"showSortIndicator", False)
        self.historyTableWidget.horizontalHeader().setStretchLastSection(True)
        self.historyTableWidget.verticalHeader().setVisible(False)
        self.historyTableWidget.verticalHeader().setMinimumSectionSize(30)
        self.historyTableWidget.verticalHeader().setDefaultSectionSize(30)
        self.historyTableWidget.verticalHeader().setProperty(u"showSortIndicator", False)
        self.historyTableWidget.verticalHeader().setStretchLastSection(False)

        self.verticalLayout_5.addWidget(self.historyTableWidget)


        self.horizontalLayout_7.addWidget(self.rightVerticalFrame)

        self.rightVerticalFrame.raise_()
        self.leftVerticalFrame.raise_()

        self.gridLayout_2.addWidget(self.homepageFrame, 0, 0, 1, 1)

        self.stackedWidget.addWidget(self.homePage)
        self.analyticsPage = QWidget()
        self.analyticsPage.setObjectName(u"analyticsPage")
        self.gridLayout_3 = QGridLayout(self.analyticsPage)
        self.gridLayout_3.setSpacing(0)
        self.gridLayout_3.setObjectName(u"gridLayout_3")
        self.gridLayout_3.setContentsMargins(0, 0, 0, 0)
        self.analyticsHorizontalFrame = QFrame(self.analyticsPage)
        self.analyticsHorizontalFrame.setObjectName(u"analyticsHorizontalFrame")
        self.analyticsHorizontalFrame.setMinimumSize(QSize(0, 660))
        self.analyticsHorizontalFrame.setFont(font6)
        self.verticalLayout_6 = QVBoxLayout(self.analyticsHorizontalFrame)
        self.verticalLayout_6.setSpacing(0)
        self.verticalLayout_6.setObjectName(u"verticalLayout_6")
        self.verticalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.analyticsYearHorizontalFrame = QFrame(self.analyticsHorizontalFrame)
        self.analyticsYearHorizontalFrame.setObjectName(u"analyticsYearHorizontalFrame")
        self.analyticsYearHorizontalFrame.setMinimumSize(QSize(0, 45))
        self.analyticsYearHorizontalFrame.setMaximumSize(QSize(16777215, 45))
        self.horizontalLayout_12 = QHBoxLayout(self.analyticsYearHorizontalFrame)
        self.horizontalLayout_12.setSpacing(5)
        self.horizontalLayout_12.setObjectName(u"horizontalLayout_12")
        self.horizontalLayout_12.setContentsMargins(16, 10, 0, 0)
        self.analyticsYearSelectionLabel = QLabel(self.analyticsYearHorizontalFrame)
        self.analyticsYearSelectionLabel.setObjectName(u"analyticsYearSelectionLabel")
        self.analyticsYearSelectionLabel.setMinimumSize(QSize(115, 35))
        self.analyticsYearSelectionLabel.setMaximumSize(QSize(115, 16777215))
        self.analyticsYearSelectionLabel.setFont(font4)
        self.analyticsYearSelectionLabel.setStyleSheet(u"#analyticsYearSelectionLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 21px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.analyticsYearSelectionLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.analyticsYearSelectionLabel.setWordWrap(False)

        self.horizontalLayout_12.addWidget(self.analyticsYearSelectionLabel)

        self.analyticsYearComboBoxFrame = QFrame(self.analyticsYearHorizontalFrame)
        self.analyticsYearComboBoxFrame.setObjectName(u"analyticsYearComboBoxFrame")
        self.analyticsYearComboBoxFrame.setMinimumSize(QSize(100, 32))
        self.analyticsYearComboBoxFrame.setMaximumSize(QSize(100, 32))
        self.analyticsYearComboBoxFrame.setFont(font6)
        self.analyticsYearComboBoxFrame.setStyleSheet(u"#analyticsYearComboBoxFrame {\n"
"    background-color: #f3f3f3;\n"
"    color: black;\n"
"    border: 2px solid lightgray; \n"
"    border-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.analyticsYearComboBoxFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.analyticsYearComboBoxFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.analyticsYearComboBoxArrow = QFrame(self.analyticsYearComboBoxFrame)
        self.analyticsYearComboBoxArrow.setObjectName(u"analyticsYearComboBoxArrow")
        self.analyticsYearComboBoxArrow.setGeometry(QRect(75, 0, 24, 32))
        self.analyticsYearComboBoxArrow.setMinimumSize(QSize(24, 32))
        self.analyticsYearComboBoxArrow.setMaximumSize(QSize(22, 32))
        self.analyticsYearComboBoxArrow.setFont(font6)
        self.analyticsYearComboBoxArrow.setStyleSheet(u"#analyticsYearComboBoxArrow {\n"
"    background-color: lightgray;\n"
"    color: black;\n"
"    border-top-right-radius: 10px;\n"
"    border-bottom-right-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.analyticsYearComboBoxArrow.setFrameShape(QFrame.Shape.StyledPanel)
        self.analyticsYearComboBoxArrow.setFrameShadow(QFrame.Shadow.Raised)
        self.analyticsYearComboBox = QComboBox(self.analyticsYearComboBoxFrame)
        self.analyticsYearComboBox.addItem("")
        self.analyticsYearComboBox.addItem("")
        self.analyticsYearComboBox.setObjectName(u"analyticsYearComboBox")
        self.analyticsYearComboBox.setEnabled(True)
        self.analyticsYearComboBox.setGeometry(QRect(0, 0, 100, 32))
        self.analyticsYearComboBox.setMinimumSize(QSize(100, 32))
        self.analyticsYearComboBox.setMaximumSize(QSize(100, 32))
        self.analyticsYearComboBox.setFont(font3)
        self.analyticsYearComboBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.analyticsYearComboBox.setStyleSheet(u"#analyticsYearComboBox {\n"
"    background-color: transparent;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"    border: 2px outset transparent;\n"
"    border-radius: 10px;\n"
"    padding: 4px;\n"
"	padding-left: 10px;\n"
"}\n"
"\n"
"#analyticsYearComboBox QAbstractItemView {\n"
"    background-color:  #f3f3f3;\n"
"    selection-background-color: rgb(95, 97, 109);\n"
"    color: rgb(0, 0, 0);\n"
"    border: 1px solid black;\n"
"    padding: 10px;\n"
"    padding-left: 5px;\n"
"    padding-right: 5px;\n"
"}\n"
"\n"
"#analyticsYearComboBox QAbstractItemView::item:hover { \n"
"    background-color: rgba(0, 0, 0, 0.07);\n"
"    color: black;\n"
"    border-radius: 6px;\n"
"    padding-left: 8px;\n"
"}\n"
"\n"
"#analyticsYearComboBox QAbstractItemView::item:selected { \n"
"    color: black;\n"
"    border: none;\n"
"    outline: none;\n"
"}\n"
"\n"
"#analyticsYearComboBox QListView{\n"
"    outline: 0px;\n"
"}")

        self.horizontalLayout_12.addWidget(self.analyticsYearComboBoxFrame)

        self.horizontalSpacer_13 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_12.addItem(self.horizontalSpacer_13)


        self.verticalLayout_6.addWidget(self.analyticsYearHorizontalFrame)

        self.chartsVerticalFrame = QFrame(self.analyticsHorizontalFrame)
        self.chartsVerticalFrame.setObjectName(u"chartsVerticalFrame")
        self.chartsVerticalFrame.setMaximumSize(QSize(16777215, 550))
        self.horizontalLayout_13 = QHBoxLayout(self.chartsVerticalFrame)
        self.horizontalLayout_13.setSpacing(0)
        self.horizontalLayout_13.setObjectName(u"horizontalLayout_13")
        self.horizontalLayout_13.setContentsMargins(0, 0, 0, 0)
        self.cardsHorizontalFrame = QFrame(self.chartsVerticalFrame)
        self.cardsHorizontalFrame.setObjectName(u"cardsHorizontalFrame")
        self.cardsHorizontalFrame.setMinimumSize(QSize(493, 307))
        self.cardsHorizontalFrame.setMaximumSize(QSize(700, 16777215))
        self.horizontalLayout_14 = QHBoxLayout(self.cardsHorizontalFrame)
        self.horizontalLayout_14.setSpacing(10)
        self.horizontalLayout_14.setObjectName(u"horizontalLayout_14")
        self.horizontalLayout_14.setContentsMargins(15, 10, 0, 10)
        self.attacksPerMonthVerticalFrame = QFrame(self.cardsHorizontalFrame)
        self.attacksPerMonthVerticalFrame.setObjectName(u"attacksPerMonthVerticalFrame")
        self.attacksPerMonthVerticalFrame.setMinimumSize(QSize(150, 0))
        self.attacksPerMonthVerticalFrame.setStyleSheet(u"#attacksPerMonthVerticalFrame {\n"
"	background-color: rgba(204, 204, 204, 0.6);\n"
"	border-radius: 20px;\n"
"    border: 2px solid black; \n"
"	color: black;\n"
"}")
        self.verticalLayout_7 = QVBoxLayout(self.attacksPerMonthVerticalFrame)
        self.verticalLayout_7.setSpacing(0)
        self.verticalLayout_7.setObjectName(u"verticalLayout_7")
        self.verticalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.verticalSpacer_4 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_7.addItem(self.verticalSpacer_4)

        self.attacksPerMonthTitleLabel = QLabel(self.attacksPerMonthVerticalFrame)
        self.attacksPerMonthTitleLabel.setObjectName(u"attacksPerMonthTitleLabel")
        self.attacksPerMonthTitleLabel.setMinimumSize(QSize(0, 0))
        self.attacksPerMonthTitleLabel.setMaximumSize(QSize(16777215, 110))
        self.attacksPerMonthTitleLabel.setFont(font4)
        self.attacksPerMonthTitleLabel.setStyleSheet(u"#attacksPerMonthTitleLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 21px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.attacksPerMonthTitleLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.attacksPerMonthTitleLabel.setWordWrap(True)

        self.verticalLayout_7.addWidget(self.attacksPerMonthTitleLabel)

        self.verticalSpacer_5 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_7.addItem(self.verticalSpacer_5)

        self.attacksPerMonthValueLabel = QLabel(self.attacksPerMonthVerticalFrame)
        self.attacksPerMonthValueLabel.setObjectName(u"attacksPerMonthValueLabel")
        self.attacksPerMonthValueLabel.setMinimumSize(QSize(0, 0))
        self.attacksPerMonthValueLabel.setMaximumSize(QSize(16777215, 16777215))
        font7 = QFont()
        font7.setFamilies([u"Days One"])
        font7.setBold(True)
        self.attacksPerMonthValueLabel.setFont(font7)
        self.attacksPerMonthValueLabel.setStyleSheet(u"#attacksPerMonthValueLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"	font-size: 60px;\n"
"    font-family: Days One;\n"
"    font-weight: bold;\n"
"	margin: 10px;\n"
"}")
        self.attacksPerMonthValueLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.attacksPerMonthValueLabel.setWordWrap(False)

        self.verticalLayout_7.addWidget(self.attacksPerMonthValueLabel)

        self.verticalSpacer_6 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_7.addItem(self.verticalSpacer_6)

        self.verticalSpacer_7 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_7.addItem(self.verticalSpacer_7)


        self.horizontalLayout_14.addWidget(self.attacksPerMonthVerticalFrame)

        self.totalNumOfAttacksVerticalFrame = QFrame(self.cardsHorizontalFrame)
        self.totalNumOfAttacksVerticalFrame.setObjectName(u"totalNumOfAttacksVerticalFrame")
        self.totalNumOfAttacksVerticalFrame.setMinimumSize(QSize(150, 0))
        self.totalNumOfAttacksVerticalFrame.setStyleSheet(u"#totalNumOfAttacksVerticalFrame {\n"
"	background-color: rgba(204, 204, 204, 0.6);\n"
"	border-radius: 20px;\n"
"    border: 2px solid black; \n"
"	color: black;\n"
"}")
        self.verticalLayout_8 = QVBoxLayout(self.totalNumOfAttacksVerticalFrame)
        self.verticalLayout_8.setSpacing(0)
        self.verticalLayout_8.setObjectName(u"verticalLayout_8")
        self.verticalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.verticalSpacer_8 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_8.addItem(self.verticalSpacer_8)

        self.totalNumOfAttacksTitleLabel = QLabel(self.totalNumOfAttacksVerticalFrame)
        self.totalNumOfAttacksTitleLabel.setObjectName(u"totalNumOfAttacksTitleLabel")
        self.totalNumOfAttacksTitleLabel.setMinimumSize(QSize(0, 0))
        self.totalNumOfAttacksTitleLabel.setMaximumSize(QSize(16777215, 110))
        self.totalNumOfAttacksTitleLabel.setFont(font4)
        self.totalNumOfAttacksTitleLabel.setStyleSheet(u"#totalNumOfAttacksTitleLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 21px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.totalNumOfAttacksTitleLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.totalNumOfAttacksTitleLabel.setWordWrap(True)

        self.verticalLayout_8.addWidget(self.totalNumOfAttacksTitleLabel)

        self.verticalSpacer_9 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_8.addItem(self.verticalSpacer_9)

        self.totalNumOfAttacksValueLabel = QLabel(self.totalNumOfAttacksVerticalFrame)
        self.totalNumOfAttacksValueLabel.setObjectName(u"totalNumOfAttacksValueLabel")
        sizePolicy.setHeightForWidth(self.totalNumOfAttacksValueLabel.sizePolicy().hasHeightForWidth())
        self.totalNumOfAttacksValueLabel.setSizePolicy(sizePolicy)
        self.totalNumOfAttacksValueLabel.setMinimumSize(QSize(0, 0))
        self.totalNumOfAttacksValueLabel.setMaximumSize(QSize(16777215, 16777215))
        self.totalNumOfAttacksValueLabel.setFont(font7)
        self.totalNumOfAttacksValueLabel.setStyleSheet(u"#totalNumOfAttacksValueLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"	font-size: 60px;\n"
"    font-family: Days One;\n"
"    font-weight: bold;\n"
"	margin: 10px;\n"
"}")
        self.totalNumOfAttacksValueLabel.setScaledContents(False)
        self.totalNumOfAttacksValueLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.totalNumOfAttacksValueLabel.setWordWrap(False)
        self.totalNumOfAttacksValueLabel.setMargin(0)

        self.verticalLayout_8.addWidget(self.totalNumOfAttacksValueLabel)

        self.verticalSpacer_10 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_8.addItem(self.verticalSpacer_10)

        self.verticalSpacer_11 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_8.addItem(self.verticalSpacer_11)


        self.horizontalLayout_14.addWidget(self.totalNumOfAttacksVerticalFrame)

        self.mostPopularAttackVerticalFrame = QFrame(self.cardsHorizontalFrame)
        self.mostPopularAttackVerticalFrame.setObjectName(u"mostPopularAttackVerticalFrame")
        self.mostPopularAttackVerticalFrame.setMinimumSize(QSize(150, 0))
        self.mostPopularAttackVerticalFrame.setStyleSheet(u"#mostPopularAttackVerticalFrame {\n"
"	background-color: rgba(204, 204, 204, 0.6);\n"
"	border-radius: 20px;\n"
"    border: 2px solid black; \n"
"	color: black;\n"
"}")
        self.verticalLayout_9 = QVBoxLayout(self.mostPopularAttackVerticalFrame)
        self.verticalLayout_9.setSpacing(0)
        self.verticalLayout_9.setObjectName(u"verticalLayout_9")
        self.verticalLayout_9.setContentsMargins(0, 0, 0, 0)
        self.verticalSpacer_12 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_9.addItem(self.verticalSpacer_12)

        self.mostPopularAttackTitleLabel = QLabel(self.mostPopularAttackVerticalFrame)
        self.mostPopularAttackTitleLabel.setObjectName(u"mostPopularAttackTitleLabel")
        self.mostPopularAttackTitleLabel.setMinimumSize(QSize(0, 0))
        self.mostPopularAttackTitleLabel.setMaximumSize(QSize(16777215, 110))
        self.mostPopularAttackTitleLabel.setFont(font4)
        self.mostPopularAttackTitleLabel.setStyleSheet(u"#mostPopularAttackTitleLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"    font-size: 21px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.mostPopularAttackTitleLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.mostPopularAttackTitleLabel.setWordWrap(True)

        self.verticalLayout_9.addWidget(self.mostPopularAttackTitleLabel)

        self.verticalSpacer_13 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_9.addItem(self.verticalSpacer_13)

        self.mostPopularAttackValueLabel = QLabel(self.mostPopularAttackVerticalFrame)
        self.mostPopularAttackValueLabel.setObjectName(u"mostPopularAttackValueLabel")
        self.mostPopularAttackValueLabel.setMinimumSize(QSize(0, 97))
        self.mostPopularAttackValueLabel.setMaximumSize(QSize(16777215, 16777215))
        self.mostPopularAttackValueLabel.setFont(font7)
        self.mostPopularAttackValueLabel.setStyleSheet(u"#mostPopularAttackValueLabel {\n"
"	background-color: transparent;\n"
"	color: black;\n"
"	font-size: 23px;\n"
"    font-family: Days One;\n"
"    font-weight: bold;\n"
"	margin: 10px;\n"
"    margin-top: 0px;\n"
"}")
        self.mostPopularAttackValueLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.mostPopularAttackValueLabel.setWordWrap(True)

        self.verticalLayout_9.addWidget(self.mostPopularAttackValueLabel)

        self.verticalSpacer_14 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_9.addItem(self.verticalSpacer_14)

        self.verticalSpacer_15 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_9.addItem(self.verticalSpacer_15)


        self.horizontalLayout_14.addWidget(self.mostPopularAttackVerticalFrame)


        self.horizontalLayout_13.addWidget(self.cardsHorizontalFrame)

        self.barChartVerticalFrame = QFrame(self.chartsVerticalFrame)
        self.barChartVerticalFrame.setObjectName(u"barChartVerticalFrame")
        self.barChartVerticalFrame.setMinimumSize(QSize(0, 307))
        self.barChartVerticalFrame.setMaximumSize(QSize(16777215, 16777215))
        self.barChartVerticalFrame.setStyleSheet(u"#barChartVerticalFrame { \n"
"    background-color: rgba(204, 204, 204, 0.6);\n"
"    border: 2px solid black; \n"
"    border-radius: 20px;\n"
"    margin: 10px 15px 10px 10px;\n"
"    color: black;\n"
"}")

        self.horizontalLayout_13.addWidget(self.barChartVerticalFrame)


        self.verticalLayout_6.addWidget(self.chartsVerticalFrame)

        self.histogramChartVerticalFrame = QFrame(self.analyticsHorizontalFrame)
        self.histogramChartVerticalFrame.setObjectName(u"histogramChartVerticalFrame")
        self.histogramChartVerticalFrame.setMinimumSize(QSize(0, 307))
        self.histogramChartVerticalFrame.setStyleSheet(u"#histogramChartVerticalFrame { \n"
"    background-color: rgba(204, 204, 204, 0.6);\n"
"    border: 2px solid black; \n"
"    border-radius: 20px;\n"
"    margin: 0px 15px 10px 15px;\n"
"    color: black;\n"
"}")

        self.verticalLayout_6.addWidget(self.histogramChartVerticalFrame)


        self.gridLayout_3.addWidget(self.analyticsHorizontalFrame, 0, 0, 1, 1)

        self.stackedWidget.addWidget(self.analyticsPage)
        self.reportPage = QWidget()
        self.reportPage.setObjectName(u"reportPage")
        self.gridLayout_4 = QGridLayout(self.reportPage)
        self.gridLayout_4.setSpacing(0)
        self.gridLayout_4.setObjectName(u"gridLayout_4")
        self.gridLayout_4.setContentsMargins(0, 0, 0, 0)
        self.reportPreviewHorizontalFrame = QFrame(self.reportPage)
        self.reportPreviewHorizontalFrame.setObjectName(u"reportPreviewHorizontalFrame")
        self.reportPreviewHorizontalFrame.setMinimumSize(QSize(0, 660))
        self.horizontalLayout_15 = QHBoxLayout(self.reportPreviewHorizontalFrame)
        self.horizontalLayout_15.setSpacing(0)
        self.horizontalLayout_15.setObjectName(u"horizontalLayout_15")
        self.horizontalLayout_15.setContentsMargins(20, 20, 10, 10)
        self.reportSelectionVerticalFrameOutside = QFrame(self.reportPreviewHorizontalFrame)
        self.reportSelectionVerticalFrameOutside.setObjectName(u"reportSelectionVerticalFrameOutside")
        self.reportSelectionVerticalFrameOutside.setMinimumSize(QSize(250, 0))
        self.reportSelectionVerticalFrameOutside.setMaximumSize(QSize(250, 16777215))
        self.verticalLayout_10 = QVBoxLayout(self.reportSelectionVerticalFrameOutside)
        self.verticalLayout_10.setSpacing(15)
        self.verticalLayout_10.setObjectName(u"verticalLayout_10")
        self.verticalLayout_10.setContentsMargins(0, 0, 10, 20)
        self.reportSelectionLabel = QLabel(self.reportSelectionVerticalFrameOutside)
        self.reportSelectionLabel.setObjectName(u"reportSelectionLabel")
        self.reportSelectionLabel.setMinimumSize(QSize(180, 40))
        self.reportSelectionLabel.setMaximumSize(QSize(16777215, 16777215))
        self.reportSelectionLabel.setFont(font4)
        self.reportSelectionLabel.setStyleSheet(u"#reportSelectionLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.reportSelectionLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.reportSelectionLabel.setWordWrap(False)

        self.verticalLayout_10.addWidget(self.reportSelectionLabel)

        self.reportSelectionVerticalFrameInside = QFrame(self.reportSelectionVerticalFrameOutside)
        self.reportSelectionVerticalFrameInside.setObjectName(u"reportSelectionVerticalFrameInside")
        self.reportSelectionVerticalFrameInside.setMinimumSize(QSize(240, 0))
        self.reportSelectionVerticalFrameInside.setMaximumSize(QSize(240, 16777215))
        self.reportSelectionVerticalFrameInside.setStyleSheet(u"")
        self.verticalLayout_11 = QVBoxLayout(self.reportSelectionVerticalFrameInside)
        self.verticalLayout_11.setSpacing(8)
        self.verticalLayout_11.setObjectName(u"verticalLayout_11")
        self.verticalLayout_11.setContentsMargins(10, 20, 20, 20)
        self.reportDurationComboBoxFrame = QFrame(self.reportSelectionVerticalFrameInside)
        self.reportDurationComboBoxFrame.setObjectName(u"reportDurationComboBoxFrame")
        self.reportDurationComboBoxFrame.setMinimumSize(QSize(210, 32))
        self.reportDurationComboBoxFrame.setMaximumSize(QSize(210, 32))
        self.reportDurationComboBoxFrame.setFont(font6)
        self.reportDurationComboBoxFrame.setStyleSheet(u"#reportDurationComboBoxFrame {\n"
"    background-color: #f3f3f3;\n"
"    color: black;\n"
"    border: 2px solid lightgray; \n"
"    border-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.reportDurationComboBoxFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.reportDurationComboBoxFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.reportDurationComboBoxArrow = QFrame(self.reportDurationComboBoxFrame)
        self.reportDurationComboBoxArrow.setObjectName(u"reportDurationComboBoxArrow")
        self.reportDurationComboBoxArrow.setGeometry(QRect(186, 0, 24, 32))
        self.reportDurationComboBoxArrow.setMinimumSize(QSize(24, 32))
        self.reportDurationComboBoxArrow.setMaximumSize(QSize(22, 32))
        self.reportDurationComboBoxArrow.setFont(font6)
        self.reportDurationComboBoxArrow.setStyleSheet(u"#reportDurationComboBoxArrow {\n"
"    background-color: lightgray;\n"
"    color: black;\n"
"    border-top-right-radius: 10px;\n"
"    border-bottom-right-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.reportDurationComboBoxArrow.setFrameShape(QFrame.Shape.StyledPanel)
        self.reportDurationComboBoxArrow.setFrameShadow(QFrame.Shadow.Raised)
        self.reportDurationComboBox = QComboBox(self.reportDurationComboBoxFrame)
        self.reportDurationComboBox.addItem("")
        self.reportDurationComboBox.addItem("")
        self.reportDurationComboBox.addItem("")
        self.reportDurationComboBox.addItem("")
        self.reportDurationComboBox.addItem("")
        self.reportDurationComboBox.setObjectName(u"reportDurationComboBox")
        self.reportDurationComboBox.setEnabled(False)
        self.reportDurationComboBox.setGeometry(QRect(0, 0, 210, 32))
        self.reportDurationComboBox.setMinimumSize(QSize(210, 32))
        self.reportDurationComboBox.setMaximumSize(QSize(210, 32))
        self.reportDurationComboBox.setFont(font3)
        self.reportDurationComboBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.reportDurationComboBox.setStyleSheet(u"#reportDurationComboBox {\n"
"    background-color: transparent;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"    border: 2px outset transparent;\n"
"    border-radius: 10px;\n"
"    padding: 4px;\n"
"	padding-left: 10px;\n"
"}\n"
"\n"
"#reportDurationComboBox QAbstractItemView {\n"
"    background-color:  #f3f3f3;\n"
"    selection-background-color: rgb(95, 97, 109);\n"
"    color: rgb(0, 0, 0);\n"
"    border: 1px solid black;\n"
"    padding: 10px;\n"
"    padding-left: 5px;\n"
"    padding-right: 5px;\n"
"}\n"
"\n"
"#reportDurationComboBox QAbstractItemView::item:hover { \n"
"    background-color: rgba(0, 0, 0, 0.07);\n"
"    color: black;\n"
"    border-radius: 6px;\n"
"    padding-left: 8px;\n"
"}\n"
"\n"
"#reportDurationComboBox QAbstractItemView::item:selected { \n"
"    color: black;\n"
"    border: none;\n"
"    outline: none;\n"
"}\n"
"\n"
"#reportDurationComboBox QListView{\n"
"    outline: 0px;\n"
"}")

        self.verticalLayout_11.addWidget(self.reportDurationComboBoxFrame)

        self.horizontalLine1 = QFrame(self.reportSelectionVerticalFrameInside)
        self.horizontalLine1.setObjectName(u"horizontalLine1")
        self.horizontalLine1.setMinimumSize(QSize(210, 40))
        self.horizontalLine1.setStyleSheet(u"#horizontalLine1 {\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLine1.setFrameShadow(QFrame.Shadow.Plain)
        self.horizontalLine1.setLineWidth(2)
        self.horizontalLine1.setFrameShape(QFrame.Shape.HLine)

        self.verticalLayout_11.addWidget(self.horizontalLine1)

        self.arpSpoofingCheckBox = QCheckBox(self.reportSelectionVerticalFrameInside)
        self.arpSpoofingCheckBox.setObjectName(u"arpSpoofingCheckBox")
        self.arpSpoofingCheckBox.setMaximumSize(QSize(16777215, 30))
        self.arpSpoofingCheckBox.setFont(font3)
        self.arpSpoofingCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.arpSpoofingCheckBox.setStyleSheet(u"#arpSpoofingCheckBox {\n"
"    spacing: 10px;\n"
"    color: #f3f3f3;\n"
"    font-size: 17px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#arpSpoofingCheckBox::indicator {\n"
"    width: 16px;\n"
"    height: 16px;\n"
"}\n"
"\n"
"#arpSpoofingCheckBox::indicator:checked {\n"
"    background-color: #3a8e32;\n"
"    border: 2px solid #2e7128;\n"
"}\n"
"\n"
"#arpSpoofingCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"#arpSpoofingCheckBox::indicator:hover {\n"
"    border: 2px solid #4d9946;\n"
"}")
        self.arpSpoofingCheckBox.setChecked(True)

        self.verticalLayout_11.addWidget(self.arpSpoofingCheckBox)

        self.portScanningCheckBox = QCheckBox(self.reportSelectionVerticalFrameInside)
        self.portScanningCheckBox.setObjectName(u"portScanningCheckBox")
        self.portScanningCheckBox.setMaximumSize(QSize(16777215, 30))
        self.portScanningCheckBox.setFont(font3)
        self.portScanningCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.portScanningCheckBox.setStyleSheet(u"#portScanningCheckBox {\n"
"    spacing: 10px;\n"
"    color: #f3f3f3;\n"
"    font-size: 17px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#portScanningCheckBox::indicator {\n"
"    width: 16px;\n"
"    height: 16px;\n"
"}\n"
"\n"
"#portScanningCheckBox::indicator:checked {\n"
"    background-color: #3a8e32;\n"
"    border: 2px solid #2e7128;\n"
"}\n"
"\n"
"#portScanningCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"#portScanningCheckBox::indicator:hover {\n"
"    border: 2px solid #4d9946;\n"
"}")
        self.portScanningCheckBox.setChecked(True)

        self.verticalLayout_11.addWidget(self.portScanningCheckBox)

        self.denialOfServiceCheckBox = QCheckBox(self.reportSelectionVerticalFrameInside)
        self.denialOfServiceCheckBox.setObjectName(u"denialOfServiceCheckBox")
        self.denialOfServiceCheckBox.setMaximumSize(QSize(16777215, 30))
        self.denialOfServiceCheckBox.setFont(font3)
        self.denialOfServiceCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.denialOfServiceCheckBox.setStyleSheet(u"#denialOfServiceCheckBox {\n"
"    spacing: 10px;\n"
"    color: #f3f3f3;\n"
"    font-size: 17px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#denialOfServiceCheckBox::indicator {\n"
"    width: 16px;\n"
"    height: 16px;\n"
"}\n"
"\n"
"#denialOfServiceCheckBox::indicator:checked {\n"
"    background-color: #3a8e32;\n"
"    border: 2px solid #2e7128;\n"
"}\n"
"\n"
"#denialOfServiceCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"#denialOfServiceCheckBox::indicator:hover {\n"
"    border: 2px solid #4d9946;\n"
"}")
        self.denialOfServiceCheckBox.setChecked(True)

        self.verticalLayout_11.addWidget(self.denialOfServiceCheckBox)

        self.dnsTunnelingCheckBox = QCheckBox(self.reportSelectionVerticalFrameInside)
        self.dnsTunnelingCheckBox.setObjectName(u"dnsTunnelingCheckBox")
        self.dnsTunnelingCheckBox.setMaximumSize(QSize(16777215, 30))
        self.dnsTunnelingCheckBox.setFont(font3)
        self.dnsTunnelingCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.dnsTunnelingCheckBox.setStyleSheet(u"#dnsTunnelingCheckBox {\n"
"    spacing: 10px;\n"
"    color: #f3f3f3;\n"
"    font-size: 17px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#dnsTunnelingCheckBox::indicator {\n"
"    width: 16px;\n"
"    height: 16px;\n"
"}\n"
"\n"
"#dnsTunnelingCheckBox::indicator:checked {\n"
"    background-color: #3a8e32;\n"
"    border: 2px solid #2e7128;\n"
"}\n"
"\n"
"#dnsTunnelingCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"#dnsTunnelingCheckBox::indicator:hover {\n"
"    border: 2px solid #4d9946;\n"
"}")
        self.dnsTunnelingCheckBox.setChecked(True)

        self.verticalLayout_11.addWidget(self.dnsTunnelingCheckBox)

        self.horizontalLine2 = QFrame(self.reportSelectionVerticalFrameInside)
        self.horizontalLine2.setObjectName(u"horizontalLine2")
        self.horizontalLine2.setMinimumSize(QSize(210, 40))
        self.horizontalLine2.setStyleSheet(u"#horizontalLine2 {\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLine2.setFrameShadow(QFrame.Shadow.Plain)
        self.horizontalLine2.setLineWidth(2)
        self.horizontalLine2.setFrameShape(QFrame.Shape.HLine)

        self.verticalLayout_11.addWidget(self.horizontalLine2)

        self.machineInfoCheckBox = QCheckBox(self.reportSelectionVerticalFrameInside)
        self.machineInfoCheckBox.setObjectName(u"machineInfoCheckBox")
        self.machineInfoCheckBox.setMaximumSize(QSize(16777215, 30))
        self.machineInfoCheckBox.setFont(font3)
        self.machineInfoCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.machineInfoCheckBox.setStyleSheet(u"#machineInfoCheckBox {\n"
"    spacing: 10px;\n"
"    color: #f3f3f3;\n"
"    font-size: 17px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#machineInfoCheckBox::indicator {\n"
"    width: 16px;\n"
"    height: 16px;\n"
"}\n"
"\n"
"#machineInfoCheckBox::indicator:checked {\n"
"    background-color: #3a8e32;\n"
"    border: 2px solid #2e7128;\n"
"}\n"
"\n"
"#machineInfoCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"#machineInfoCheckBox::indicator:hover {\n"
"    border: 2px solid #4d9946;\n"
"}")

        self.verticalLayout_11.addWidget(self.machineInfoCheckBox)

        self.downloadReportButtonVerticalFrame = QFrame(self.reportSelectionVerticalFrameInside)
        self.downloadReportButtonVerticalFrame.setObjectName(u"downloadReportButtonVerticalFrame")
        self.downloadReportButtonVerticalFrame.setMaximumSize(QSize(16777215, 16777215))
        self.downloadReportButtonVerticalFrame.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.verticalLayout_12 = QVBoxLayout(self.downloadReportButtonVerticalFrame)
        self.verticalLayout_12.setSpacing(10)
        self.verticalLayout_12.setObjectName(u"verticalLayout_12")
        self.verticalLayout_12.setSizeConstraint(QLayout.SizeConstraint.SetDefaultConstraint)
        self.verticalLayout_12.setContentsMargins(25, 15, 25, 9)
        self.downloadReportPushButton = QPushButton(self.downloadReportButtonVerticalFrame)
        self.downloadReportPushButton.setObjectName(u"downloadReportPushButton")
        self.downloadReportPushButton.setMinimumSize(QSize(160, 31))
        self.downloadReportPushButton.setMaximumSize(QSize(160, 31))
        self.downloadReportPushButton.setFont(font4)
        self.downloadReportPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.downloadReportPushButton.setStyleSheet(u"#downloadReportPushButton  {\n"
"    background-color: #4e4f5a;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: #f3f3f3;\n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#downloadReportPushButton:hover {\n"
"    background-color: #464751; \n"
"	border-color: #d7d7d7;\n"
"}\n"
"\n"
"#downloadReportPushButton:pressed {\n"
"    background-color: #383840; \n"
"	border-color:#d7d7d7;\n"
"}")

        self.verticalLayout_12.addWidget(self.downloadReportPushButton)

        self.cancelReportPushButton = QPushButton(self.downloadReportButtonVerticalFrame)
        self.cancelReportPushButton.setObjectName(u"cancelReportPushButton")
        self.cancelReportPushButton.setMinimumSize(QSize(160, 31))
        self.cancelReportPushButton.setMaximumSize(QSize(160, 31))
        self.cancelReportPushButton.setFont(font4)
        self.cancelReportPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancelReportPushButton.setStyleSheet(u"#cancelReportPushButton  {\n"
"    background-color: #d84f4f;\n"
"    border: 1px solid black;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: black; \n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#cancelReportPushButton:hover {\n"
"     background-color: #db6060;\n"
"}\n"
"\n"
" #cancelReportPushButton:pressed {\n"
"    background-color: #ac3f3f;\n"
"}")

        self.verticalLayout_12.addWidget(self.cancelReportPushButton)

        self.reportProgressBar = QProgressBar(self.downloadReportButtonVerticalFrame)
        self.reportProgressBar.setObjectName(u"reportProgressBar")
        sizePolicy3 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        sizePolicy3.setHorizontalStretch(0)
        sizePolicy3.setVerticalStretch(0)
        sizePolicy3.setHeightForWidth(self.reportProgressBar.sizePolicy().hasHeightForWidth())
        self.reportProgressBar.setSizePolicy(sizePolicy3)
        self.reportProgressBar.setMinimumSize(QSize(160, 26))
        self.reportProgressBar.setMaximumSize(QSize(160, 26))
        self.reportProgressBar.setFont(font4)
        self.reportProgressBar.setStyleSheet(u"#reportProgressBar {\n"
"    border: 2px solid #d3d3d3;\n"
"    border-radius: 10px;\n"
"    background-color: #f3f3f3;\n"
"    text-align: center;\n"
"    color: black; \n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}\n"
"\n"
"#reportProgressBar::chunk {\n"
"    background-color: #3a8e32;\n"
"    border-radius: 10px;\n"
"}\n"
"")
        self.reportProgressBar.setValue(0)

        self.verticalLayout_12.addWidget(self.reportProgressBar)


        self.verticalLayout_11.addWidget(self.downloadReportButtonVerticalFrame)

        self.verticalSpacer_16 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_11.addItem(self.verticalSpacer_16)


        self.verticalLayout_10.addWidget(self.reportSelectionVerticalFrameInside)


        self.horizontalLayout_15.addWidget(self.reportSelectionVerticalFrameOutside)

        self.reportPreviewVerticalFrame = QFrame(self.reportPreviewHorizontalFrame)
        self.reportPreviewVerticalFrame.setObjectName(u"reportPreviewVerticalFrame")
        self.verticalLayout_13 = QVBoxLayout(self.reportPreviewVerticalFrame)
        self.verticalLayout_13.setSpacing(15)
        self.verticalLayout_13.setObjectName(u"verticalLayout_13")
        self.verticalLayout_13.setContentsMargins(0, 0, 0, 0)
        self.reportPreviewLabel = QLabel(self.reportPreviewVerticalFrame)
        self.reportPreviewLabel.setObjectName(u"reportPreviewLabel")
        self.reportPreviewLabel.setMinimumSize(QSize(100, 40))
        self.reportPreviewLabel.setMaximumSize(QSize(16777215, 16777215))
        self.reportPreviewLabel.setFont(font4)
        self.reportPreviewLabel.setStyleSheet(u"#reportPreviewLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.reportPreviewLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.reportPreviewLabel.setWordWrap(False)

        self.verticalLayout_13.addWidget(self.reportPreviewLabel)

        self.previewTableVerticalFrame = QFrame(self.reportPreviewVerticalFrame)
        self.previewTableVerticalFrame.setObjectName(u"previewTableVerticalFrame")
        self.previewTableVerticalFrame.setStyleSheet(u"#previewTableVerticalFrame {\n"
"   background-color: rgba(204, 204, 204, 0.6);;\n"
"   color: black;\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-color: black;	\n"
"}")
        self.verticalLayout_14 = QVBoxLayout(self.previewTableVerticalFrame)
        self.verticalLayout_14.setSpacing(10)
        self.verticalLayout_14.setObjectName(u"verticalLayout_14")
        self.verticalLayout_14.setContentsMargins(1, 7, 1, 7)
        self.reportPreviewTableView = QTableView(self.previewTableVerticalFrame)
        self.reportPreviewTableView.setObjectName(u"reportPreviewTableView")
        self.reportPreviewTableView.setMinimumSize(QSize(551, 556))
        self.reportPreviewTableView.setFont(font3)
        self.reportPreviewTableView.setStyleSheet(u"#reportPreviewTableView {\n"
"    border-radius: 8px;\n"
"    background-color: transparent;\n"
"    color: black;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"    gridline-color: black;\n"
"}\n"
"\n"
"#reportPreviewTableView QHeaderView::section {\n"
"    background-color: rgba(204, 204, 204, 0.6);\n"
"    color: black;\n"
"    font-size: 14px;\n"
"    font-weight: bold;\n"
"    border-right: 1px solid black;\n"
"    border-top: none;\n"
"    border-left: none;\n"
"    border-bottom: 2px solid black;\n"
"}\n"
"\n"
"#reportPreviewTableView QHeaderView::section:vertical {\n"
"    background-color: rgba(204, 204, 204, 0.6);\n"
"    color: black;\n"
"    font-size: 14px;\n"
"    font-weight: bold;\n"
"    gridline-color: black;\n"
"}\n"
"\n"
"#reportPreviewTableView::item {\n"
"    border: none;\n"
"}\n"
"\n"
"#reportPreviewTableView::item:selected {\n"
"    background: transparent;\n"
"    color: black;\n"
"    border: none;\n"
"}\n"
"\n"
"#reportPreviewTableView::focus {\n"
"    outline: none;\n"
"}"
                        "\n"
"\n"
"#reportPreviewTableView::corner {\n"
"    background-color: #f3f3f3;\n"
"    border-top-left-radius: 8px;\n"
"}\n"
"\n"
"#reportPreviewTableView QScrollBar:vertical, #reportPreviewTableView QScrollBar:horizontal {\n"
"    background-color: rgb(250, 250, 250);\n"
"    border: 1px solid rgb(153, 153, 153);\n"
"    width: 10px;\n"
"    height: 10px; \n"
"    margin: 0px 0px 0px 0px;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#reportPreviewTableView QScrollBar::handle:vertical,  #reportPreviewTableView QScrollBar::handle:horizontal {\n"
"    background-color: black;\n"
"    min-height: 100px;\n"
"    border: 0px solid black;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#reportPreviewTableView QScrollBar::add-line:vertical, #reportPreviewTableView QScrollBar::add-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: bottom;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"#reportPreviewTableView QScrollBar::sub-line:vertical, #reportPreviewTableView QScrollBar::sub-line:horizontal {\n"
"    h"
                        "eight: 0px;\n"
"    subcontrol-position: top;\n"
"    subcontrol-origin: margin;\n"
"}")
        self.reportPreviewTableView.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.reportPreviewTableView.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.reportPreviewTableView.setTextElideMode(Qt.TextElideMode.ElideLeft)
        self.reportPreviewTableView.horizontalHeader().setMinimumSectionSize(110)
        self.reportPreviewTableView.horizontalHeader().setHighlightSections(False)
        self.reportPreviewTableView.horizontalHeader().setProperty(u"showSortIndicator", True)
        self.reportPreviewTableView.horizontalHeader().setStretchLastSection(True)
        self.reportPreviewTableView.verticalHeader().setVisible(False)
        self.reportPreviewTableView.verticalHeader().setCascadingSectionResizes(True)
        self.reportPreviewTableView.verticalHeader().setMinimumSectionSize(30)
        self.reportPreviewTableView.verticalHeader().setDefaultSectionSize(32)
        self.reportPreviewTableView.verticalHeader().setStretchLastSection(True)

        self.verticalLayout_14.addWidget(self.reportPreviewTableView)


        self.verticalLayout_13.addWidget(self.previewTableVerticalFrame)


        self.horizontalLayout_15.addWidget(self.reportPreviewVerticalFrame)


        self.gridLayout_4.addWidget(self.reportPreviewHorizontalFrame, 0, 0, 1, 1)

        self.stackedWidget.addWidget(self.reportPage)
        self.infoPage = QWidget()
        self.infoPage.setObjectName(u"infoPage")
        self.gridLayout_5 = QGridLayout(self.infoPage)
        self.gridLayout_5.setSpacing(0)
        self.gridLayout_5.setObjectName(u"gridLayout_5")
        self.gridLayout_5.setContentsMargins(0, 0, 0, 0)
        self.infoHorizontalFrame = QFrame(self.infoPage)
        self.infoHorizontalFrame.setObjectName(u"infoHorizontalFrame")
        self.infoHorizontalFrame.setMinimumSize(QSize(0, 660))
        self.infoHorizontalFrame.setFont(font6)
        self.horizontalLayout_16 = QHBoxLayout(self.infoHorizontalFrame)
        self.horizontalLayout_16.setSpacing(10)
        self.horizontalLayout_16.setObjectName(u"horizontalLayout_16")
        self.horizontalLayout_16.setContentsMargins(20, 20, 20, 20)
        self.machineInfoVerticalFrameOutside = QFrame(self.infoHorizontalFrame)
        self.machineInfoVerticalFrameOutside.setObjectName(u"machineInfoVerticalFrameOutside")
        self.verticalLayout_15 = QVBoxLayout(self.machineInfoVerticalFrameOutside)
        self.verticalLayout_15.setSpacing(0)
        self.verticalLayout_15.setObjectName(u"verticalLayout_15")
        self.verticalLayout_15.setContentsMargins(0, 0, 0, 0)
        self.machineInformationLabel = QLabel(self.machineInfoVerticalFrameOutside)
        self.machineInformationLabel.setObjectName(u"machineInformationLabel")
        self.machineInformationLabel.setMinimumSize(QSize(0, 40))
        self.machineInformationLabel.setMaximumSize(QSize(16777215, 16777215))
        self.machineInformationLabel.setFont(font4)
        self.machineInformationLabel.setStyleSheet(u"#machineInformationLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.machineInformationLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.machineInformationLabel.setWordWrap(False)

        self.verticalLayout_15.addWidget(self.machineInformationLabel)

        self.machineInfoVerticalFrameInside = QFrame(self.machineInfoVerticalFrameOutside)
        self.machineInfoVerticalFrameInside.setObjectName(u"machineInfoVerticalFrameInside")
        self.verticalLayout_16 = QVBoxLayout(self.machineInfoVerticalFrameInside)
        self.verticalLayout_16.setSpacing(6)
        self.verticalLayout_16.setObjectName(u"verticalLayout_16")
        self.verticalLayout_16.setContentsMargins(30, 0, 30, 0)
        self.OSTypeFrame = QFrame(self.machineInfoVerticalFrameInside)
        self.OSTypeFrame.setObjectName(u"OSTypeFrame")
        self.OSTypeFrame.setMinimumSize(QSize(0, 50))
        self.OSTypeFrame.setMaximumSize(QSize(16777215, 50))
        self.OSTypeFrame.setStyleSheet(u"#OSTypeFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_17 = QHBoxLayout(self.OSTypeFrame)
        self.horizontalLayout_17.setObjectName(u"horizontalLayout_17")
        self.horizontalLayout_17.setContentsMargins(0, 0, 0, 0)
        self.OSTypeLabel = QLabel(self.OSTypeFrame)
        self.OSTypeLabel.setObjectName(u"OSTypeLabel")
        self.OSTypeLabel.setMinimumSize(QSize(80, 40))
        self.OSTypeLabel.setMaximumSize(QSize(16777215, 40))
        self.OSTypeLabel.setFont(font3)
        self.OSTypeLabel.setStyleSheet(u"#OSTypeLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"}")
        self.OSTypeLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.OSTypeLabel.setWordWrap(False)
        self.OSTypeLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_17.addWidget(self.OSTypeLabel)

        self.OSTypeInfoLabel = QLabel(self.OSTypeFrame)
        self.OSTypeInfoLabel.setObjectName(u"OSTypeInfoLabel")
        sizePolicy4 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        sizePolicy4.setHorizontalStretch(0)
        sizePolicy4.setVerticalStretch(0)
        sizePolicy4.setHeightForWidth(self.OSTypeInfoLabel.sizePolicy().hasHeightForWidth())
        self.OSTypeInfoLabel.setSizePolicy(sizePolicy4)
        self.OSTypeInfoLabel.setMinimumSize(QSize(150, 40))
        self.OSTypeInfoLabel.setMaximumSize(QSize(400, 40))
        self.OSTypeInfoLabel.setFont(font3)
        self.OSTypeInfoLabel.setStyleSheet(u"#OSTypeInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.OSTypeInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.OSTypeInfoLabel.setWordWrap(False)
        self.OSTypeInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_17.addWidget(self.OSTypeInfoLabel)

        self.horizontalSpacer_14 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_17.addItem(self.horizontalSpacer_14)


        self.verticalLayout_16.addWidget(self.OSTypeFrame)

        self.OSVersionFrame = QFrame(self.machineInfoVerticalFrameInside)
        self.OSVersionFrame.setObjectName(u"OSVersionFrame")
        self.OSVersionFrame.setMinimumSize(QSize(0, 50))
        self.OSVersionFrame.setMaximumSize(QSize(16777215, 50))
        self.OSVersionFrame.setStyleSheet(u"#OSVersionFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_18 = QHBoxLayout(self.OSVersionFrame)
        self.horizontalLayout_18.setObjectName(u"horizontalLayout_18")
        self.horizontalLayout_18.setContentsMargins(0, 0, 0, 0)
        self.OSVersionLabel = QLabel(self.OSVersionFrame)
        self.OSVersionLabel.setObjectName(u"OSVersionLabel")
        self.OSVersionLabel.setMinimumSize(QSize(100, 40))
        self.OSVersionLabel.setMaximumSize(QSize(16777215, 40))
        self.OSVersionLabel.setFont(font3)
        self.OSVersionLabel.setStyleSheet(u"#OSVersionLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.OSVersionLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.OSVersionLabel.setWordWrap(False)
        self.OSVersionLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_18.addWidget(self.OSVersionLabel)

        self.OSVersionInfoLabel = QLabel(self.OSVersionFrame)
        self.OSVersionInfoLabel.setObjectName(u"OSVersionInfoLabel")
        sizePolicy4.setHeightForWidth(self.OSVersionInfoLabel.sizePolicy().hasHeightForWidth())
        self.OSVersionInfoLabel.setSizePolicy(sizePolicy4)
        self.OSVersionInfoLabel.setMinimumSize(QSize(150, 40))
        self.OSVersionInfoLabel.setMaximumSize(QSize(400, 40))
        self.OSVersionInfoLabel.setFont(font3)
        self.OSVersionInfoLabel.setStyleSheet(u"#OSVersionInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.OSVersionInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.OSVersionInfoLabel.setWordWrap(False)
        self.OSVersionInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_18.addWidget(self.OSVersionInfoLabel)

        self.horizontalSpacer_15 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_18.addItem(self.horizontalSpacer_15)


        self.verticalLayout_16.addWidget(self.OSVersionFrame)

        self.architectureFrame = QFrame(self.machineInfoVerticalFrameInside)
        self.architectureFrame.setObjectName(u"architectureFrame")
        self.architectureFrame.setMinimumSize(QSize(0, 50))
        self.architectureFrame.setMaximumSize(QSize(16777215, 50))
        self.architectureFrame.setStyleSheet(u"#architectureFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_19 = QHBoxLayout(self.architectureFrame)
        self.horizontalLayout_19.setObjectName(u"horizontalLayout_19")
        self.horizontalLayout_19.setContentsMargins(0, 0, 0, 0)
        self.architectureLabel = QLabel(self.architectureFrame)
        self.architectureLabel.setObjectName(u"architectureLabel")
        self.architectureLabel.setMinimumSize(QSize(110, 40))
        self.architectureLabel.setMaximumSize(QSize(16777215, 40))
        self.architectureLabel.setFont(font3)
        self.architectureLabel.setStyleSheet(u"#architectureLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.architectureLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.architectureLabel.setWordWrap(False)
        self.architectureLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_19.addWidget(self.architectureLabel)

        self.architectureInfoLabel = QLabel(self.architectureFrame)
        self.architectureInfoLabel.setObjectName(u"architectureInfoLabel")
        sizePolicy4.setHeightForWidth(self.architectureInfoLabel.sizePolicy().hasHeightForWidth())
        self.architectureInfoLabel.setSizePolicy(sizePolicy4)
        self.architectureInfoLabel.setMinimumSize(QSize(150, 40))
        self.architectureInfoLabel.setMaximumSize(QSize(400, 40))
        self.architectureInfoLabel.setFont(font3)
        self.architectureInfoLabel.setStyleSheet(u"#architectureInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.architectureInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.architectureInfoLabel.setWordWrap(False)
        self.architectureInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_19.addWidget(self.architectureInfoLabel)

        self.horizontalSpacer_16 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_19.addItem(self.horizontalSpacer_16)


        self.verticalLayout_16.addWidget(self.architectureFrame)

        self.hostNameFrame = QFrame(self.machineInfoVerticalFrameInside)
        self.hostNameFrame.setObjectName(u"hostNameFrame")
        self.hostNameFrame.setMinimumSize(QSize(250, 50))
        self.hostNameFrame.setMaximumSize(QSize(16777215, 50))
        self.hostNameFrame.setStyleSheet(u"#hostNameFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_20 = QHBoxLayout(self.hostNameFrame)
        self.horizontalLayout_20.setObjectName(u"horizontalLayout_20")
        self.horizontalLayout_20.setContentsMargins(0, 0, 0, 0)
        self.hostNameLabel = QLabel(self.hostNameFrame)
        self.hostNameLabel.setObjectName(u"hostNameLabel")
        self.hostNameLabel.setMinimumSize(QSize(105, 40))
        self.hostNameLabel.setMaximumSize(QSize(16777215, 40))
        self.hostNameLabel.setFont(font3)
        self.hostNameLabel.setStyleSheet(u"#hostNameLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.hostNameLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.hostNameLabel.setWordWrap(False)
        self.hostNameLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_20.addWidget(self.hostNameLabel)

        self.hostNameInfoLabel = QLabel(self.hostNameFrame)
        self.hostNameInfoLabel.setObjectName(u"hostNameInfoLabel")
        sizePolicy4.setHeightForWidth(self.hostNameInfoLabel.sizePolicy().hasHeightForWidth())
        self.hostNameInfoLabel.setSizePolicy(sizePolicy4)
        self.hostNameInfoLabel.setMinimumSize(QSize(150, 40))
        self.hostNameInfoLabel.setMaximumSize(QSize(400, 40))
        self.hostNameInfoLabel.setFont(font3)
        self.hostNameInfoLabel.setStyleSheet(u"#hostNameInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.hostNameInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.hostNameInfoLabel.setWordWrap(False)
        self.hostNameInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_20.addWidget(self.hostNameInfoLabel)

        self.horizontalSpacer_17 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_20.addItem(self.horizontalSpacer_17)


        self.verticalLayout_16.addWidget(self.hostNameFrame)

        self.verticalSpacer_17 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_16.addItem(self.verticalSpacer_17)


        self.verticalLayout_15.addWidget(self.machineInfoVerticalFrameInside)

        self.programInformationLabel = QLabel(self.machineInfoVerticalFrameOutside)
        self.programInformationLabel.setObjectName(u"programInformationLabel")
        self.programInformationLabel.setMinimumSize(QSize(0, 40))
        self.programInformationLabel.setMaximumSize(QSize(16777215, 16777215))
        self.programInformationLabel.setFont(font4)
        self.programInformationLabel.setStyleSheet(u"#programInformationLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.programInformationLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.programInformationLabel.setWordWrap(False)

        self.verticalLayout_15.addWidget(self.programInformationLabel)

        self.programInformationVerticalFrame = QFrame(self.machineInfoVerticalFrameOutside)
        self.programInformationVerticalFrame.setObjectName(u"programInformationVerticalFrame")
        self.verticalLayout_17 = QVBoxLayout(self.programInformationVerticalFrame)
        self.verticalLayout_17.setObjectName(u"verticalLayout_17")
        self.verticalLayout_17.setContentsMargins(30, 0, 30, 0)
        self.netspectVersionFrame = QFrame(self.programInformationVerticalFrame)
        self.netspectVersionFrame.setObjectName(u"netspectVersionFrame")
        self.netspectVersionFrame.setMinimumSize(QSize(0, 50))
        self.netspectVersionFrame.setMaximumSize(QSize(16777215, 50))
        self.netspectVersionFrame.setStyleSheet(u"#netspectVersionFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_21 = QHBoxLayout(self.netspectVersionFrame)
        self.horizontalLayout_21.setObjectName(u"horizontalLayout_21")
        self.horizontalLayout_21.setContentsMargins(0, 0, 0, 0)
        self.netspectVersionLabel = QLabel(self.netspectVersionFrame)
        self.netspectVersionLabel.setObjectName(u"netspectVersionLabel")
        self.netspectVersionLabel.setMinimumSize(QSize(150, 40))
        self.netspectVersionLabel.setMaximumSize(QSize(16777215, 40))
        self.netspectVersionLabel.setFont(font3)
        self.netspectVersionLabel.setStyleSheet(u"#netspectVersionLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.netspectVersionLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.netspectVersionLabel.setWordWrap(False)
        self.netspectVersionLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_21.addWidget(self.netspectVersionLabel)

        self.netspectVersionInfoLabel = QLabel(self.netspectVersionFrame)
        self.netspectVersionInfoLabel.setObjectName(u"netspectVersionInfoLabel")
        sizePolicy4.setHeightForWidth(self.netspectVersionInfoLabel.sizePolicy().hasHeightForWidth())
        self.netspectVersionInfoLabel.setSizePolicy(sizePolicy4)
        self.netspectVersionInfoLabel.setMinimumSize(QSize(150, 40))
        self.netspectVersionInfoLabel.setMaximumSize(QSize(400, 40))
        self.netspectVersionInfoLabel.setFont(font3)
        self.netspectVersionInfoLabel.setStyleSheet(u"#netspectVersionInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.netspectVersionInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.netspectVersionInfoLabel.setWordWrap(False)
        self.netspectVersionInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_21.addWidget(self.netspectVersionInfoLabel)

        self.horizontalSpacer_18 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_21.addItem(self.horizontalSpacer_18)


        self.verticalLayout_17.addWidget(self.netspectVersionFrame)

        self.githubFrame = QFrame(self.programInformationVerticalFrame)
        self.githubFrame.setObjectName(u"githubFrame")
        self.githubFrame.setMinimumSize(QSize(0, 50))
        self.githubFrame.setMaximumSize(QSize(16777215, 50))
        self.githubFrame.setStyleSheet(u"#githubFrame {\n"
"	background-color: transparent;\n"
"}")
        self.horizontalLayout_22 = QHBoxLayout(self.githubFrame)
        self.horizontalLayout_22.setObjectName(u"horizontalLayout_22")
        self.horizontalLayout_22.setContentsMargins(0, 0, 0, 0)
        self.githubLabel = QLabel(self.githubFrame)
        self.githubLabel.setObjectName(u"githubLabel")
        self.githubLabel.setMinimumSize(QSize(65, 40))
        self.githubLabel.setMaximumSize(QSize(16777215, 40))
        self.githubLabel.setFont(font3)
        self.githubLabel.setStyleSheet(u"#githubLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.githubLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.githubLabel.setWordWrap(False)

        self.horizontalLayout_22.addWidget(self.githubLabel)

        self.githubInfoLabel = QLabel(self.githubFrame)
        self.githubInfoLabel.setObjectName(u"githubInfoLabel")
        sizePolicy4.setHeightForWidth(self.githubInfoLabel.sizePolicy().hasHeightForWidth())
        self.githubInfoLabel.setSizePolicy(sizePolicy4)
        self.githubInfoLabel.setMinimumSize(QSize(150, 40))
        self.githubInfoLabel.setMaximumSize(QSize(400, 40))
        self.githubInfoLabel.setFont(font3)
        self.githubInfoLabel.setStyleSheet(u"#githubInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}\n"
"")
        self.githubInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.githubInfoLabel.setWordWrap(False)
        self.githubInfoLabel.setOpenExternalLinks(True)

        self.horizontalLayout_22.addWidget(self.githubInfoLabel)

        self.horizontalSpacer_19 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_22.addItem(self.horizontalSpacer_19)


        self.verticalLayout_17.addWidget(self.githubFrame)

        self.verticalSpacer_18 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_17.addItem(self.verticalSpacer_18)


        self.verticalLayout_15.addWidget(self.programInformationVerticalFrame)

        self.verticalSpacer_19 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_15.addItem(self.verticalSpacer_19)


        self.horizontalLayout_16.addWidget(self.machineInfoVerticalFrameOutside)

        self.ProgramInfoVerticalFrameOutside = QFrame(self.infoHorizontalFrame)
        self.ProgramInfoVerticalFrameOutside.setObjectName(u"ProgramInfoVerticalFrameOutside")
        self.verticalLayout_18 = QVBoxLayout(self.ProgramInfoVerticalFrameOutside)
        self.verticalLayout_18.setSpacing(0)
        self.verticalLayout_18.setObjectName(u"verticalLayout_18")
        self.verticalLayout_18.setContentsMargins(0, 0, 10, 0)
        self.ProgramInfoVerticalFrameInside = QFrame(self.ProgramInfoVerticalFrameOutside)
        self.ProgramInfoVerticalFrameInside.setObjectName(u"ProgramInfoVerticalFrameInside")
        self.verticalLayout_19 = QVBoxLayout(self.ProgramInfoVerticalFrameInside)
        self.verticalLayout_19.setSpacing(0)
        self.verticalLayout_19.setObjectName(u"verticalLayout_19")
        self.verticalLayout_19.setContentsMargins(0, 0, 0, 0)
        self.networkInterfaceInformationLabel = QLabel(self.ProgramInfoVerticalFrameInside)
        self.networkInterfaceInformationLabel.setObjectName(u"networkInterfaceInformationLabel")
        self.networkInterfaceInformationLabel.setMinimumSize(QSize(0, 40))
        self.networkInterfaceInformationLabel.setMaximumSize(QSize(16777215, 16777215))
        self.networkInterfaceInformationLabel.setFont(font4)
        self.networkInterfaceInformationLabel.setStyleSheet(u"#networkInterfaceInformationLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.networkInterfaceInformationLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.networkInterfaceInformationLabel.setWordWrap(False)

        self.verticalLayout_19.addWidget(self.networkInterfaceInformationLabel)

        self.netowrkInterfaceInformationFrame = QFrame(self.ProgramInfoVerticalFrameInside)
        self.netowrkInterfaceInformationFrame.setObjectName(u"netowrkInterfaceInformationFrame")
        self.verticalLayout_20 = QVBoxLayout(self.netowrkInterfaceInformationFrame)
        self.verticalLayout_20.setSpacing(6)
        self.verticalLayout_20.setObjectName(u"verticalLayout_20")
        self.verticalLayout_20.setContentsMargins(30, 0, 30, 0)
        self.connectedInterfaceFrame = QFrame(self.netowrkInterfaceInformationFrame)
        self.connectedInterfaceFrame.setObjectName(u"connectedInterfaceFrame")
        self.connectedInterfaceFrame.setMinimumSize(QSize(360, 50))
        self.connectedInterfaceFrame.setMaximumSize(QSize(16777215, 50))
        self.connectedInterfaceFrame.setStyleSheet(u"#connectedInterfaceFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_23 = QHBoxLayout(self.connectedInterfaceFrame)
        self.horizontalLayout_23.setObjectName(u"horizontalLayout_23")
        self.horizontalLayout_23.setContentsMargins(0, 0, 0, 0)
        self.connectedInterfaceLabel = QLabel(self.connectedInterfaceFrame)
        self.connectedInterfaceLabel.setObjectName(u"connectedInterfaceLabel")
        self.connectedInterfaceLabel.setMinimumSize(QSize(175, 40))
        self.connectedInterfaceLabel.setMaximumSize(QSize(16777215, 40))
        self.connectedInterfaceLabel.setFont(font3)
        self.connectedInterfaceLabel.setStyleSheet(u"#connectedInterfaceLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.connectedInterfaceLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.connectedInterfaceLabel.setWordWrap(False)
        self.connectedInterfaceLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_23.addWidget(self.connectedInterfaceLabel)

        self.connectedInterfaceInfoLabel = QLabel(self.connectedInterfaceFrame)
        self.connectedInterfaceInfoLabel.setObjectName(u"connectedInterfaceInfoLabel")
        sizePolicy4.setHeightForWidth(self.connectedInterfaceInfoLabel.sizePolicy().hasHeightForWidth())
        self.connectedInterfaceInfoLabel.setSizePolicy(sizePolicy4)
        self.connectedInterfaceInfoLabel.setMinimumSize(QSize(150, 40))
        self.connectedInterfaceInfoLabel.setMaximumSize(QSize(400, 40))
        self.connectedInterfaceInfoLabel.setFont(font3)
        self.connectedInterfaceInfoLabel.setStyleSheet(u"#connectedInterfaceInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.connectedInterfaceInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.connectedInterfaceInfoLabel.setWordWrap(False)
        self.connectedInterfaceInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_23.addWidget(self.connectedInterfaceInfoLabel)

        self.horizontalSpacer_20 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_23.addItem(self.horizontalSpacer_20)


        self.verticalLayout_20.addWidget(self.connectedInterfaceFrame)

        self.macAddressFrame = QFrame(self.netowrkInterfaceInformationFrame)
        self.macAddressFrame.setObjectName(u"macAddressFrame")
        self.macAddressFrame.setMinimumSize(QSize(360, 50))
        self.macAddressFrame.setMaximumSize(QSize(16777215, 50))
        self.macAddressFrame.setStyleSheet(u"#macAddressFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_24 = QHBoxLayout(self.macAddressFrame)
        self.horizontalLayout_24.setObjectName(u"horizontalLayout_24")
        self.horizontalLayout_24.setContentsMargins(0, 0, 0, 0)
        self.macAddressLabel = QLabel(self.macAddressFrame)
        self.macAddressLabel.setObjectName(u"macAddressLabel")
        self.macAddressLabel.setMinimumSize(QSize(120, 40))
        self.macAddressLabel.setMaximumSize(QSize(16777215, 40))
        self.macAddressLabel.setFont(font3)
        self.macAddressLabel.setStyleSheet(u"#macAddressLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.macAddressLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.macAddressLabel.setWordWrap(False)
        self.macAddressLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_24.addWidget(self.macAddressLabel)

        self.macAddressInfoLabel = QLabel(self.macAddressFrame)
        self.macAddressInfoLabel.setObjectName(u"macAddressInfoLabel")
        sizePolicy4.setHeightForWidth(self.macAddressInfoLabel.sizePolicy().hasHeightForWidth())
        self.macAddressInfoLabel.setSizePolicy(sizePolicy4)
        self.macAddressInfoLabel.setMinimumSize(QSize(180, 40))
        self.macAddressInfoLabel.setMaximumSize(QSize(400, 40))
        self.macAddressInfoLabel.setFont(font3)
        self.macAddressInfoLabel.setStyleSheet(u"#macAddressInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.macAddressInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.macAddressInfoLabel.setWordWrap(False)
        self.macAddressInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_24.addWidget(self.macAddressInfoLabel)

        self.horizontalSpacer_21 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_24.addItem(self.horizontalSpacer_21)


        self.verticalLayout_20.addWidget(self.macAddressFrame)

        self.descriptionFrame = QFrame(self.netowrkInterfaceInformationFrame)
        self.descriptionFrame.setObjectName(u"descriptionFrame")
        self.descriptionFrame.setMinimumSize(QSize(360, 50))
        self.descriptionFrame.setMaximumSize(QSize(16777215, 50))
        self.descriptionFrame.setStyleSheet(u"#descriptionFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_25 = QHBoxLayout(self.descriptionFrame)
        self.horizontalLayout_25.setObjectName(u"horizontalLayout_25")
        self.horizontalLayout_25.setContentsMargins(0, 0, 0, 0)
        self.descriptionLabel = QLabel(self.descriptionFrame)
        self.descriptionLabel.setObjectName(u"descriptionLabel")
        self.descriptionLabel.setMinimumSize(QSize(105, 40))
        self.descriptionLabel.setMaximumSize(QSize(16777215, 40))
        self.descriptionLabel.setFont(font3)
        self.descriptionLabel.setStyleSheet(u"#descriptionLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.descriptionLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.descriptionLabel.setWordWrap(False)
        self.descriptionLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_25.addWidget(self.descriptionLabel)

        self.descriptionInfoLabel = QLabel(self.descriptionFrame)
        self.descriptionInfoLabel.setObjectName(u"descriptionInfoLabel")
        sizePolicy4.setHeightForWidth(self.descriptionInfoLabel.sizePolicy().hasHeightForWidth())
        self.descriptionInfoLabel.setSizePolicy(sizePolicy4)
        self.descriptionInfoLabel.setMinimumSize(QSize(150, 40))
        self.descriptionInfoLabel.setMaximumSize(QSize(500, 40))
        self.descriptionInfoLabel.setFont(font3)
        self.descriptionInfoLabel.setStyleSheet(u"#descriptionInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.descriptionInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.descriptionInfoLabel.setWordWrap(False)
        self.descriptionInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_25.addWidget(self.descriptionInfoLabel)

        self.horizontalSpacer_22 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_25.addItem(self.horizontalSpacer_22)


        self.verticalLayout_20.addWidget(self.descriptionFrame)

        self.maxTransmitionUnitFrame = QFrame(self.netowrkInterfaceInformationFrame)
        self.maxTransmitionUnitFrame.setObjectName(u"maxTransmitionUnitFrame")
        self.maxTransmitionUnitFrame.setMinimumSize(QSize(360, 50))
        self.maxTransmitionUnitFrame.setMaximumSize(QSize(16777215, 50))
        self.maxTransmitionUnitFrame.setStyleSheet(u"#maxTransmitionUnitFrame {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_26 = QHBoxLayout(self.maxTransmitionUnitFrame)
        self.horizontalLayout_26.setObjectName(u"horizontalLayout_26")
        self.horizontalLayout_26.setContentsMargins(0, 0, 0, 0)
        self.maxTransmitionUnitLabel = QLabel(self.maxTransmitionUnitFrame)
        self.maxTransmitionUnitLabel.setObjectName(u"maxTransmitionUnitLabel")
        self.maxTransmitionUnitLabel.setMinimumSize(QSize(185, 40))
        self.maxTransmitionUnitLabel.setMaximumSize(QSize(16777215, 40))
        self.maxTransmitionUnitLabel.setFont(font3)
        self.maxTransmitionUnitLabel.setStyleSheet(u"#maxTransmitionUnitLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.maxTransmitionUnitLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.maxTransmitionUnitLabel.setWordWrap(False)
        self.maxTransmitionUnitLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_26.addWidget(self.maxTransmitionUnitLabel)

        self.maxTransmitionUnitInfoLabel = QLabel(self.maxTransmitionUnitFrame)
        self.maxTransmitionUnitInfoLabel.setObjectName(u"maxTransmitionUnitInfoLabel")
        sizePolicy4.setHeightForWidth(self.maxTransmitionUnitInfoLabel.sizePolicy().hasHeightForWidth())
        self.maxTransmitionUnitInfoLabel.setSizePolicy(sizePolicy4)
        self.maxTransmitionUnitInfoLabel.setMinimumSize(QSize(150, 40))
        self.maxTransmitionUnitInfoLabel.setMaximumSize(QSize(400, 40))
        self.maxTransmitionUnitInfoLabel.setFont(font3)
        self.maxTransmitionUnitInfoLabel.setStyleSheet(u"#maxTransmitionUnitInfoLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo\n"
"}")
        self.maxTransmitionUnitInfoLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.maxTransmitionUnitInfoLabel.setWordWrap(False)
        self.maxTransmitionUnitInfoLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.horizontalLayout_26.addWidget(self.maxTransmitionUnitInfoLabel)

        self.horizontalSpacer_23 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_26.addItem(self.horizontalSpacer_23)


        self.verticalLayout_20.addWidget(self.maxTransmitionUnitFrame)

        self.verticalSpacer_20 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_20.addItem(self.verticalSpacer_20)


        self.verticalLayout_19.addWidget(self.netowrkInterfaceInformationFrame)

        self.myIpAddressesLabel = QLabel(self.ProgramInfoVerticalFrameInside)
        self.myIpAddressesLabel.setObjectName(u"myIpAddressesLabel")
        self.myIpAddressesLabel.setMinimumSize(QSize(0, 20))
        self.myIpAddressesLabel.setMaximumSize(QSize(16777215, 16777215))
        self.myIpAddressesLabel.setFont(font4)
        self.myIpAddressesLabel.setStyleSheet(u"#myIpAddressesLabel {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")
        self.myIpAddressesLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.myIpAddressesLabel.setWordWrap(False)

        self.verticalLayout_19.addWidget(self.myIpAddressesLabel)

        self.myIpAddressesFrameOutside = QFrame(self.ProgramInfoVerticalFrameInside)
        self.myIpAddressesFrameOutside.setObjectName(u"myIpAddressesFrameOutside")
        self.verticalLayout_21 = QVBoxLayout(self.myIpAddressesFrameOutside)
        self.verticalLayout_21.setSpacing(0)
        self.verticalLayout_21.setObjectName(u"verticalLayout_21")
        self.verticalLayout_21.setContentsMargins(0, 0, 0, 0)
        self.myIpAddressesFrameInside = QFrame(self.myIpAddressesFrameOutside)
        self.myIpAddressesFrameInside.setObjectName(u"myIpAddressesFrameInside")
        self.myIpAddressesFrameInside.setMinimumSize(QSize(360, 50))
        self.myIpAddressesFrameInside.setMaximumSize(QSize(16777215, 16777215))
        self.myIpAddressesFrameInside.setStyleSheet(u"#myIpAddressesFrameInside {\n"
"	background-color: transparent;\n"
"	color: #f3f3f3;\n"
"}")
        self.horizontalLayout_27 = QHBoxLayout(self.myIpAddressesFrameInside)
        self.horizontalLayout_27.setSpacing(0)
        self.horizontalLayout_27.setObjectName(u"horizontalLayout_27")
        self.horizontalLayout_27.setContentsMargins(10, 3, 0, 0)
        self.ipAddressesListWidget = QListWidget(self.myIpAddressesFrameInside)
        self.ipAddressesListWidget.setObjectName(u"ipAddressesListWidget")
        self.ipAddressesListWidget.setMinimumSize(QSize(400, 180))
        self.ipAddressesListWidget.setMaximumSize(QSize(400, 180))
        self.ipAddressesListWidget.setFont(font3)
        self.ipAddressesListWidget.setStyleSheet(u"#ipAddressesListWidget {\n"
"    background-color: rgba(198, 198, 198, 0.6);\n"
"    border-radius: 15px;\n"
"    border: 2px solid black;\n"
"    padding: 4px;\n"
"    color: black;\n"
"    font-size: 17px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#ipAddressesListWidget::item {\n"
"    color: black;\n"
"}\n"
"\n"
"#ipAddressesListWidget::item:selected {\n"
"    background: transparent;\n"
"    color: black;\n"
"    border: none;\n"
"}\n"
"\n"
"#ipAddressesListWidget::item:hover {\n"
"    background: transparent;\n"
"    outline: none;\n"
"    border: none;\n"
"}\n"
"\n"
"#ipAddressesListWidget::focus {\n"
"    outline: none;\n"
"}\n"
"\n"
"#ipAddressesListWidget::corner {\n"
"    background-color: rgba(198, 198, 198, 0.6);\n"
"    border-top-left-radius: 8px;\n"
"}\n"
"\n"
"#ipAddressesListWidget QScrollBar:vertical, #ipAddressesListWidget QScrollBar:horizontal {\n"
"    background-color: rgb(250, 250, 250);\n"
"    border: 1px solid rgb(153, 153, 153);\n"
"    width: 10px;\n"
"    height: 10px; \n"
"    ma"
                        "rgin: 0px 0px 0px 0px;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#ipAddressesListWidget QScrollBar::handle:vertical,  #ipAddressesListWidget QScrollBar::handle:horizontal {\n"
"    background-color: black;\n"
"    min-height: 100px;\n"
"    border: 0px solid black;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#ipAddressesListWidget QScrollBar::add-line:vertical, #ipAddressesListWidget QScrollBar::add-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: bottom;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"#ipAddressesListWidget QScrollBar::sub-line:vertical, #ipAddressesListWidget QScrollBar::sub-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: top;\n"
"    subcontrol-origin: margin;\n"
"}")
        self.ipAddressesListWidget.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.ipAddressesListWidget.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.ipAddressesListWidget.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)

        self.horizontalLayout_27.addWidget(self.ipAddressesListWidget)

        self.horizontalSpacer_24 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_27.addItem(self.horizontalSpacer_24)


        self.verticalLayout_21.addWidget(self.myIpAddressesFrameInside)

        self.verticalSpacer_21 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_21.addItem(self.verticalSpacer_21)


        self.verticalLayout_19.addWidget(self.myIpAddressesFrameOutside)

        self.verticalSpacer_22 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_19.addItem(self.verticalSpacer_22)


        self.verticalLayout_18.addWidget(self.ProgramInfoVerticalFrameInside)


        self.horizontalLayout_16.addWidget(self.ProgramInfoVerticalFrameOutside)

        self.horizontalSpacer_25 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_16.addItem(self.horizontalSpacer_25)


        self.gridLayout_5.addWidget(self.infoHorizontalFrame, 0, 0, 1, 1)

        self.stackedWidget.addWidget(self.infoPage)
        self.settingsPage = QWidget()
        self.settingsPage.setObjectName(u"settingsPage")
        self.gridLayout_6 = QGridLayout(self.settingsPage)
        self.gridLayout_6.setSpacing(0)
        self.gridLayout_6.setObjectName(u"gridLayout_6")
        self.gridLayout_6.setContentsMargins(0, 0, 0, 0)
        self.settingsHorizontalFrame = QFrame(self.settingsPage)
        self.settingsHorizontalFrame.setObjectName(u"settingsHorizontalFrame")
        sizePolicy5 = QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        sizePolicy5.setHorizontalStretch(0)
        sizePolicy5.setVerticalStretch(0)
        sizePolicy5.setHeightForWidth(self.settingsHorizontalFrame.sizePolicy().hasHeightForWidth())
        self.settingsHorizontalFrame.setSizePolicy(sizePolicy5)
        self.horizontalLayout_28 = QHBoxLayout(self.settingsHorizontalFrame)
        self.horizontalLayout_28.setSpacing(0)
        self.horizontalLayout_28.setObjectName(u"horizontalLayout_28")
        self.horizontalLayout_28.setContentsMargins(20, 20, 20, 20)
        self.settingsLeftVerticalFrame = QFrame(self.settingsHorizontalFrame)
        self.settingsLeftVerticalFrame.setObjectName(u"settingsLeftVerticalFrame")
        sizePolicy5.setHeightForWidth(self.settingsLeftVerticalFrame.sizePolicy().hasHeightForWidth())
        self.settingsLeftVerticalFrame.setSizePolicy(sizePolicy5)
        self.settingsLeftVerticalFrame.setMaximumSize(QSize(16777215, 16777215))
        self.verticalLayout_22 = QVBoxLayout(self.settingsLeftVerticalFrame)
        self.verticalLayout_22.setSpacing(20)
        self.verticalLayout_22.setObjectName(u"verticalLayout_22")
        self.verticalLayout_22.setContentsMargins(0, 0, 0, 0)
        self.userSettingsLabel = QLabel(self.settingsLeftVerticalFrame)
        self.userSettingsLabel.setObjectName(u"userSettingsLabel")
        self.userSettingsLabel.setMinimumSize(QSize(185, 40))
        self.userSettingsLabel.setFont(font4)
        self.userSettingsLabel.setCursor(QCursor(Qt.CursorShape.ArrowCursor))
        self.userSettingsLabel.setStyleSheet(u"#userSettingsLabel {\n"
"    color: #f3f3f3;\n"
"    font-size: 24px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")

        self.verticalLayout_22.addWidget(self.userSettingsLabel)

        self.settingsLeftHorizontalFrame = QFrame(self.settingsLeftVerticalFrame)
        self.settingsLeftHorizontalFrame.setObjectName(u"settingsLeftHorizontalFrame")
        sizePolicy5.setHeightForWidth(self.settingsLeftHorizontalFrame.sizePolicy().hasHeightForWidth())
        self.settingsLeftHorizontalFrame.setSizePolicy(sizePolicy5)
        self.horizontalLayout_29 = QHBoxLayout(self.settingsLeftHorizontalFrame)
        self.horizontalLayout_29.setSpacing(20)
        self.horizontalLayout_29.setObjectName(u"horizontalLayout_29")
        self.horizontalLayout_29.setContentsMargins(0, 0, 0, 0)
        self.settingsChangeVerticalFrame = QFrame(self.settingsLeftHorizontalFrame)
        self.settingsChangeVerticalFrame.setObjectName(u"settingsChangeVerticalFrame")
        self.settingsChangeVerticalFrame.setMinimumSize(QSize(474, 0))
        self.settingsChangeVerticalFrame.setStyleSheet(u"")
        self.verticalLayout_23 = QVBoxLayout(self.settingsChangeVerticalFrame)
        self.verticalLayout_23.setSpacing(0)
        self.verticalLayout_23.setObjectName(u"verticalLayout_23")
        self.verticalLayout_23.setContentsMargins(40, 10, 40, 20)
        self.settingsChangeInsideVerticalFrame = QFrame(self.settingsChangeVerticalFrame)
        self.settingsChangeInsideVerticalFrame.setObjectName(u"settingsChangeInsideVerticalFrame")
        self.verticalLayout_24 = QVBoxLayout(self.settingsChangeInsideVerticalFrame)
        self.verticalLayout_24.setSpacing(0)
        self.verticalLayout_24.setObjectName(u"verticalLayout_24")
        self.verticalLayout_24.setContentsMargins(0, 0, 0, 0)
        self.changeEmailLabel = QLabel(self.settingsChangeInsideVerticalFrame)
        self.changeEmailLabel.setObjectName(u"changeEmailLabel")
        self.changeEmailLabel.setMinimumSize(QSize(0, 40))
        self.changeEmailLabel.setFont(font4)
        self.changeEmailLabel.setStyleSheet(u"#changeEmailLabel {\n"
"    color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")

        self.verticalLayout_24.addWidget(self.changeEmailLabel)

        self.emailLineEdit = QLineEdit(self.settingsChangeInsideVerticalFrame)
        self.emailLineEdit.setObjectName(u"emailLineEdit")
        self.emailLineEdit.setMaximumSize(QSize(500, 33))
        self.emailLineEdit.setFont(font5)
        self.emailLineEdit.setStyleSheet(u"#emailLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"}")

        self.verticalLayout_24.addWidget(self.emailLineEdit)

        self.saveEmailErrorMessageLabel = QLabel(self.settingsChangeInsideVerticalFrame)
        self.saveEmailErrorMessageLabel.setObjectName(u"saveEmailErrorMessageLabel")
        sizePolicy5.setHeightForWidth(self.saveEmailErrorMessageLabel.sizePolicy().hasHeightForWidth())
        self.saveEmailErrorMessageLabel.setSizePolicy(sizePolicy5)
        self.saveEmailErrorMessageLabel.setMinimumSize(QSize(252, 20))
        self.saveEmailErrorMessageLabel.setMaximumSize(QSize(500, 50))
        font8 = QFont()
        font8.setFamilies([u"Cairo"])
        font8.setBold(True)
        font8.setStrikeOut(False)
        font8.setKerning(True)
        self.saveEmailErrorMessageLabel.setFont(font8)
        self.saveEmailErrorMessageLabel.setStyleSheet(u"#saveEmailErrorMessageLabel {\n"
"	background-color: #3c3d4a;\n"
"	color: #d84f4f;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"	border: none;\n"
"}")
        self.saveEmailErrorMessageLabel.setLineWidth(1)
        self.saveEmailErrorMessageLabel.setMidLineWidth(0)
        self.saveEmailErrorMessageLabel.setTextFormat(Qt.TextFormat.RichText)
        self.saveEmailErrorMessageLabel.setScaledContents(False)
        self.saveEmailErrorMessageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.saveEmailErrorMessageLabel.setWordWrap(True)
        self.saveEmailErrorMessageLabel.setMargin(0)
        self.saveEmailErrorMessageLabel.setIndent(-1)
        self.saveEmailErrorMessageLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.verticalLayout_24.addWidget(self.saveEmailErrorMessageLabel)

        self.emailPushButtonFrame = QFrame(self.settingsChangeInsideVerticalFrame)
        self.emailPushButtonFrame.setObjectName(u"emailPushButtonFrame")
        self.emailPushButtonFrame.setMaximumSize(QSize(500, 16777215))
        self.horizontalLayout_30 = QHBoxLayout(self.emailPushButtonFrame)
        self.horizontalLayout_30.setObjectName(u"horizontalLayout_30")
        self.horizontalLayout_30.setContentsMargins(-1, 9, -1, -1)
        self.emailPushButton = QPushButton(self.emailPushButtonFrame)
        self.emailPushButton.setObjectName(u"emailPushButton")
        self.emailPushButton.setMinimumSize(QSize(145, 31))
        self.emailPushButton.setMaximumSize(QSize(145, 31))
        self.emailPushButton.setFont(font4)
        self.emailPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.emailPushButton.setStyleSheet(u"#emailPushButton  {\n"
"    background-color: #4e4f5a;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: #f3f3f3;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"\n"
"#emailPushButton:hover {\n"
"    background-color: #464751; \n"
"	border-color: #d7d7d7;\n"
"}\n"
"\n"
"#emailPushButton:pressed {\n"
"    background-color: #383840; \n"
"	border-color:#d7d7d7;\n"
"}")

        self.horizontalLayout_30.addWidget(self.emailPushButton)


        self.verticalLayout_24.addWidget(self.emailPushButtonFrame)

        self.verticalSpacer_23 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_24.addItem(self.verticalSpacer_23)

        self.changeUsernameLabel = QLabel(self.settingsChangeInsideVerticalFrame)
        self.changeUsernameLabel.setObjectName(u"changeUsernameLabel")
        self.changeUsernameLabel.setMinimumSize(QSize(0, 40))
        self.changeUsernameLabel.setFont(font4)
        self.changeUsernameLabel.setStyleSheet(u"#changeUsernameLabel {\n"
"    color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")

        self.verticalLayout_24.addWidget(self.changeUsernameLabel)

        self.usernameLineEdit = QLineEdit(self.settingsChangeInsideVerticalFrame)
        self.usernameLineEdit.setObjectName(u"usernameLineEdit")
        self.usernameLineEdit.setMaximumSize(QSize(500, 33))
        self.usernameLineEdit.setFont(font3)
        self.usernameLineEdit.setStyleSheet(u"#usernameLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px; \n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"}")

        self.verticalLayout_24.addWidget(self.usernameLineEdit)

        self.saveUsernameErrorMessageLabel = QLabel(self.settingsChangeInsideVerticalFrame)
        self.saveUsernameErrorMessageLabel.setObjectName(u"saveUsernameErrorMessageLabel")
        sizePolicy5.setHeightForWidth(self.saveUsernameErrorMessageLabel.sizePolicy().hasHeightForWidth())
        self.saveUsernameErrorMessageLabel.setSizePolicy(sizePolicy5)
        self.saveUsernameErrorMessageLabel.setMinimumSize(QSize(252, 20))
        self.saveUsernameErrorMessageLabel.setMaximumSize(QSize(500, 50))
        self.saveUsernameErrorMessageLabel.setFont(font4)
        self.saveUsernameErrorMessageLabel.setStyleSheet(u"#saveUsernameErrorMessageLabel {\n"
"	background-color: #3c3d4a;\n"
"	color: #d84f4f;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"	border: none;\n"
"}")
        self.saveUsernameErrorMessageLabel.setScaledContents(False)
        self.saveUsernameErrorMessageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.saveUsernameErrorMessageLabel.setWordWrap(True)
        self.saveUsernameErrorMessageLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.verticalLayout_24.addWidget(self.saveUsernameErrorMessageLabel)

        self.usernamePushButtonFrame = QFrame(self.settingsChangeInsideVerticalFrame)
        self.usernamePushButtonFrame.setObjectName(u"usernamePushButtonFrame")
        self.usernamePushButtonFrame.setMaximumSize(QSize(500, 16777215))
        self.horizontalLayout_31 = QHBoxLayout(self.usernamePushButtonFrame)
        self.horizontalLayout_31.setObjectName(u"horizontalLayout_31")
        self.usernamePushButton = QPushButton(self.usernamePushButtonFrame)
        self.usernamePushButton.setObjectName(u"usernamePushButton")
        self.usernamePushButton.setMinimumSize(QSize(145, 31))
        self.usernamePushButton.setMaximumSize(QSize(145, 31))
        self.usernamePushButton.setFont(font4)
        self.usernamePushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.usernamePushButton.setStyleSheet(u"#usernamePushButton  {\n"
"    background-color: #4e4f5a;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: #f3f3f3;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#usernamePushButton:hover {\n"
"    background-color: #464751; \n"
"	border-color: #d7d7d7;\n"
"}\n"
"\n"
"#usernamePushButton:pressed {\n"
"    background-color: #383840; \n"
"	border-color:#d7d7d7;\n"
"}")

        self.horizontalLayout_31.addWidget(self.usernamePushButton)


        self.verticalLayout_24.addWidget(self.usernamePushButtonFrame)

        self.verticalSpacer_24 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_24.addItem(self.verticalSpacer_24)

        self.changePasswordLabel = QLabel(self.settingsChangeInsideVerticalFrame)
        self.changePasswordLabel.setObjectName(u"changePasswordLabel")
        self.changePasswordLabel.setMinimumSize(QSize(0, 40))
        self.changePasswordLabel.setFont(font4)
        self.changePasswordLabel.setStyleSheet(u"#changePasswordLabel {\n"
"    color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")

        self.verticalLayout_24.addWidget(self.changePasswordLabel)

        self.PasswordVerticalFrame = QFrame(self.settingsChangeInsideVerticalFrame)
        self.PasswordVerticalFrame.setObjectName(u"PasswordVerticalFrame")
        self.changePasswordVerticalFrame = QVBoxLayout(self.PasswordVerticalFrame)
        self.changePasswordVerticalFrame.setSpacing(15)
        self.changePasswordVerticalFrame.setObjectName(u"changePasswordVerticalFrame")
        self.changePasswordVerticalFrame.setContentsMargins(0, 0, 0, 0)
        self.currentPasswordLineEdit = QLineEdit(self.PasswordVerticalFrame)
        self.currentPasswordLineEdit.setObjectName(u"currentPasswordLineEdit")
        self.currentPasswordLineEdit.setMaximumSize(QSize(500, 33))
        self.currentPasswordLineEdit.setFont(font3)
        self.currentPasswordLineEdit.setStyleSheet(u"#currentPasswordLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"}")
        self.currentPasswordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.changePasswordVerticalFrame.addWidget(self.currentPasswordLineEdit)

        self.newPasswordLineEdit = QLineEdit(self.PasswordVerticalFrame)
        self.newPasswordLineEdit.setObjectName(u"newPasswordLineEdit")
        self.newPasswordLineEdit.setMaximumSize(QSize(500, 33))
        self.newPasswordLineEdit.setFont(font3)
        self.newPasswordLineEdit.setStyleSheet(u"#newPasswordLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"}")
        self.newPasswordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.changePasswordVerticalFrame.addWidget(self.newPasswordLineEdit)

        self.confirmPasswordLineEdit = QLineEdit(self.PasswordVerticalFrame)
        self.confirmPasswordLineEdit.setObjectName(u"confirmPasswordLineEdit")
        self.confirmPasswordLineEdit.setMaximumSize(QSize(500, 33))
        self.confirmPasswordLineEdit.setFont(font3)
        self.confirmPasswordLineEdit.setStyleSheet(u"#confirmPasswordLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"}")
        self.confirmPasswordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.changePasswordVerticalFrame.addWidget(self.confirmPasswordLineEdit)


        self.verticalLayout_24.addWidget(self.PasswordVerticalFrame)

        self.savePasswordErrorMessageLabel = QLabel(self.settingsChangeInsideVerticalFrame)
        self.savePasswordErrorMessageLabel.setObjectName(u"savePasswordErrorMessageLabel")
        sizePolicy5.setHeightForWidth(self.savePasswordErrorMessageLabel.sizePolicy().hasHeightForWidth())
        self.savePasswordErrorMessageLabel.setSizePolicy(sizePolicy5)
        self.savePasswordErrorMessageLabel.setMinimumSize(QSize(252, 20))
        self.savePasswordErrorMessageLabel.setMaximumSize(QSize(500, 50))
        self.savePasswordErrorMessageLabel.setFont(font4)
        self.savePasswordErrorMessageLabel.setStyleSheet(u"#savePasswordErrorMessageLabel {\n"
"	background-color: #3c3d4a;\n"
"	color: #d84f4f;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"	border: none;\n"
"	line-height: 50%;\n"
"}")
        self.savePasswordErrorMessageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.savePasswordErrorMessageLabel.setWordWrap(True)
        self.savePasswordErrorMessageLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.verticalLayout_24.addWidget(self.savePasswordErrorMessageLabel)

        self.passwordPushButtonFrame = QFrame(self.settingsChangeInsideVerticalFrame)
        self.passwordPushButtonFrame.setObjectName(u"passwordPushButtonFrame")
        self.passwordPushButtonFrame.setMaximumSize(QSize(500, 16777215))
        self.horizontalLayout_32 = QHBoxLayout(self.passwordPushButtonFrame)
        self.horizontalLayout_32.setObjectName(u"horizontalLayout_32")
        self.passwordPushButton = QPushButton(self.passwordPushButtonFrame)
        self.passwordPushButton.setObjectName(u"passwordPushButton")
        self.passwordPushButton.setMinimumSize(QSize(145, 31))
        self.passwordPushButton.setMaximumSize(QSize(145, 31))
        self.passwordPushButton.setFont(font4)
        self.passwordPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.passwordPushButton.setStyleSheet(u"#passwordPushButton  {\n"
"    background-color: #4e4f5a;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: #f3f3f3;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#passwordPushButton:hover {\n"
"    background-color: #464751; \n"
"	border-color: #d7d7d7;\n"
"}\n"
"\n"
"#passwordPushButton:pressed {\n"
"    background-color: #383840; \n"
"	border-color:#d7d7d7;\n"
"}")

        self.horizontalLayout_32.addWidget(self.passwordPushButton)


        self.verticalLayout_24.addWidget(self.passwordPushButtonFrame)


        self.verticalLayout_23.addWidget(self.settingsChangeInsideVerticalFrame)

        self.verticalSpacer_25 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_23.addItem(self.verticalSpacer_25)


        self.horizontalLayout_29.addWidget(self.settingsChangeVerticalFrame)

        self.settingsInterfaceMacButtonsVerticalFrame = QFrame(self.settingsLeftHorizontalFrame)
        self.settingsInterfaceMacButtonsVerticalFrame.setObjectName(u"settingsInterfaceMacButtonsVerticalFrame")
        sizePolicy5.setHeightForWidth(self.settingsInterfaceMacButtonsVerticalFrame.sizePolicy().hasHeightForWidth())
        self.settingsInterfaceMacButtonsVerticalFrame.setSizePolicy(sizePolicy5)
        self.settingsInterfaceMacButtonsVerticalFrame.setStyleSheet(u"")
        self.verticalLayout_25 = QVBoxLayout(self.settingsInterfaceMacButtonsVerticalFrame)
        self.verticalLayout_25.setSpacing(25)
        self.verticalLayout_25.setObjectName(u"verticalLayout_25")
        self.verticalLayout_25.setContentsMargins(0, 10, 0, 0)
        self.interfaceSettingsHorizontalFrame = QFrame(self.settingsInterfaceMacButtonsVerticalFrame)
        self.interfaceSettingsHorizontalFrame.setObjectName(u"interfaceSettingsHorizontalFrame")
        self.horizontalLayout_33 = QHBoxLayout(self.interfaceSettingsHorizontalFrame)
        self.horizontalLayout_33.setSpacing(0)
        self.horizontalLayout_33.setObjectName(u"horizontalLayout_33")
        self.horizontalLayout_33.setContentsMargins(0, 0, 0, 0)
        self.interfaceSettingsVerticalFrame = QFrame(self.interfaceSettingsHorizontalFrame)
        self.interfaceSettingsVerticalFrame.setObjectName(u"interfaceSettingsVerticalFrame")
        self.verticalLayout_26 = QVBoxLayout(self.interfaceSettingsVerticalFrame)
        self.verticalLayout_26.setSpacing(0)
        self.verticalLayout_26.setObjectName(u"verticalLayout_26")
        self.verticalLayout_26.setContentsMargins(0, 0, 0, 0)
        self.interfaceColorModeLabel = QLabel(self.interfaceSettingsVerticalFrame)
        self.interfaceColorModeLabel.setObjectName(u"interfaceColorModeLabel")
        self.interfaceColorModeLabel.setMinimumSize(QSize(185, 40))
        self.interfaceColorModeLabel.setFont(font4)
        self.interfaceColorModeLabel.setStyleSheet(u"#interfaceColorModeLabel {\n"
"    color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")

        self.verticalLayout_26.addWidget(self.interfaceColorModeLabel)

        self.colorModeComboBoxFrame = QFrame(self.interfaceSettingsVerticalFrame)
        self.colorModeComboBoxFrame.setObjectName(u"colorModeComboBoxFrame")
        self.colorModeComboBoxFrame.setMinimumSize(QSize(195, 32))
        self.colorModeComboBoxFrame.setMaximumSize(QSize(195, 32))
        self.colorModeComboBoxFrame.setFont(font6)
        self.colorModeComboBoxFrame.setStyleSheet(u"#colorModeComboBoxFrame {\n"
"    background-color: #f3f3f3;\n"
"    color: black;\n"
"    border: 2px solid lightgray; \n"
"    border-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.colorModeComboBoxFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.colorModeComboBoxFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.colorModeComboBoxArrow = QFrame(self.colorModeComboBoxFrame)
        self.colorModeComboBoxArrow.setObjectName(u"colorModeComboBoxArrow")
        self.colorModeComboBoxArrow.setGeometry(QRect(171, 0, 24, 32))
        self.colorModeComboBoxArrow.setMinimumSize(QSize(24, 32))
        self.colorModeComboBoxArrow.setMaximumSize(QSize(22, 32))
        self.colorModeComboBoxArrow.setFont(font6)
        self.colorModeComboBoxArrow.setStyleSheet(u"#colorModeComboBoxArrow {\n"
"    background-color: lightgray;\n"
"    color: black;\n"
"    border-top-right-radius: 10px;\n"
"    border-bottom-right-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.colorModeComboBoxArrow.setFrameShape(QFrame.Shape.StyledPanel)
        self.colorModeComboBoxArrow.setFrameShadow(QFrame.Shadow.Raised)
        self.colorModeComboBox = QComboBox(self.colorModeComboBoxFrame)
        self.colorModeComboBox.addItem("")
        self.colorModeComboBox.addItem("")
        self.colorModeComboBox.setObjectName(u"colorModeComboBox")
        self.colorModeComboBox.setEnabled(True)
        self.colorModeComboBox.setGeometry(QRect(0, 0, 195, 32))
        self.colorModeComboBox.setMinimumSize(QSize(195, 32))
        self.colorModeComboBox.setMaximumSize(QSize(195, 32))
        self.colorModeComboBox.setFont(font3)
        self.colorModeComboBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.colorModeComboBox.setStyleSheet(u"#colorModeComboBox {\n"
"    background-color: transparent;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"    border: 2px outset transparent;\n"
"    border-radius: 10px;\n"
"    padding: 4px;\n"
"	padding-left: 10px;\n"
"}\n"
"\n"
"#colorModeComboBox QAbstractItemView {\n"
"    background-color:  #f3f3f3;\n"
"    selection-background-color: rgb(95, 97, 109);\n"
"    color: rgb(0, 0, 0);\n"
"    border: 1px solid black;\n"
"    padding: 10px;\n"
"    padding-left: 5px;\n"
"    padding-right: 5px;\n"
"}\n"
"\n"
"#colorModeComboBox QAbstractItemView::item:hover { \n"
"    background-color: rgba(0, 0, 0, 0.07);\n"
"    color: black;\n"
"    border-radius: 6px;\n"
"    padding-left: 8px;\n"
"}\n"
"\n"
"#colorModeComboBox QAbstractItemView::item:selected { \n"
"    color: black;\n"
"    border: none;\n"
"    outline: none;\n"
"}\n"
"\n"
"#colorModeComboBox QListView{\n"
"    outline: 0px;\n"
"}")

        self.verticalLayout_26.addWidget(self.colorModeComboBoxFrame)


        self.horizontalLayout_33.addWidget(self.interfaceSettingsVerticalFrame)

        self.horizontalSpacer_26 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_33.addItem(self.horizontalSpacer_26)


        self.verticalLayout_25.addWidget(self.interfaceSettingsHorizontalFrame)

        self.opperationModeHorizontalFrame = QFrame(self.settingsInterfaceMacButtonsVerticalFrame)
        self.opperationModeHorizontalFrame.setObjectName(u"opperationModeHorizontalFrame")
        self.horizontalLayout_34 = QHBoxLayout(self.opperationModeHorizontalFrame)
        self.horizontalLayout_34.setSpacing(0)
        self.horizontalLayout_34.setObjectName(u"horizontalLayout_34")
        self.horizontalLayout_34.setContentsMargins(0, 0, 0, 0)
        self.opperationModeVerticalFrame = QFrame(self.opperationModeHorizontalFrame)
        self.opperationModeVerticalFrame.setObjectName(u"opperationModeVerticalFrame")
        self.verticalLayout_27 = QVBoxLayout(self.opperationModeVerticalFrame)
        self.verticalLayout_27.setSpacing(0)
        self.verticalLayout_27.setObjectName(u"verticalLayout_27")
        self.verticalLayout_27.setContentsMargins(0, 0, 0, 0)
        self.operationModeLabel = QLabel(self.opperationModeVerticalFrame)
        self.operationModeLabel.setObjectName(u"operationModeLabel")
        self.operationModeLabel.setMinimumSize(QSize(265, 40))
        self.operationModeLabel.setFont(font4)
        self.operationModeLabel.setStyleSheet(u"#operationModeLabel {\n"
"    color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")

        self.verticalLayout_27.addWidget(self.operationModeLabel)

        self.operationModeComboBoxFrame = QFrame(self.opperationModeVerticalFrame)
        self.operationModeComboBoxFrame.setObjectName(u"operationModeComboBoxFrame")
        self.operationModeComboBoxFrame.setMinimumSize(QSize(195, 32))
        self.operationModeComboBoxFrame.setMaximumSize(QSize(195, 32))
        self.operationModeComboBoxFrame.setFont(font6)
        self.operationModeComboBoxFrame.setStyleSheet(u"#operationModeComboBoxFrame {\n"
"    background-color: #f3f3f3;\n"
"    color: black;\n"
"    border: 2px solid lightgray; \n"
"    border-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.operationModeComboBoxFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.operationModeComboBoxFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.operationModeComboBoxArrow = QFrame(self.operationModeComboBoxFrame)
        self.operationModeComboBoxArrow.setObjectName(u"operationModeComboBoxArrow")
        self.operationModeComboBoxArrow.setGeometry(QRect(171, 0, 24, 32))
        self.operationModeComboBoxArrow.setMinimumSize(QSize(24, 32))
        self.operationModeComboBoxArrow.setMaximumSize(QSize(22, 32))
        self.operationModeComboBoxArrow.setFont(font6)
        self.operationModeComboBoxArrow.setStyleSheet(u"#operationModeComboBoxArrow {\n"
"    background-color: lightgray;\n"
"    color: black;\n"
"    border-top-right-radius: 10px;\n"
"    border-bottom-right-radius: 10px;\n"
"    padding-left: 10px;\n"
"}")
        self.operationModeComboBoxArrow.setFrameShape(QFrame.Shape.StyledPanel)
        self.operationModeComboBoxArrow.setFrameShadow(QFrame.Shadow.Raised)
        self.operationModeComboBox = QComboBox(self.operationModeComboBoxFrame)
        self.operationModeComboBox.addItem("")
        self.operationModeComboBox.addItem("")
        self.operationModeComboBox.addItem("")
        self.operationModeComboBox.setObjectName(u"operationModeComboBox")
        self.operationModeComboBox.setEnabled(True)
        self.operationModeComboBox.setGeometry(QRect(0, 0, 195, 32))
        self.operationModeComboBox.setMinimumSize(QSize(195, 32))
        self.operationModeComboBox.setMaximumSize(QSize(195, 32))
        self.operationModeComboBox.setFont(font3)
        self.operationModeComboBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.operationModeComboBox.setStyleSheet(u"#operationModeComboBox {\n"
"    background-color: transparent;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"    border: 2px outset transparent;\n"
"    border-radius: 10px;\n"
"    padding: 4px;\n"
"	padding-left: 10px;\n"
"}\n"
"\n"
"#operationModeComboBox QAbstractItemView {\n"
"    background-color:  #f3f3f3;\n"
"    selection-background-color: rgb(95, 97, 109);\n"
"    color: rgb(0, 0, 0);\n"
"    border: 1px solid black;\n"
"    padding: 10px;\n"
"    padding-left: 5px;\n"
"    padding-right: 5px;\n"
"}\n"
"\n"
"#operationModeComboBox QAbstractItemView::item:hover { \n"
"    background-color: rgba(0, 0, 0, 0.07);\n"
"    color: black;\n"
"    border-radius: 6px;\n"
"    padding-left: 8px;\n"
"}\n"
"\n"
"#operationModeComboBox QAbstractItemView::item:selected { \n"
"    color: black;\n"
"    border: none;\n"
"    outline: none;\n"
"}\n"
"\n"
"#operationModeComboBox QListView{\n"
"    outline: 0px;\n"
"}")

        self.verticalLayout_27.addWidget(self.operationModeComboBoxFrame)


        self.horizontalLayout_34.addWidget(self.opperationModeVerticalFrame)

        self.horizontalSpacer_27 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_34.addItem(self.horizontalSpacer_27)


        self.verticalLayout_25.addWidget(self.opperationModeHorizontalFrame)

        self.macAddressBlacklistHorizontalFrame = QFrame(self.settingsInterfaceMacButtonsVerticalFrame)
        self.macAddressBlacklistHorizontalFrame.setObjectName(u"macAddressBlacklistHorizontalFrame")
        sizePolicy5.setHeightForWidth(self.macAddressBlacklistHorizontalFrame.sizePolicy().hasHeightForWidth())
        self.macAddressBlacklistHorizontalFrame.setSizePolicy(sizePolicy5)
        self.macAddressBlacklistHorizontalFrame.setMaximumSize(QSize(16777215, 357))
        self.macAddressBlacklistHorizontalFrame.setStyleSheet(u"")
        self.horizontalLayout_35 = QHBoxLayout(self.macAddressBlacklistHorizontalFrame)
        self.horizontalLayout_35.setSpacing(0)
        self.horizontalLayout_35.setObjectName(u"horizontalLayout_35")
        self.horizontalLayout_35.setContentsMargins(0, 0, 0, 0)
        self.macAddressBlacklistVerticalFrame = QFrame(self.macAddressBlacklistHorizontalFrame)
        self.macAddressBlacklistVerticalFrame.setObjectName(u"macAddressBlacklistVerticalFrame")
        self.macAddressBlacklistVerticalFrame.setMinimumSize(QSize(0, 0))
        self.verticalLayout_28 = QVBoxLayout(self.macAddressBlacklistVerticalFrame)
        self.verticalLayout_28.setSpacing(0)
        self.verticalLayout_28.setObjectName(u"verticalLayout_28")
        self.verticalLayout_28.setContentsMargins(0, 0, 0, 0)
        self.macAddressBlacklistLabel = QLabel(self.macAddressBlacklistVerticalFrame)
        self.macAddressBlacklistLabel.setObjectName(u"macAddressBlacklistLabel")
        self.macAddressBlacklistLabel.setMinimumSize(QSize(185, 40))
        self.macAddressBlacklistLabel.setFont(font4)
        self.macAddressBlacklistLabel.setStyleSheet(u"#macAddressBlacklistLabel {\n"
"    color: #f3f3f3;\n"
"    font-size: 19px;\n"
"    font-family: Cairo;\n"
"    font-weight: bold;\n"
"}")

        self.verticalLayout_28.addWidget(self.macAddressBlacklistLabel)

        self.macAddressListWidget = QListWidget(self.macAddressBlacklistVerticalFrame)
        self.macAddressListWidget.setObjectName(u"macAddressListWidget")
        self.macAddressListWidget.setMinimumSize(QSize(256, 170))
        self.macAddressListWidget.setMaximumSize(QSize(375, 275))
        self.macAddressListWidget.setFont(font3)
        self.macAddressListWidget.setStyleSheet(u"#macAddressListWidget {\n"
"    background-color: #f3f3f3;\n"
"    border-radius: 15px;\n"
"    border: 2px solid lightgray;\n"
"    padding: 5px;\n"
"    color: black;\n"
"    font-size: 17px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#macAddressListWidget::item {\n"
"    color: black;\n"
"}\n"
"\n"
"#macAddressListWidget::item:hover {\n"
"    background-color: rgba(0, 0, 0, 0.05);\n"
"    border-radius: 10px;\n"
"    color: black;\n"
"}\n"
"\n"
"#macAddressListWidget::item:selected {\n"
"	background-color: transparent;\n"
"    color: black;\n"
"    outline: none;\n"
"    border: none;\n"
"}\n"
"\n"
"#macAddressListWidget::focus {\n"
"    outline: none;\n"
"}\n"
"\n"
"#macAddressListWidget::corner {\n"
"    background-color: #f3f3f3;\n"
"    border-top-left-radius: 8px;\n"
"}\n"
"\n"
"#macAddressListWidget QScrollBar:vertical, #macAddressListWidget QScrollBar:horizontal {\n"
"    background-color: rgb(250, 250, 250);\n"
"    border: 1px solid rgb(153, 153, 153);\n"
"    width: 10px;\n"
"    height: 10px; \n"
""
                        "    margin: 0px 0px 0px 0px;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#macAddressListWidget QScrollBar::handle:vertical,  #macAddressListWidget QScrollBar::handle:horizontal {\n"
"    background-color: black;\n"
"    min-height: 100px;\n"
"    border: 0px solid black;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"#macAddressListWidget QScrollBar::add-line:vertical, #macAddressListWidget QScrollBar::add-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: bottom;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"#macAddressListWidget QScrollBar::sub-line:vertical, #macAddressListWidget QScrollBar::sub-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: top;\n"
"    subcontrol-origin: margin;\n"
"}")
        self.macAddressListWidget.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.macAddressListWidget.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.macAddressListWidget.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked)
        self.macAddressListWidget.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        self.verticalLayout_28.addWidget(self.macAddressListWidget)

        self.macAddressLineEditHorizontalFrame = QFrame(self.macAddressBlacklistVerticalFrame)
        self.macAddressLineEditHorizontalFrame.setObjectName(u"macAddressLineEditHorizontalFrame")
        self.macAddressLineEditHorizontalFrame.setMaximumSize(QSize(375, 42))
        self.horizontalLayout_36 = QHBoxLayout(self.macAddressLineEditHorizontalFrame)
        self.horizontalLayout_36.setSpacing(7)
        self.horizontalLayout_36.setObjectName(u"horizontalLayout_36")
        self.horizontalLayout_36.setContentsMargins(0, 7, 0, 0)
        self.macAddressLineEdit = QLineEdit(self.macAddressLineEditHorizontalFrame)
        self.macAddressLineEdit.setObjectName(u"macAddressLineEdit")
        self.macAddressLineEdit.setMaximumSize(QSize(16777215, 33))
        self.macAddressLineEdit.setFont(font3)
        self.macAddressLineEdit.setStyleSheet(u"#macAddressLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray; \n"
"    border-radius: 10px;\n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 15px;\n"
"    font-family: Cairo;\n"
"}")
        self.macAddressLineEdit.setMaxLength(17)

        self.horizontalLayout_36.addWidget(self.macAddressLineEdit)

        self.addMacAddressPushButton = QPushButton(self.macAddressLineEditHorizontalFrame)
        self.addMacAddressPushButton.setObjectName(u"addMacAddressPushButton")
        self.addMacAddressPushButton.setMinimumSize(QSize(70, 35))
        self.addMacAddressPushButton.setMaximumSize(QSize(70, 35))
        self.addMacAddressPushButton.setFont(font4)
        self.addMacAddressPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.addMacAddressPushButton.setStyleSheet(u"#addMacAddressPushButton  {\n"
"    background-color: #3a8e32;\n"
"    border: 1px solid black;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#addMacAddressPushButton:hover {\n"
"     background-color: #4d9946;\n"
" }\n"
"\n"
"#addMacAddressPushButton:pressed {\n"
"    background-color: #2e7128;\n"
"}")

        self.horizontalLayout_36.addWidget(self.addMacAddressPushButton)


        self.verticalLayout_28.addWidget(self.macAddressLineEditHorizontalFrame)

        self.macAddressBlacklistErrorMessageLabel = QLabel(self.macAddressBlacklistVerticalFrame)
        self.macAddressBlacklistErrorMessageLabel.setObjectName(u"macAddressBlacklistErrorMessageLabel")
        sizePolicy5.setHeightForWidth(self.macAddressBlacklistErrorMessageLabel.sizePolicy().hasHeightForWidth())
        self.macAddressBlacklistErrorMessageLabel.setSizePolicy(sizePolicy5)
        self.macAddressBlacklistErrorMessageLabel.setMinimumSize(QSize(252, 20))
        self.macAddressBlacklistErrorMessageLabel.setMaximumSize(QSize(375, 50))
        self.macAddressBlacklistErrorMessageLabel.setFont(font4)
        self.macAddressBlacklistErrorMessageLabel.setStyleSheet(u"#macAddressBlacklistErrorMessageLabel {\n"
"	background-color: #3c3d4a;\n"
"	color: #d84f4f;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"	border: none;\n"
"}")
        self.macAddressBlacklistErrorMessageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.macAddressBlacklistErrorMessageLabel.setWordWrap(True)
        self.macAddressBlacklistErrorMessageLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.verticalLayout_28.addWidget(self.macAddressBlacklistErrorMessageLabel)


        self.horizontalLayout_35.addWidget(self.macAddressBlacklistVerticalFrame)

        self.horizontalSpacer_28 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_35.addItem(self.horizontalSpacer_28)


        self.verticalLayout_25.addWidget(self.macAddressBlacklistHorizontalFrame)

        self.verticalSpacer_26 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_25.addItem(self.verticalSpacer_26)

        self.settingsButtonsHorizontalFrame = QFrame(self.settingsInterfaceMacButtonsVerticalFrame)
        self.settingsButtonsHorizontalFrame.setObjectName(u"settingsButtonsHorizontalFrame")
        self.horizontalLayout_37 = QHBoxLayout(self.settingsButtonsHorizontalFrame)
        self.horizontalLayout_37.setSpacing(10)
        self.horizontalLayout_37.setObjectName(u"horizontalLayout_37")
        self.horizontalLayout_37.setContentsMargins(0, 0, 0, 0)
        self.horizontalSpacer_29 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_37.addItem(self.horizontalSpacer_29)

        self.clearHistoryPushButton = QPushButton(self.settingsButtonsHorizontalFrame)
        self.clearHistoryPushButton.setObjectName(u"clearHistoryPushButton")
        self.clearHistoryPushButton.setMinimumSize(QSize(145, 31))
        self.clearHistoryPushButton.setMaximumSize(QSize(145, 31))
        self.clearHistoryPushButton.setFont(font4)
        self.clearHistoryPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.clearHistoryPushButton.setStyleSheet(u"#clearHistoryPushButton  {\n"
"    background-color: #d84f4f;\n"
"    border: 1px solid black;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#clearHistoryPushButton:hover {\n"
"     background-color: #db6060;\n"
"}\n"
"\n"
" #clearHistoryPushButton:pressed {\n"
"    background-color: #ac3f3f;\n"
"}")

        self.horizontalLayout_37.addWidget(self.clearHistoryPushButton)

        self.deleteAccoutPushButton = QPushButton(self.settingsButtonsHorizontalFrame)
        self.deleteAccoutPushButton.setObjectName(u"deleteAccoutPushButton")
        self.deleteAccoutPushButton.setMinimumSize(QSize(145, 31))
        self.deleteAccoutPushButton.setMaximumSize(QSize(145, 31))
        self.deleteAccoutPushButton.setFont(font4)
        self.deleteAccoutPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.deleteAccoutPushButton.setStyleSheet(u"#deleteAccoutPushButton  {\n"
"    background-color: #d84f4f;\n"
"    border: 1px solid black;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"\n"
"#deleteAccoutPushButton:hover {\n"
"    background-color: #db6060;\n"
"}\n"
"\n"
"#deleteAccoutPushButton:pressed {\n"
"    background-color: #ac3f3f;\n"
"}")

        self.horizontalLayout_37.addWidget(self.deleteAccoutPushButton)


        self.verticalLayout_25.addWidget(self.settingsButtonsHorizontalFrame)


        self.horizontalLayout_29.addWidget(self.settingsInterfaceMacButtonsVerticalFrame)


        self.verticalLayout_22.addWidget(self.settingsLeftHorizontalFrame)


        self.horizontalLayout_28.addWidget(self.settingsLeftVerticalFrame)


        self.gridLayout_6.addWidget(self.settingsHorizontalFrame, 0, 0, 1, 1)

        self.stackedWidget.addWidget(self.settingsPage)

        self.mainHorizontalFrame.addWidget(self.stackedWidget)

        self.loginRegisterVerticalFrame = QFrame(self.mainWindowHorizontalFrame)
        self.loginRegisterVerticalFrame.setObjectName(u"loginRegisterVerticalFrame")
        self.loginRegisterVerticalFrame.setMaximumSize(QSize(300, 16777215))
        self.loginRegisterVerticalFrame.setStyleSheet(u"#loginRegisterVerticalFrame {\n"
"    background-color: #2d2e36;\n"
"}")
        self.verticalLayout_29 = QVBoxLayout(self.loginRegisterVerticalFrame)
        self.verticalLayout_29.setSpacing(10)
        self.verticalLayout_29.setObjectName(u"verticalLayout_29")
        self.verticalLayout_29.setContentsMargins(0, 30, 0, 0)
        self.loginFrame = QFrame(self.loginRegisterVerticalFrame)
        self.loginFrame.setObjectName(u"loginFrame")
        self.loginFrame.setEnabled(True)
        self.loginFrame.setMinimumSize(QSize(300, 320))
        self.loginFrame.setMaximumSize(QSize(300, 320))
        self.loginFrame.setStyleSheet(u"#loginFrame {\n"
"	background-color: #2d2e36;\n"
"    border: none;\n"
"}")
        self.loginFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.loginFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.gridLayout_7 = QGridLayout(self.loginFrame)
        self.gridLayout_7.setSpacing(0)
        self.gridLayout_7.setObjectName(u"gridLayout_7")
        self.gridLayout_7.setContentsMargins(0, 0, 0, 0)
        self.loginVerticalFrame = QFrame(self.loginFrame)
        self.loginVerticalFrame.setObjectName(u"loginVerticalFrame")
        self.loginVerticalFrame.setEnabled(True)
        sizePolicy5.setHeightForWidth(self.loginVerticalFrame.sizePolicy().hasHeightForWidth())
        self.loginVerticalFrame.setSizePolicy(sizePolicy5)
        self.loginVerticalFrame.setMinimumSize(QSize(300, 320))
        self.loginVerticalFrame.setMaximumSize(QSize(300, 320))
        self.loginVerticalFrame.setCursor(QCursor(Qt.CursorShape.ArrowCursor))
        self.loginVerticalFrame.setStyleSheet(u"#loginVerticalFrame {\n"
"	background-color: #2d2e36;\n"
"	border: none;\n"
"}")
        self.verticalLayout_30 = QVBoxLayout(self.loginVerticalFrame)
        self.verticalLayout_30.setSpacing(5)
        self.verticalLayout_30.setObjectName(u"verticalLayout_30")
        self.verticalLayout_30.setContentsMargins(20, 0, 15, 10)
        self.loginLabel = QLabel(self.loginVerticalFrame)
        self.loginLabel.setObjectName(u"loginLabel")
        self.loginLabel.setMinimumSize(QSize(0, 50))
        self.loginLabel.setMaximumSize(QSize(16777215, 70))
        self.loginLabel.setFont(font4)
        self.loginLabel.setStyleSheet(u"#loginLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #f3f3f3;\n"
"    font-size: 27px;\n"
"    font-family: Cairo;\n"
"}")
        self.loginLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.loginLabel.setMargin(0)

        self.verticalLayout_30.addWidget(self.loginLabel)

        self.loginLineEditsVerticalFrame = QFrame(self.loginVerticalFrame)
        self.loginLineEditsVerticalFrame.setObjectName(u"loginLineEditsVerticalFrame")
        self.loginLineEditsVerticalFrame.setMinimumSize(QSize(265, 100))
        self.loginLineEditsVerticalFrame.setMaximumSize(QSize(265, 100))
        self.loginLineEditsVerticalFrame.setStyleSheet(u"#loginLineEditsVerticalFrame {\n"
"	background-color: #2d2e36;\n"
"	border: none;\n"
"}")
        self.verticalLayout_31 = QVBoxLayout(self.loginLineEditsVerticalFrame)
        self.verticalLayout_31.setSpacing(5)
        self.verticalLayout_31.setObjectName(u"verticalLayout_31")
        self.verticalLayout_31.setContentsMargins(0, 0, 0, 0)
        self.loginUsernameLineEdit = QLineEdit(self.loginLineEditsVerticalFrame)
        self.loginUsernameLineEdit.setObjectName(u"loginUsernameLineEdit")
        sizePolicy5.setHeightForWidth(self.loginUsernameLineEdit.sizePolicy().hasHeightForWidth())
        self.loginUsernameLineEdit.setSizePolicy(sizePolicy5)
        self.loginUsernameLineEdit.setMinimumSize(QSize(265, 34))
        self.loginUsernameLineEdit.setMaximumSize(QSize(16777215, 34))
        self.loginUsernameLineEdit.setFont(font3)
        self.loginUsernameLineEdit.setStyleSheet(u"#loginUsernameLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px; \n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}")

        self.verticalLayout_31.addWidget(self.loginUsernameLineEdit)

        self.loginPasswordLineEdit = QLineEdit(self.loginLineEditsVerticalFrame)
        self.loginPasswordLineEdit.setObjectName(u"loginPasswordLineEdit")
        sizePolicy5.setHeightForWidth(self.loginPasswordLineEdit.sizePolicy().hasHeightForWidth())
        self.loginPasswordLineEdit.setSizePolicy(sizePolicy5)
        self.loginPasswordLineEdit.setMinimumSize(QSize(265, 34))
        self.loginPasswordLineEdit.setMaximumSize(QSize(16777215, 34))
        self.loginPasswordLineEdit.setFont(font5)
        self.loginPasswordLineEdit.setStyleSheet(u"#loginPasswordLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"")
        self.loginPasswordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.verticalLayout_31.addWidget(self.loginPasswordLineEdit)


        self.verticalLayout_30.addWidget(self.loginLineEditsVerticalFrame)

        self.loginErrorMessageLabel = QLabel(self.loginVerticalFrame)
        self.loginErrorMessageLabel.setObjectName(u"loginErrorMessageLabel")
        sizePolicy5.setHeightForWidth(self.loginErrorMessageLabel.sizePolicy().hasHeightForWidth())
        self.loginErrorMessageLabel.setSizePolicy(sizePolicy5)
        self.loginErrorMessageLabel.setMinimumSize(QSize(252, 20))
        self.loginErrorMessageLabel.setMaximumSize(QSize(16777215, 50))
        self.loginErrorMessageLabel.setFont(font4)
        self.loginErrorMessageLabel.setStyleSheet(u"#loginErrorMessageLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #d84f4f;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"}")
        self.loginErrorMessageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.loginErrorMessageLabel.setWordWrap(True)
        self.loginErrorMessageLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.verticalLayout_30.addWidget(self.loginErrorMessageLabel)

        self.loginButtonFrame = QFrame(self.loginVerticalFrame)
        self.loginButtonFrame.setObjectName(u"loginButtonFrame")
        self.loginButtonFrame.setMaximumSize(QSize(300, 70))
        self.loginButtonFrame.setStyleSheet(u"#loginButtonFrame {\n"
"	background-color: #2d2e36;\n"
"}")
        self.horizontalLayout_38 = QHBoxLayout(self.loginButtonFrame)
        self.horizontalLayout_38.setSpacing(0)
        self.horizontalLayout_38.setObjectName(u"horizontalLayout_38")
        self.horizontalLayout_38.setContentsMargins(0, 15, 0, 15)
        self.loginPushButton = QPushButton(self.loginButtonFrame)
        self.loginPushButton.setObjectName(u"loginPushButton")
        self.loginPushButton.setMaximumSize(QSize(100, 36))
        self.loginPushButton.setFont(font4)
        self.loginPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.loginPushButton.setStyleSheet(u"#loginPushButton  {\n"
"    background-color: #4e4f5a;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: #f3f3f3;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#loginPushButton:hover {\n"
"    background-color: #464751; \n"
"	border-color: #d7d7d7;\n"
"}\n"
"\n"
"#loginPushButton:pressed {\n"
"    background-color: #383840; \n"
"	border-color:#d7d7d7;\n"
"}")

        self.horizontalLayout_38.addWidget(self.loginPushButton)


        self.verticalLayout_30.addWidget(self.loginButtonFrame)

        self.moveToRegisterLabel = QLabel(self.loginVerticalFrame)
        self.moveToRegisterLabel.setObjectName(u"moveToRegisterLabel")
        sizePolicy5.setHeightForWidth(self.moveToRegisterLabel.sizePolicy().hasHeightForWidth())
        self.moveToRegisterLabel.setSizePolicy(sizePolicy5)
        self.moveToRegisterLabel.setMinimumSize(QSize(250, 20))
        self.moveToRegisterLabel.setMaximumSize(QSize(16777215, 20))
        self.moveToRegisterLabel.setFont(font5)
        self.moveToRegisterLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.moveToRegisterLabel.setStyleSheet(u"#moveToRegisterLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #6ba6fd;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#moveToRegisterLabel:hover {\n"
"	color: #6095e3;\n"
"}\n"
"")
        self.moveToRegisterLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.verticalLayout_30.addWidget(self.moveToRegisterLabel)

        self.moveToForgotPasswordLabel = QLabel(self.loginVerticalFrame)
        self.moveToForgotPasswordLabel.setObjectName(u"moveToForgotPasswordLabel")
        sizePolicy5.setHeightForWidth(self.moveToForgotPasswordLabel.sizePolicy().hasHeightForWidth())
        self.moveToForgotPasswordLabel.setSizePolicy(sizePolicy5)
        self.moveToForgotPasswordLabel.setMinimumSize(QSize(250, 20))
        self.moveToForgotPasswordLabel.setMaximumSize(QSize(16777215, 20))
        self.moveToForgotPasswordLabel.setFont(font5)
        self.moveToForgotPasswordLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.moveToForgotPasswordLabel.setStyleSheet(u"#moveToForgotPasswordLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #6ba6fd;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#moveToForgotPasswordLabel:hover {\n"
"	color: #6095e3;\n"
"}\n"
"")
        self.moveToForgotPasswordLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.verticalLayout_30.addWidget(self.moveToForgotPasswordLabel)


        self.gridLayout_7.addWidget(self.loginVerticalFrame, 0, 0, 1, 1)


        self.verticalLayout_29.addWidget(self.loginFrame)

        self.registerFrame = QFrame(self.loginRegisterVerticalFrame)
        self.registerFrame.setObjectName(u"registerFrame")
        self.registerFrame.setEnabled(True)
        self.registerFrame.setMinimumSize(QSize(300, 390))
        self.registerFrame.setMaximumSize(QSize(300, 390))
        self.registerFrame.setStyleSheet(u"#registerFrame {\n"
"    background-color: #2d2e36;\n"
"    border: none;\n"
"}")
        self.registerFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.registerFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.gridLayout_8 = QGridLayout(self.registerFrame)
        self.gridLayout_8.setSpacing(0)
        self.gridLayout_8.setObjectName(u"gridLayout_8")
        self.gridLayout_8.setContentsMargins(0, 0, 0, 0)
        self.registerVerticalFrame = QFrame(self.registerFrame)
        self.registerVerticalFrame.setObjectName(u"registerVerticalFrame")
        self.registerVerticalFrame.setMinimumSize(QSize(300, 390))
        self.registerVerticalFrame.setMaximumSize(QSize(300, 390))
        self.registerVerticalFrame.setStyleSheet(u"#registerVerticalFrame {\n"
"	background-color: #2d2e36;\n"
"	border: none;\n"
"}")
        self.verticalLayout_32 = QVBoxLayout(self.registerVerticalFrame)
        self.verticalLayout_32.setSpacing(5)
        self.verticalLayout_32.setObjectName(u"verticalLayout_32")
        self.verticalLayout_32.setContentsMargins(20, 0, 15, 10)
        self.registerLabel = QLabel(self.registerVerticalFrame)
        self.registerLabel.setObjectName(u"registerLabel")
        self.registerLabel.setMinimumSize(QSize(0, 50))
        self.registerLabel.setMaximumSize(QSize(16777215, 70))
        self.registerLabel.setFont(font4)
        self.registerLabel.setStyleSheet(u"#registerLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #f3f3f3;\n"
"    font-size: 27px;\n"
"    font-family: Cairo;\n"
"}")
        self.registerLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.registerLabel.setMargin(0)

        self.verticalLayout_32.addWidget(self.registerLabel)

        self.registerLineEditsVerticalFrame = QFrame(self.registerVerticalFrame)
        self.registerLineEditsVerticalFrame.setObjectName(u"registerLineEditsVerticalFrame")
        self.registerLineEditsVerticalFrame.setMinimumSize(QSize(265, 200))
        self.registerLineEditsVerticalFrame.setMaximumSize(QSize(265, 200))
        self.registerLineEditsVerticalFrame.setStyleSheet(u"#registerLineEditsVerticalFrame {\n"
"	background-color: #2d2e36;\n"
"	border: none;\n"
"}")
        self.verticalLayout_33 = QVBoxLayout(self.registerLineEditsVerticalFrame)
        self.verticalLayout_33.setSpacing(5)
        self.verticalLayout_33.setObjectName(u"verticalLayout_33")
        self.verticalLayout_33.setContentsMargins(0, 0, 0, 0)
        self.registerEmailLineEdit = QLineEdit(self.registerLineEditsVerticalFrame)
        self.registerEmailLineEdit.setObjectName(u"registerEmailLineEdit")
        sizePolicy5.setHeightForWidth(self.registerEmailLineEdit.sizePolicy().hasHeightForWidth())
        self.registerEmailLineEdit.setSizePolicy(sizePolicy5)
        self.registerEmailLineEdit.setMinimumSize(QSize(265, 34))
        self.registerEmailLineEdit.setMaximumSize(QSize(16777215, 34))
        self.registerEmailLineEdit.setSizeIncrement(QSize(0, 0))
        self.registerEmailLineEdit.setFont(font3)
        self.registerEmailLineEdit.setStyleSheet(u"#registerEmailLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px; \n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}")

        self.verticalLayout_33.addWidget(self.registerEmailLineEdit)

        self.registerUsernameLineEdit = QLineEdit(self.registerLineEditsVerticalFrame)
        self.registerUsernameLineEdit.setObjectName(u"registerUsernameLineEdit")
        sizePolicy5.setHeightForWidth(self.registerUsernameLineEdit.sizePolicy().hasHeightForWidth())
        self.registerUsernameLineEdit.setSizePolicy(sizePolicy5)
        self.registerUsernameLineEdit.setMinimumSize(QSize(265, 34))
        self.registerUsernameLineEdit.setMaximumSize(QSize(16777215, 34))
        self.registerUsernameLineEdit.setSizeIncrement(QSize(0, 0))
        self.registerUsernameLineEdit.setFont(font3)
        self.registerUsernameLineEdit.setStyleSheet(u"#registerUsernameLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px; \n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}")

        self.verticalLayout_33.addWidget(self.registerUsernameLineEdit)

        self.registerPasswordLineEdit = QLineEdit(self.registerLineEditsVerticalFrame)
        self.registerPasswordLineEdit.setObjectName(u"registerPasswordLineEdit")
        sizePolicy5.setHeightForWidth(self.registerPasswordLineEdit.sizePolicy().hasHeightForWidth())
        self.registerPasswordLineEdit.setSizePolicy(sizePolicy5)
        self.registerPasswordLineEdit.setMinimumSize(QSize(265, 34))
        self.registerPasswordLineEdit.setMaximumSize(QSize(16777215, 34))
        self.registerPasswordLineEdit.setSizeIncrement(QSize(0, 0))
        self.registerPasswordLineEdit.setFont(font3)
        self.registerPasswordLineEdit.setToolTipDuration(-1)
        self.registerPasswordLineEdit.setStyleSheet(u"#registerPasswordLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px; \n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"")
        self.registerPasswordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.verticalLayout_33.addWidget(self.registerPasswordLineEdit)

        self.registerConfirmPasswordLineEdit = QLineEdit(self.registerLineEditsVerticalFrame)
        self.registerConfirmPasswordLineEdit.setObjectName(u"registerConfirmPasswordLineEdit")
        sizePolicy5.setHeightForWidth(self.registerConfirmPasswordLineEdit.sizePolicy().hasHeightForWidth())
        self.registerConfirmPasswordLineEdit.setSizePolicy(sizePolicy5)
        self.registerConfirmPasswordLineEdit.setMinimumSize(QSize(265, 34))
        self.registerConfirmPasswordLineEdit.setMaximumSize(QSize(16777215, 34))
        self.registerConfirmPasswordLineEdit.setSizeIncrement(QSize(0, 0))
        self.registerConfirmPasswordLineEdit.setFont(font3)
        self.registerConfirmPasswordLineEdit.setToolTipDuration(-1)
        self.registerConfirmPasswordLineEdit.setStyleSheet(u"#registerConfirmPasswordLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px; \n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"")
        self.registerConfirmPasswordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.verticalLayout_33.addWidget(self.registerConfirmPasswordLineEdit)


        self.verticalLayout_32.addWidget(self.registerLineEditsVerticalFrame)

        self.registerErrorMessageLabel = QLabel(self.registerVerticalFrame)
        self.registerErrorMessageLabel.setObjectName(u"registerErrorMessageLabel")
        sizePolicy5.setHeightForWidth(self.registerErrorMessageLabel.sizePolicy().hasHeightForWidth())
        self.registerErrorMessageLabel.setSizePolicy(sizePolicy5)
        self.registerErrorMessageLabel.setMinimumSize(QSize(252, 20))
        self.registerErrorMessageLabel.setMaximumSize(QSize(16777215, 50))
        self.registerErrorMessageLabel.setFont(font4)
        self.registerErrorMessageLabel.setStyleSheet(u"#registerErrorMessageLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #d84f4f;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"}")
        self.registerErrorMessageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.registerErrorMessageLabel.setWordWrap(True)
        self.registerErrorMessageLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.verticalLayout_32.addWidget(self.registerErrorMessageLabel)

        self.registerButtonFrame = QFrame(self.registerVerticalFrame)
        self.registerButtonFrame.setObjectName(u"registerButtonFrame")
        self.registerButtonFrame.setMaximumSize(QSize(300, 70))
        self.registerButtonFrame.setStyleSheet(u"#registerButtonFrame {\n"
"	background-color: #2d2e36;\n"
"}")
        self.horizontalLayout_39 = QHBoxLayout(self.registerButtonFrame)
        self.horizontalLayout_39.setSpacing(0)
        self.horizontalLayout_39.setObjectName(u"horizontalLayout_39")
        self.horizontalLayout_39.setContentsMargins(0, 15, 0, 15)
        self.registerPushButton = QPushButton(self.registerButtonFrame)
        self.registerPushButton.setObjectName(u"registerPushButton")
        self.registerPushButton.setMaximumSize(QSize(100, 36))
        self.registerPushButton.setFont(font4)
        self.registerPushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.registerPushButton.setStyleSheet(u"#registerPushButton  {\n"
"    background-color: #4e4f5a;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: #f3f3f3;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#registerPushButton:hover {\n"
"    background-color: #464751; \n"
"	border-color: #d7d7d7;\n"
"}\n"
"\n"
"#registerPushButton:pressed {\n"
"    background-color: #383840; \n"
"	border-color:#d7d7d7;\n"
"}")

        self.horizontalLayout_39.addWidget(self.registerPushButton)


        self.verticalLayout_32.addWidget(self.registerButtonFrame)

        self.moveToLoginLabel = QLabel(self.registerVerticalFrame)
        self.moveToLoginLabel.setObjectName(u"moveToLoginLabel")
        sizePolicy5.setHeightForWidth(self.moveToLoginLabel.sizePolicy().hasHeightForWidth())
        self.moveToLoginLabel.setSizePolicy(sizePolicy5)
        self.moveToLoginLabel.setMinimumSize(QSize(250, 20))
        self.moveToLoginLabel.setMaximumSize(QSize(16777215, 20))
        self.moveToLoginLabel.setFont(font5)
        self.moveToLoginLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.moveToLoginLabel.setStyleSheet(u"#moveToLoginLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #6ba6fd;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#moveToLoginLabel:hover {\n"
"	color: #6095e3;\n"
"}\n"
"")
        self.moveToLoginLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.verticalLayout_32.addWidget(self.moveToLoginLabel)


        self.gridLayout_8.addWidget(self.registerVerticalFrame, 0, 0, 1, 1)


        self.verticalLayout_29.addWidget(self.registerFrame)

        self.resetPasswordFrame = QFrame(self.loginRegisterVerticalFrame)
        self.resetPasswordFrame.setObjectName(u"resetPasswordFrame")
        self.resetPasswordFrame.setMinimumSize(QSize(300, 250))
        self.resetPasswordFrame.setMaximumSize(QSize(300, 250))
        self.resetPasswordFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.gridLayout_9 = QGridLayout(self.resetPasswordFrame)
        self.gridLayout_9.setSpacing(0)
        self.gridLayout_9.setObjectName(u"gridLayout_9")
        self.gridLayout_9.setContentsMargins(0, 0, 0, 0)
        self.resetPasswordVerticalFrame = QFrame(self.resetPasswordFrame)
        self.resetPasswordVerticalFrame.setObjectName(u"resetPasswordVerticalFrame")
        self.resetPasswordVerticalFrame.setEnabled(True)
        sizePolicy.setHeightForWidth(self.resetPasswordVerticalFrame.sizePolicy().hasHeightForWidth())
        self.resetPasswordVerticalFrame.setSizePolicy(sizePolicy)
        self.resetPasswordVerticalFrame.setMinimumSize(QSize(300, 250))
        self.resetPasswordVerticalFrame.setMaximumSize(QSize(300, 250))
        self.resetPasswordVerticalFrame.setCursor(QCursor(Qt.CursorShape.ArrowCursor))
        self.resetPasswordVerticalFrame.setStyleSheet(u"#resetPasswordVerticalFrame {\n"
"	background-color: #2d2e36;\n"
"	border: none;\n"
"}")
        self.resetPasswordVerticalFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.verticalLayout_34 = QVBoxLayout(self.resetPasswordVerticalFrame)
        self.verticalLayout_34.setSpacing(5)
        self.verticalLayout_34.setObjectName(u"verticalLayout_34")
        self.verticalLayout_34.setContentsMargins(20, 0, 15, 10)
        self.resetPasswordLabel = QLabel(self.resetPasswordVerticalFrame)
        self.resetPasswordLabel.setObjectName(u"resetPasswordLabel")
        self.resetPasswordLabel.setMinimumSize(QSize(0, 50))
        self.resetPasswordLabel.setMaximumSize(QSize(16777215, 70))
        self.resetPasswordLabel.setFont(font4)
        self.resetPasswordLabel.setStyleSheet(u"#resetPasswordLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #f3f3f3;\n"
"    font-size: 27px;\n"
"    font-family: Cairo;\n"
"}")
        self.resetPasswordLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.resetPasswordLabel.setMargin(0)

        self.verticalLayout_34.addWidget(self.resetPasswordLabel)

        self.resetPasswordEmailLineEdit = QLineEdit(self.resetPasswordVerticalFrame)
        self.resetPasswordEmailLineEdit.setObjectName(u"resetPasswordEmailLineEdit")
        sizePolicy5.setHeightForWidth(self.resetPasswordEmailLineEdit.sizePolicy().hasHeightForWidth())
        self.resetPasswordEmailLineEdit.setSizePolicy(sizePolicy5)
        self.resetPasswordEmailLineEdit.setMinimumSize(QSize(265, 34))
        self.resetPasswordEmailLineEdit.setMaximumSize(QSize(16777215, 34))
        self.resetPasswordEmailLineEdit.setFont(font3)
        self.resetPasswordEmailLineEdit.setStyleSheet(u"#resetPasswordEmailLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px; \n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}")

        self.verticalLayout_34.addWidget(self.resetPasswordEmailLineEdit)

        self.resetPasswordEmailErrorMessageLabel = QLabel(self.resetPasswordVerticalFrame)
        self.resetPasswordEmailErrorMessageLabel.setObjectName(u"resetPasswordEmailErrorMessageLabel")
        sizePolicy5.setHeightForWidth(self.resetPasswordEmailErrorMessageLabel.sizePolicy().hasHeightForWidth())
        self.resetPasswordEmailErrorMessageLabel.setSizePolicy(sizePolicy5)
        self.resetPasswordEmailErrorMessageLabel.setMinimumSize(QSize(252, 20))
        self.resetPasswordEmailErrorMessageLabel.setMaximumSize(QSize(16777215, 50))
        self.resetPasswordEmailErrorMessageLabel.setFont(font4)
        self.resetPasswordEmailErrorMessageLabel.setStyleSheet(u"#resetPasswordEmailErrorMessageLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #d84f4f;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"}")
        self.resetPasswordEmailErrorMessageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.resetPasswordEmailErrorMessageLabel.setWordWrap(True)
        self.resetPasswordEmailErrorMessageLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.verticalLayout_34.addWidget(self.resetPasswordEmailErrorMessageLabel)

        self.sendCodeButtonFrame = QFrame(self.resetPasswordVerticalFrame)
        self.sendCodeButtonFrame.setObjectName(u"sendCodeButtonFrame")
        self.sendCodeButtonFrame.setMaximumSize(QSize(300, 70))
        self.sendCodeButtonFrame.setStyleSheet(u"#sendCodeButtonFrame {\n"
"	background-color: #2d2e36;\n"
"}")
        self.horizontalLayout_40 = QHBoxLayout(self.sendCodeButtonFrame)
        self.horizontalLayout_40.setSpacing(0)
        self.horizontalLayout_40.setObjectName(u"horizontalLayout_40")
        self.horizontalLayout_40.setContentsMargins(0, 10, 0, 10)
        self.sendCodePushButton = QPushButton(self.sendCodeButtonFrame)
        self.sendCodePushButton.setObjectName(u"sendCodePushButton")
        self.sendCodePushButton.setMaximumSize(QSize(120, 36))
        self.sendCodePushButton.setFont(font4)
        self.sendCodePushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.sendCodePushButton.setStyleSheet(u"#sendCodePushButton  {\n"
"    background-color: #4e4f5a;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: #f3f3f3;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#sendCodePushButton:hover {\n"
"    background-color: #464751; \n"
"	border-color: #d7d7d7;\n"
"}\n"
"\n"
"#sendCodePushButton:pressed {\n"
"    background-color: #383840; \n"
"	border-color:#d7d7d7;\n"
"}")

        self.horizontalLayout_40.addWidget(self.sendCodePushButton)


        self.verticalLayout_34.addWidget(self.sendCodeButtonFrame)

        self.resetPasswordCodeLineEdit = QLineEdit(self.resetPasswordVerticalFrame)
        self.resetPasswordCodeLineEdit.setObjectName(u"resetPasswordCodeLineEdit")
        sizePolicy5.setHeightForWidth(self.resetPasswordCodeLineEdit.sizePolicy().hasHeightForWidth())
        self.resetPasswordCodeLineEdit.setSizePolicy(sizePolicy5)
        self.resetPasswordCodeLineEdit.setMinimumSize(QSize(265, 34))
        self.resetPasswordCodeLineEdit.setMaximumSize(QSize(16777215, 34))
        self.resetPasswordCodeLineEdit.setFont(font5)
        self.resetPasswordCodeLineEdit.setStyleSheet(u"#resetPasswordCodeLineEdit {\n"
"    background-color: #f3f3f3;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px; \n"
"    padding: 0px 5px;\n"
"    color: black;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"")
        self.resetPasswordCodeLineEdit.setEchoMode(QLineEdit.EchoMode.Normal)

        self.verticalLayout_34.addWidget(self.resetPasswordCodeLineEdit)

        self.resetPasswordCodeErrorMessageLabel = QLabel(self.resetPasswordVerticalFrame)
        self.resetPasswordCodeErrorMessageLabel.setObjectName(u"resetPasswordCodeErrorMessageLabel")
        sizePolicy5.setHeightForWidth(self.resetPasswordCodeErrorMessageLabel.sizePolicy().hasHeightForWidth())
        self.resetPasswordCodeErrorMessageLabel.setSizePolicy(sizePolicy5)
        self.resetPasswordCodeErrorMessageLabel.setMinimumSize(QSize(252, 20))
        self.resetPasswordCodeErrorMessageLabel.setMaximumSize(QSize(16777215, 50))
        self.resetPasswordCodeErrorMessageLabel.setFont(font4)
        self.resetPasswordCodeErrorMessageLabel.setStyleSheet(u"#resetPasswordCodeErrorMessageLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #d84f4f;\n"
"    font-size: 13px;\n"
"    font-family: Cairo;\n"
"}")
        self.resetPasswordCodeErrorMessageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.resetPasswordCodeErrorMessageLabel.setWordWrap(True)
        self.resetPasswordCodeErrorMessageLabel.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.TextSelectableByMouse)

        self.verticalLayout_34.addWidget(self.resetPasswordCodeErrorMessageLabel)

        self.verifyCodeButtonFrame = QFrame(self.resetPasswordVerticalFrame)
        self.verifyCodeButtonFrame.setObjectName(u"verifyCodeButtonFrame")
        self.verifyCodeButtonFrame.setMaximumSize(QSize(300, 70))
        self.verifyCodeButtonFrame.setStyleSheet(u"#verifyCodeButtonFrame {\n"
"	background-color: #2d2e36;\n"
"}")
        self.horizontalLayout_41 = QHBoxLayout(self.verifyCodeButtonFrame)
        self.horizontalLayout_41.setSpacing(0)
        self.horizontalLayout_41.setObjectName(u"horizontalLayout_41")
        self.horizontalLayout_41.setContentsMargins(0, 10, 0, 10)
        self.verifyCodePushButton = QPushButton(self.verifyCodeButtonFrame)
        self.verifyCodePushButton.setObjectName(u"verifyCodePushButton")
        self.verifyCodePushButton.setMaximumSize(QSize(120, 36))
        self.verifyCodePushButton.setFont(font4)
        self.verifyCodePushButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.verifyCodePushButton.setStyleSheet(u"#verifyCodePushButton  {\n"
"    background-color: #4e4f5a;\n"
"    border: 2px solid lightgray;\n"
"    border-radius: 10px;\n"
"    padding: 5px;\n"
"    color: #f3f3f3;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#verifyCodePushButton:hover {\n"
"    background-color: #464751; \n"
"	border-color: #d7d7d7;\n"
"}\n"
"\n"
"#verifyCodePushButton:pressed {\n"
"    background-color: #383840; \n"
"	border-color:#d7d7d7;\n"
"}")

        self.horizontalLayout_41.addWidget(self.verifyCodePushButton)


        self.verticalLayout_34.addWidget(self.verifyCodeButtonFrame)

        self.cancelResetPasswordProcessLabel = QLabel(self.resetPasswordVerticalFrame)
        self.cancelResetPasswordProcessLabel.setObjectName(u"cancelResetPasswordProcessLabel")
        sizePolicy5.setHeightForWidth(self.cancelResetPasswordProcessLabel.sizePolicy().hasHeightForWidth())
        self.cancelResetPasswordProcessLabel.setSizePolicy(sizePolicy5)
        self.cancelResetPasswordProcessLabel.setMinimumSize(QSize(250, 20))
        self.cancelResetPasswordProcessLabel.setMaximumSize(QSize(16777215, 20))
        self.cancelResetPasswordProcessLabel.setFont(font5)
        self.cancelResetPasswordProcessLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancelResetPasswordProcessLabel.setStyleSheet(u"#cancelResetPasswordProcessLabel {\n"
"	background-color: #2d2e36;\n"
"	color: #6ba6fd;\n"
"    font-size: 16px;\n"
"    font-family: Cairo;\n"
"}\n"
"\n"
"#cancelResetPasswordProcessLabel:hover {\n"
"	color: #6095e3;\n"
"}\n"
"")
        self.cancelResetPasswordProcessLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.verticalLayout_34.addWidget(self.cancelResetPasswordProcessLabel)


        self.gridLayout_9.addWidget(self.resetPasswordVerticalFrame, 0, 0, 1, 1)


        self.verticalLayout_29.addWidget(self.resetPasswordFrame)

        self.verticalSpacer_27 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_29.addItem(self.verticalSpacer_27)


        self.mainHorizontalFrame.addWidget(self.loginRegisterVerticalFrame)

        self.stackedWidget.raise_()
        self.sideFrame.raise_()
        self.loginRegisterVerticalFrame.raise_()

        self.gridLayout.addWidget(self.mainWindowHorizontalFrame, 1, 1, 1, 1)

        NetSpect.setCentralWidget(self.centralWidget)

        self.retranslateUi(NetSpect)

        self.stackedWidget.setCurrentIndex(0)
        self.analyticsYearComboBox.setCurrentIndex(0)
        self.reportDurationComboBox.setCurrentIndex(4)


        QMetaObject.connectSlotsByName(NetSpect)
    # setupUi

    def retranslateUi(self, NetSpect):
        NetSpect.setWindowTitle(QCoreApplication.translate("NetSpect", u"NetSpect\u2122", None))
        self.logoLabel.setText(QCoreApplication.translate("NetSpect", u"NetSpect", None))
        self.welcomeLabel.setText(QCoreApplication.translate("NetSpect", u"Welcome User", None))
#if QT_CONFIG(tooltip)
        self.logoutIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Logout.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.logoutIcon.setText("")
#if QT_CONFIG(tooltip)
        self.accountIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Login or Register.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.accountIcon.setText("")
#if QT_CONFIG(tooltip)
        self.settingsIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Settings Page.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.settingsIcon.setText("")
#if QT_CONFIG(tooltip)
        self.menuIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Expand Side Menu.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.menuIcon.setText("")
#if QT_CONFIG(tooltip)
        self.closeMenuIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Collapse Side Menu.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.closeMenuIcon.setText("")
#if QT_CONFIG(tooltip)
        self.homePageIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Home Page.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.homePageIcon.setText("")
        self.homePageLabel.setText(QCoreApplication.translate("NetSpect", u"Home Page", None))
#if QT_CONFIG(tooltip)
        self.analyticsIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Analytics Page.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.analyticsIcon.setText("")
        self.analyticsLabel.setText(QCoreApplication.translate("NetSpect", u"Analytics", None))
#if QT_CONFIG(tooltip)
        self.reportIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Report Page.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.reportIcon.setText("")
        self.reportLabel.setText(QCoreApplication.translate("NetSpect", u"Reports", None))
#if QT_CONFIG(tooltip)
        self.infoIcon.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Information Page.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.infoIcon.setText("")
        self.infoLabel.setText(QCoreApplication.translate("NetSpect", u"Information", None))
        self.initiateDefenceLabel.setText(QCoreApplication.translate("NetSpect", u"Initiate Detection", None))
#if QT_CONFIG(tooltip)
        self.startStopPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Start/Stop network scan.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.startStopPushButton.setText(QCoreApplication.translate("NetSpect", u"START", None))
        self.networkInterfaceLabel.setText(QCoreApplication.translate("NetSpect", u"Network Interface:", None))
        self.networkInterfaceComboBox.setItemText(0, QCoreApplication.translate("NetSpect", u"Ethernet", None))
        self.networkInterfaceComboBox.setItemText(1, QCoreApplication.translate("NetSpect", u"Wi-Fi", None))
        self.networkInterfaceComboBox.setItemText(2, QCoreApplication.translate("NetSpect", u"eth0", None))
        self.networkInterfaceComboBox.setItemText(3, QCoreApplication.translate("NetSpect", u"wlan0", None))

#if QT_CONFIG(tooltip)
        self.networkInterfaceComboBox.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Choose your network interface.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.runningTimeLabel.setText(QCoreApplication.translate("NetSpect", u"Running Time:", None))
#if QT_CONFIG(tooltip)
        self.runningTimeCounter.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Time passed since scan started.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.runningTimeCounter.setText(QCoreApplication.translate("NetSpect", u"0:00:00", None))
        self.numberOfDetectionsLabel.setText(QCoreApplication.translate("NetSpect", u"Number of Detections:", None))
#if QT_CONFIG(tooltip)
        self.numberOfDetectionsCounter.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Number of detected attacks.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.numberOfDetectionsCounter.setText(QCoreApplication.translate("NetSpect", u"0", None))
        self.historyLabel.setText(QCoreApplication.translate("NetSpect", u"Alert History", None))
        ___qtablewidgetitem = self.historyTableWidget.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("NetSpect", u"Source IP", None));
        ___qtablewidgetitem1 = self.historyTableWidget.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("NetSpect", u"Source MAC", None));
        ___qtablewidgetitem2 = self.historyTableWidget.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("NetSpect", u"Destination IP", None));
        ___qtablewidgetitem3 = self.historyTableWidget.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("NetSpect", u"Destination MAC", None));
        ___qtablewidgetitem4 = self.historyTableWidget.horizontalHeaderItem(4)
        ___qtablewidgetitem4.setText(QCoreApplication.translate("NetSpect", u"Detected Attack", None));
        ___qtablewidgetitem5 = self.historyTableWidget.horizontalHeaderItem(5)
        ___qtablewidgetitem5.setText(QCoreApplication.translate("NetSpect", u"Timestamp", None));
        self.analyticsYearSelectionLabel.setText(QCoreApplication.translate("NetSpect", u"Select Year:", None))
        self.analyticsYearComboBox.setItemText(0, QCoreApplication.translate("NetSpect", u"2025", None))
        self.analyticsYearComboBox.setItemText(1, QCoreApplication.translate("NetSpect", u"2024", None))

#if QT_CONFIG(tooltip)
        self.analyticsYearComboBox.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Select the year for analytics detection data.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.attacksPerMonthTitleLabel.setText(QCoreApplication.translate("NetSpect", u"<p style=\"line-height: 0.7;\">Attacks Per <br>Month</p>", None))
        self.attacksPerMonthValueLabel.setText(QCoreApplication.translate("NetSpect", u"0", None))
        self.totalNumOfAttacksTitleLabel.setText(QCoreApplication.translate("NetSpect", u"<p style=\"line-height: 0.7;\">Total Number <br>of Attacks</p>", None))
        self.totalNumOfAttacksValueLabel.setText(QCoreApplication.translate("NetSpect", u"0", None))
        self.mostPopularAttackTitleLabel.setText(QCoreApplication.translate("NetSpect", u"<p style=\"line-height: 0.7;\">Most Popular <br>Attak</p>", None))
        self.mostPopularAttackValueLabel.setText(QCoreApplication.translate("NetSpect", u"DNS<br>Tunneling", None))
        self.reportSelectionLabel.setText(QCoreApplication.translate("NetSpect", u"Report Selection", None))
        self.reportDurationComboBox.setItemText(0, QCoreApplication.translate("NetSpect", u"Last Day", None))
        self.reportDurationComboBox.setItemText(1, QCoreApplication.translate("NetSpect", u"Last Week", None))
        self.reportDurationComboBox.setItemText(2, QCoreApplication.translate("NetSpect", u"Last Month", None))
        self.reportDurationComboBox.setItemText(3, QCoreApplication.translate("NetSpect", u"Last Year", None))
        self.reportDurationComboBox.setItemText(4, QCoreApplication.translate("NetSpect", u"All Available Data", None))

#if QT_CONFIG(tooltip)
        self.reportDurationComboBox.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Select the time range for the report.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.arpSpoofingCheckBox.setText(QCoreApplication.translate("NetSpect", u"ARP Spoofing", None))
        self.portScanningCheckBox.setText(QCoreApplication.translate("NetSpect", u"Port Scanning", None))
        self.denialOfServiceCheckBox.setText(QCoreApplication.translate("NetSpect", u"DoS - Denial of Service", None))
        self.dnsTunnelingCheckBox.setText(QCoreApplication.translate("NetSpect", u"DNS Tunneling", None))
        self.machineInfoCheckBox.setText(QCoreApplication.translate("NetSpect", u"Include Machine Info", None))
#if QT_CONFIG(tooltip)
        self.downloadReportPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Download the report now.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.downloadReportPushButton.setText(QCoreApplication.translate("NetSpect", u"Download Report", None))
#if QT_CONFIG(tooltip)
        self.cancelReportPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Cancel report creation.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.cancelReportPushButton.setText(QCoreApplication.translate("NetSpect", u"Cancel Report", None))
#if QT_CONFIG(tooltip)
        self.reportProgressBar.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Report creation progress.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.reportPreviewLabel.setText(QCoreApplication.translate("NetSpect", u"Preview", None))
        self.machineInformationLabel.setText(QCoreApplication.translate("NetSpect", u"Machine Information:", None))
        self.OSTypeLabel.setText(QCoreApplication.translate("NetSpect", u"OS Type:", None))
        self.OSTypeInfoLabel.setText(QCoreApplication.translate("NetSpect", u"Windows", None))
        self.OSVersionLabel.setText(QCoreApplication.translate("NetSpect", u"OS Version:", None))
        self.OSVersionInfoLabel.setText(QCoreApplication.translate("NetSpect", u"24H2", None))
        self.architectureLabel.setText(QCoreApplication.translate("NetSpect", u"Architecture:", None))
        self.architectureInfoLabel.setText(QCoreApplication.translate("NetSpect", u"64bit", None))
        self.hostNameLabel.setText(QCoreApplication.translate("NetSpect", u"Host Name:", None))
        self.hostNameInfoLabel.setText(QCoreApplication.translate("NetSpect", u"User's PC", None))
        self.programInformationLabel.setText(QCoreApplication.translate("NetSpect", u"Program Information:", None))
        self.netspectVersionLabel.setText(QCoreApplication.translate("NetSpect", u"NetSpect Version:", None))
        self.netspectVersionInfoLabel.setText(QCoreApplication.translate("NetSpect", u"v1.0.0", None))
        self.githubLabel.setText(QCoreApplication.translate("NetSpect", u"GitHub:", None))
#if QT_CONFIG(tooltip)
        self.githubInfoLabel.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Visit NetSpect on GitHub.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.githubInfoLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p><a href=\"https://github.com/Shayhha/NetSpect\"><span style=\" text-decoration: underline; color:#f3f3f3;\">Visit NetSpect Page</span></a></p></body></html>", None))
        self.networkInterfaceInformationLabel.setText(QCoreApplication.translate("NetSpect", u"Network Interface Information:", None))
        self.connectedInterfaceLabel.setText(QCoreApplication.translate("NetSpect", u"Connected Interface:", None))
        self.connectedInterfaceInfoLabel.setText(QCoreApplication.translate("NetSpect", u"Ethernet", None))
        self.macAddressLabel.setText(QCoreApplication.translate("NetSpect", u"MAC Address:", None))
        self.macAddressInfoLabel.setText(QCoreApplication.translate("NetSpect", u"b6:a8:b6:b5:fd:11", None))
        self.descriptionLabel.setText(QCoreApplication.translate("NetSpect", u"Description:", None))
        self.descriptionInfoLabel.setText(QCoreApplication.translate("NetSpect", u"Some Description", None))
        self.maxTransmitionUnitLabel.setText(QCoreApplication.translate("NetSpect", u"Max Transmition Unit:", None))
        self.maxTransmitionUnitInfoLabel.setText(QCoreApplication.translate("NetSpect", u"1000", None))
        self.myIpAddressesLabel.setText(QCoreApplication.translate("NetSpect", u"My IP Addresses:", None))
        self.userSettingsLabel.setText(QCoreApplication.translate("NetSpect", u"User Settings:", None))
        self.changeEmailLabel.setText(QCoreApplication.translate("NetSpect", u"Change Email:", None))
#if QT_CONFIG(tooltip)
        self.emailLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Enter a valid email address (e.g., name@example.com).</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.emailLineEdit.setText("")
        self.emailLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"New Email", None))
        self.saveEmailErrorMessageLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Please fill in the email address field before changing email address.</p></body></html>", None))
#if QT_CONFIG(tooltip)
        self.emailPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Save your new email.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.emailPushButton.setText(QCoreApplication.translate("NetSpect", u"Save Email", None))
        self.changeUsernameLabel.setText(QCoreApplication.translate("NetSpect", u"Change Username:", None))
#if QT_CONFIG(tooltip)
        self.usernameLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Choose a new username between 4 and 16 characters.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.usernameLineEdit.setText("")
        self.usernameLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"New Username", None))
        self.saveUsernameErrorMessageLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Please fill in the username field before changing username.</p></body></html>", None))
#if QT_CONFIG(tooltip)
        self.usernamePushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Save your new username.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.usernamePushButton.setText(QCoreApplication.translate("NetSpect", u"Save Username", None))
        self.changePasswordLabel.setText(QCoreApplication.translate("NetSpect", u"Change Password:", None))
#if QT_CONFIG(tooltip)
        self.currentPasswordLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Enter your current password.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.currentPasswordLineEdit.setText("")
        self.currentPasswordLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Current Password", None))
#if QT_CONFIG(tooltip)
        self.newPasswordLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Choose a new password with at least 6 characters and include at least one uppercase letter and one digit.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.newPasswordLineEdit.setText("")
        self.newPasswordLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"New Password", None))
#if QT_CONFIG(tooltip)
        self.confirmPasswordLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Confirm your new password by entering it again.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.confirmPasswordLineEdit.setText("")
        self.confirmPasswordLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Confirm Password", None))
        self.savePasswordErrorMessageLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Please fill in all the password fields before changing password.</p></body></html>", None))
#if QT_CONFIG(tooltip)
        self.passwordPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Save your new password.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.passwordPushButton.setText(QCoreApplication.translate("NetSpect", u"Save Password", None))
        self.interfaceColorModeLabel.setText(QCoreApplication.translate("NetSpect", u"Interface Color Mode:", None))
        self.colorModeComboBox.setItemText(0, QCoreApplication.translate("NetSpect", u"Dark Mode", None))
        self.colorModeComboBox.setItemText(1, QCoreApplication.translate("NetSpect", u"Light Mode", None))

#if QT_CONFIG(tooltip)
        self.colorModeComboBox.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Select the color mode for the interface, dark mode or light mode.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.operationModeLabel.setText(QCoreApplication.translate("NetSpect", u"Operation Mode:", None))
        self.operationModeComboBox.setItemText(0, QCoreApplication.translate("NetSpect", u"Real Time Detection", None))
        self.operationModeComboBox.setItemText(1, QCoreApplication.translate("NetSpect", u"Collection (TCP/UDP)", None))
        self.operationModeComboBox.setItemText(2, QCoreApplication.translate("NetSpect", u"Collection (DNS)", None))

#if QT_CONFIG(tooltip)
        self.operationModeComboBox.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Select the application's operation mode, 'Real Time Detection' for detecting attacks in real time and 'Data Collection TCP/UDP' or 'Data Collection DNS' for collecting data from current network.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.macAddressBlacklistLabel.setText(QCoreApplication.translate("NetSpect", u"MAC Address Blacklist:", None))
#if QT_CONFIG(tooltip)
        self.macAddressListWidget.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Double click an item to delete it from the list.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.macAddressLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Enter a MAC address (e.g., f7:58:15:f3:ce:22).</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.macAddressLineEdit.setText("")
        self.macAddressLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Enter MAC Address", None))
#if QT_CONFIG(tooltip)
        self.addMacAddressPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Add a MAC address to the blacklist.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.addMacAddressPushButton.setText(QCoreApplication.translate("NetSpect", u"Add", None))
        self.macAddressBlacklistErrorMessageLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Please enter a valid MAC address.</p></body></html>", None))
#if QT_CONFIG(tooltip)
        self.clearHistoryPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Permanently clear your alert history.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.clearHistoryPushButton.setText(QCoreApplication.translate("NetSpect", u"Clear History", None))
#if QT_CONFIG(tooltip)
        self.deleteAccoutPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Permanently delete your account.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.deleteAccoutPushButton.setText(QCoreApplication.translate("NetSpect", u"Delete Account", None))
        self.loginLabel.setText(QCoreApplication.translate("NetSpect", u"Login", None))
#if QT_CONFIG(tooltip)
        self.loginUsernameLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Enter your account username. If you don't have an account you can create one below.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.loginUsernameLineEdit.setText("")
        self.loginUsernameLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Username", None))
#if QT_CONFIG(tooltip)
        self.loginPasswordLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Enter your password, if you forgot it you can reset it below.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.loginPasswordLineEdit.setText("")
        self.loginPasswordLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Password", None))
        self.loginErrorMessageLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Please enter your username and password.</p></body></html>", None))
#if QT_CONFIG(tooltip)
        self.loginPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Log into your account.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.loginPushButton.setText(QCoreApplication.translate("NetSpect", u"Login", None))
#if QT_CONFIG(tooltip)
        self.moveToRegisterLabel.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Register a new account.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.moveToRegisterLabel.setText(QCoreApplication.translate("NetSpect", u"Don't have an account?", None))
#if QT_CONFIG(tooltip)
        self.moveToForgotPasswordLabel.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Reset your account password with account email address.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.moveToForgotPasswordLabel.setText(QCoreApplication.translate("NetSpect", u"Forgot password?", None))
        self.registerLabel.setText(QCoreApplication.translate("NetSpect", u"Register", None))
#if QT_CONFIG(tooltip)
        self.registerEmailLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Enter a valid email address (e.g., name@example.com).</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.registerEmailLineEdit.setText("")
        self.registerEmailLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Email", None))
#if QT_CONFIG(tooltip)
        self.registerUsernameLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Choose a username between 4 and 16 characters.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.registerUsernameLineEdit.setText("")
        self.registerUsernameLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Username", None))
#if QT_CONFIG(tooltip)
        self.registerPasswordLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Choose a password with at least 6 characters and include at least one uppercase letter and one digit.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.registerPasswordLineEdit.setText("")
        self.registerPasswordLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Password", None))
#if QT_CONFIG(tooltip)
        self.registerConfirmPasswordLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Confirm your password by entering it again.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.registerConfirmPasswordLineEdit.setText("")
        self.registerConfirmPasswordLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Confirm Password", None))
        self.registerErrorMessageLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Please fill in all the fields.</p></body></html>", None))
#if QT_CONFIG(tooltip)
        self.registerPushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Register a new account.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.registerPushButton.setText(QCoreApplication.translate("NetSpect", u"Register", None))
#if QT_CONFIG(tooltip)
        self.moveToLoginLabel.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Log into your account.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.moveToLoginLabel.setText(QCoreApplication.translate("NetSpect", u"Already have an account?", None))
        self.resetPasswordLabel.setText(QCoreApplication.translate("NetSpect", u"Reset Password", None))
#if QT_CONFIG(tooltip)
        self.resetPasswordEmailLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Enter the email address that is associated with your account for verification.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.resetPasswordEmailLineEdit.setText("")
        self.resetPasswordEmailLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Email", None))
        self.resetPasswordEmailErrorMessageLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Please fill in the email field for receiving a reset code.</p></body></html>", None))
#if QT_CONFIG(tooltip)
        self.sendCodePushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Send a reset code to account email address for reset password.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.sendCodePushButton.setText(QCoreApplication.translate("NetSpect", u"Send Code", None))
#if QT_CONFIG(tooltip)
        self.resetPasswordCodeLineEdit.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Enter the verification code that we have sent to your provided email address. It might be in the 'Spam' folder.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.resetPasswordCodeLineEdit.setText("")
        self.resetPasswordCodeLineEdit.setPlaceholderText(QCoreApplication.translate("NetSpect", u"Received Code", None))
        self.resetPasswordCodeErrorMessageLabel.setText(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Please fill in the reset code field for verifying your identity.</p></body></html>", None))
#if QT_CONFIG(tooltip)
        self.verifyCodePushButton.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Verify reset code and reset account password.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.verifyCodePushButton.setText(QCoreApplication.translate("NetSpect", u"Verify Code", None))
#if QT_CONFIG(tooltip)
        self.cancelResetPasswordProcessLabel.setToolTip(QCoreApplication.translate("NetSpect", u"<html><head/><body><p>Cancel reset password.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.cancelResetPasswordProcessLabel.setText(QCoreApplication.translate("NetSpect", u"Cancel reset password process", None))
    # retranslateUi

