
<div align='center'>
  <img src="src/interface/Icons/NetSpectIconTransparent.png" width="175"/>
  <div id="toc">
    <ul align="center" style="list-style: none">
      <summary>
        <h1><b>NetSpect - Real-Time Intrusion Detection System (IDS)</b></h1>
      </summary>
    </ul>
  </div>

[![Python](https://img.shields.io/badge/Python-3.12-3572A5?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/release/python-3120/) 
[![Scapy](https://img.shields.io/badge/Scapy-2.6.1-2C3E50?style=for-the-badge&logo=github&logoColor=white)](https://github.com/secdev/scapy)
[![PyQt5](https://img.shields.io/badge/PyQt5-5.15.11-2C3E50?style=for-the-badge&logo=github&logoColor=white)](https://www.riverbankcomputing.com/software/pyqt/)
[![SQL Server](https://img.shields.io/badge/SQL%20Server-2022-blue?style=for-the-badge&logo=microsoft-sql-server&logoColor=white)](https://www.microsoft.com/en-us/sql-server/sql-server-2022)
[![Npcap](https://img.shields.io/badge/Npcap-1.79-59118e?style=for-the-badge&logo=Caffeine&logoColor=white)](https://npcap.com/)
![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux-2C3E50?style=for-the-badge&logo=apple&logoColor=white)
[![MIT License](https://img.shields.io/badge/License-MIT-28A745?style=for-the-badge&logo=mit&logoColor=white)](https://opensource.org/licenses/MIT)
</div>

<h1></h1>

**Final Project for B.Sc. in Software Engineering**

**NetSpect** is an advanced, real-time, cross-platform *[Hybrid Intrusion Detection System (HIDS)](https://www.stamus-networks.com/blog/what-are-the-three-types-of-ids#:~:text=Hybrid%20IDS%3A%20A%20hybrid%20intrusion,based%20detection%20for%20novel%20attacks.)* built with Python 3.12, it uses custom algorithms and machine learning models to identify and alert on multiple types of network cyberattacks, detecting intrusions such as:

- [ARP Spoofing](https://www.crowdstrike.com/en-us/cybersecurity-101/social-engineering/arp-spoofing/)
- [Port Scanning](https://www.paloaltonetworks.com/cyberpedia/what-is-a-port-scan)
- [DoS TCP SYN Floods](https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/) & [HTTP GET Floods](https://www.cloudflare.com/learning/ddos/http-flood-ddos-attack/)
- [DNS Tunneling](https://www.checkpoint.com/cyber-hub/network-security/what-is-dns-tunneling/)  

<br>  

## Overview
**NetSpect is a Hybrid IDS** developed as the culmination of our four-year Software Engineering degree. Engineered for **accuracy**, **efficiency**, and **ease of use** it features an intuitive graphical user interface (GUI) paired with a robust backend to deliver a **comprehensive solution for real-time threat detection** in local networks. By integrating **custom-designed algorithms** with **machine learning**, NetSpect combines signature-based and anomaly-based detection methods to monitor and analyze network traffic, ensuring **precise**, **rapid**, and **reliable detection** of malicious activities.

Our software includes a specialized algorithm for ARP Spoofing detection, capable of **identifying both IP-MAC and MAC-IP spoofing across individual subnets in real time**. This algorithm systematically analyzes incoming ARP traffic, organizes it by subnet, and verifies the absence of duplications indicative of spoofing attempts. Enhanced by a **cache-based mechanism**, it optimizes data processing to achieve efficient and accurate detection, providing robust protection against network spoofing threats with minimal performance impact.

In addition to that, the machine learning models that we built were trained on **datasets we manually collected** from various Ethernet and Wi-Fi networks. These datasets include benign network traffic as well as **attack traffic synthesized from real-world scenarios** we created in controlled environments, covering threats such as Port Scanning, DoS TCP SYN Floods, DoS HTTP GET Floods, and DNS Tunneling. This hands-on approach to data collection ensures our models are finely tuned to recognize both typical network behavior and sophisticated attack patterns effectively.

NetSpect cleverly employs a **multi-threaded architecture** to distribute tasks across multiple worker threads, delivering **strong performance** and **real-time detection** capabilities. This design enables the application to maintain high responsiveness and process network traffic efficiently, even under significant load. By leveraging multi-threading, NetSpect provides a scalable and dependable solution for monitoring and securing local networks in dynamic environments.

<br>  

## Features
### Core Features

-  **Real-Time Detection**  
  Detects ARP Spoofing, Port Scans, DoS Attacks and DNS Tunnels in real time with high accuracy.

-  **ARP Spoofing Detection**  
  Implements a custom logic-based algorithm to detect ARP spoofing attempts in your network.

-  **Machine Learning-Based Classification**  
  Uses pre-trained **SVM models** to classify network flows and detect attack signatures in real time.

-  **Data Collection**  
  Provides the ability to switch between Detection and Data Collection modes. In Data Collection mode, network packets are aggregated and stored in a **CSV** file for further analysis.

- **MAC Address Blacklist**  
  Allows users to add MAC addresses to a blacklist. Any attacks originating from these addresses will be ignored during detection.
  
### Interface Features

-  **Alert Center**  
  View real-time and historical alerts directly in the app.

- **Incident Reports**  
  Enables users to filter and export historical alerts into TXT or CSV report formats for future analysis.

-  **Modern GUI with Dark/Light Mode**  
  Clean and responsive user interface built with user experience in mind.

### User & System Features

-  **User Authentication**  
  Supports **login** and **registration**; Includes a guest mode with limited functionality.

- **Account Management**  
  Offers users the ability to changing their password, username, and email address. Also includes a password recovery feature in case of forgotten credentials.

- **System Information**  
  Displays detailed information about the user’s network interface, system details and the current program version.

### Performance & Compatibility Features

-  **Multithreaded Architecture**  
  Efficient and responsive performance with concurrent data capture and processing.

-  **System Tray Integration**  
  Runs in the background and shows native tray notifications upon attack detection.

-  **Cross-Platform**  
  Compatible with Windows, Linux, and macOS thanks to Python 3.12 and PyQt.

<br>  

## Technologies Used

| Technology | Purpose |
|------------|---------|
| **[Python 3.12](https://www.python.org/downloads/release/python-3120/)** | Core programming language for development and scripting. |
| **[Scapy](https://github.com/secdev/scapy)** | A powerful packet manipulation library used for network traffic analysis. |
| **[PyQt5](https://www.riverbankcomputing.com/software/pyqt/)** | A framework for building the graphical user interface (GUI). |
| **[SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-2022)** | Database management system for storing and retrieving user data. |
| **[Joblib](https://joblib.readthedocs.io/)** | Library utilized for saving and loading machine learning models efficiently. |
| **[Scikit-learn](https://scikit-learn.org/)** | Machine learning library leveraged for model training and prediction. |

<br>  

## Installation & Setup

### Clone The Repository:

```shell
git clone https://github.com/Shayhha/NetSpect.git
cd NetSpect
```

### Install Requirements:

```shell
pip install -r requirements.txt
```

### Install ODBC Driver:

In order to use the application and have access to the user's database, you must install **[Microsoft ODBC Driver for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver15)**

### Additional Installations (Only On Windows):

Make sure to install **[Npcap](https://nmap.org/npcap/)** before running the application. It's required for network packet capturing.


<br>  

## How To Run The Application:

- **On Windows**
  ```shell
  cd src/main
  python NetSpect.py
  ```
  
- **On macOS / Linux**  
  You must run the application with elevated privileges to allow network monitoring:
  > This is necessary because raw packet capturing requires administrative/root permissions on Unix-based systems.
  
  ```shell
  cd src/main
  sudo python NetSpect.py
  ```

<br>  

## Screenshots

The following screenshots showcase the application's interface, functionality, and user experience across various scenarios

### Dark Mode:
![Home Page](src/interface/screenshots/home_page.png)

![Report Page](src/interface/screenshots/report_page.png)

![Login](src/interface/screenshots/login.png)

### Light Mode:
![Settings Page](src/interface/screenshots/settings_page.png)

![Reset Password](src/interface/screenshots/reset_password.png)

<br>  

## Requirements

Our application relies of the following requirements in order to work properly:
> You can install them via the requirements.txt file as mentioned in [Installation & Setup](#installation--setup)

- scapy
- PyQt5
- pandas
- numpy
- joblib
- dotenv
- pyodbc


**Important** 
- On Windows based systems **[Npcap](https://npcap.com/#download)** must be installed to enable packet analysis and capturing.
- On Linux and macOS you have to run the application with administrative privileges to enable packet analysis and capturing.
- In order to have access to the user's database you must install **[Microsoft ODBC Driver for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver15)**


<br>  

## Contact

- **Shay Hahiashvili**
  - Email: [shayhha@gmail.com](mailto:shayhha@gmail.com)
  - GitHub: [https://github.com/Shayhha](https://github.com/Shayhha)
  - 
- **Maxim Subotin**
  - Email: [maxim.sub21@gmail.com](mailto:maxim.sub21@gmail.com)
  - GitHub: [https://github.com/MaxSubotin](https://github.com/MaxSubotin)

<br>  

## License

NetSpect is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.

© All rights reserved to Shay Hahiashvili and Maxim Subotin.
