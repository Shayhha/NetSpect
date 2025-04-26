-- Drop existing database if it exists
DROP DATABASE IF EXISTS NetSpect;

-- Create the database
CREATE DATABASE NetSpect;

-- Use the new database
USE NetSpect;

-- Drop existing tables if they exist
IF OBJECT_ID('Users', 'U') IS NOT NULL DROP TABLE Users;
IF OBJECT_ID('Blacklist', 'U') IS NOT NULL DROP TABLE Blacklist;
IF OBJECT_ID('Alerts', 'U') IS NOT NULL DROP TABLE Alerts;

-- Create Users table
CREATE TABLE Users (
	userId INT IDENTITY(1,1) UNIQUE NOT NULL, --represents userId of user
	email VARCHAR(255) UNIQUE NOT NULL, --represents email of user
	userName VARCHAR(255) UNIQUE NOT NULL, --represents userName of user
	password VARCHAR(255) NOT NULL, --represents password of user stored in SHA-256
	lightMode INT NOT NULL DEFAULT 0, --represents the color mode of app, 1 means lightmode, else darkmode
	operationMode INT NOT NULL DEFAULT 0, --represents the operation mode of application, 0 means detection, 1 means TCP/UDP collection, 2 means DNS collection
	isDeleted INT NOT NULL DEFAULT 0, --represents state of account, if 1 its deleted, else not
	CHECK (email LIKE '_%@_%._%'),
	CHECK (LEN(userName) BETWEEN 4 AND 16),
	CHECK (lightMode BETWEEN 0 AND 1),
	CHECK (operationMode BETWEEN 0 AND 2),
	CHECK (isDeleted BETWEEN 0 AND 1),
	PRIMARY KEY(userId)
);


-- Create Blacklist table
CREATE TABLE Blacklist (
	userid INT NOT NULL, --represents userId for MAC address
	macAddress VARCHAR(255) NOT NULL, --represents MAC address, lowercase letters
	CHECK (macAddress LIKE '%:%:%:%:%:%' AND macAddress NOT LIKE '%[^0-9a-f:]%' AND LEN(macAddress) = 17),
	PRIMARY KEY(userId, macAddress),
	FOREIGN KEY (userId) REFERENCES Users(userId)
);


-- Create Alerts table
CREATE TABLE Alerts (
	alertId INT IDENTITY(1,1) UNIQUE NOT NULL, --represents alertId for alert
	userId INT NOT NULL, --represents userId for alert
	interface VARCHAR(255) NOT NULL, --represents network interface
	attackType VARCHAR(255) NOT NULL, --represents attack type, like ARP Spoofing, Port Scan, DoS, DNS Tunneling
	sourceIp VARCHAR(255) NOT NULL, --represents source IP, IPv4 or IPv6 with lowercase letters
	sourceMac VARCHAR(255) NOT NULL, --represents source MAC, lowercase letters
	destinationIp VARCHAR(255) NOT NULL, --represents destination IP, IPv4 or IPv6 with lowercase letters
	destinationMac VARCHAR(255) NOT NULL, --represents destination MAC, lowercase letters
	protocol VARCHAR(255) NOT NULL, --represents protocol of attack, can be TCP, UDP, DNS, ARP
	osType VARCHAR(255) NOT NULL, --represents os type
	timestamp VARCHAR(255) NOT NULL, --timestamp template is hh:mm:ss dd/mm/yy
	isDeleted INT NOT NULL DEFAULT 0, --represents state of alert, if 1 its deleted, else not
	CHECK (attackType IN ('ARP Spoofing', 'Port Scan', 'DoS', 'DNS Tunneling')),
	CHECK ((sourceIp LIKE '%.%.%.%' AND sourceIp NOT LIKE '%[^0-9.]%' AND LEN(sourceIp) BETWEEN 7 AND 15) OR (sourceIp LIKE '%:%' AND sourceIp NOT LIKE '%[^0-9a-f:]%' AND LEN(sourceIp) BETWEEN 2 AND 39)),
	CHECK ((destinationIp LIKE '%.%.%.%' AND destinationIp NOT LIKE '%[^0-9.]%' AND LEN(destinationIp) BETWEEN 7 AND 15) OR (destinationIp LIKE '%:%' AND destinationIp NOT LIKE '%[^0-9a-f:]%' AND LEN(destinationIp) BETWEEN 2 AND 39)),
	CHECK (sourceMac LIKE '%:%:%:%:%:%' AND sourceMac NOT LIKE '%[^0-9a-f:]%' AND LEN(sourceMac) = 17),
	CHECK (destinationMac LIKE '%:%:%:%:%:%' AND destinationMac NOT LIKE '%[^0-9a-f:]%' AND LEN(destinationMac) = 17),
	CHECK (protocol IN ('TCP', 'UDP', 'DNS', 'ARP')),
	CHECK (timestamp LIKE '[0-2][0-9]:[0-5][0-9]:[0-5][0-9] [0-3][0-9]/[0-1][0-9]/[0-9][0-9]'),
	CHECK (isDeleted BETWEEN 0 AND 1),
	PRIMARY KEY(alertId),
	FOREIGN KEY (userId) REFERENCES Users(userId)
);


-- Insert two default users into our database
INSERT INTO Users (email, userName, password)  
VALUES  
('shayhha@gmail.com', 'Shay', 'a0ae799a2910f035b250e5175a02576f0ed0970c18ece1e65ce706767fa85c72'),
('maximsu@ac.sce.ac.il', 'Maxim', '43011903cd7b0638011ffe1eb34d82dd45b74cb2a56a5502aa117cbb35a67d67');