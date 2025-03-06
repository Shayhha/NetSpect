-- Drop existing database if it exists
DROP DATABASE IF EXISTS NetSpect;

-- Create the database
CREATE DATABASE NetSpect;

-- Use the new database
USE NetSpect;

-- Drop existing tables if they exist
IF OBJECT_ID('Users', 'U') IS NOT NULL DROP TABLE Users;
IF OBJECT_ID('Alerts', 'U') IS NOT NULL DROP TABLE Alerts;

-- Create Users table
CREATE TABLE Users (
    userId INT IDENTITY(1,1) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    userName VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
	numberOfDetectedAttacks INT NOT NULL DEFAULT 0,
	lightMode INT NOT NULL DEFAULT 0, --represents the color mode of app, 1 means lightmode, else darkmode
	isDeleted INT NOT NULL DEFAULT 0, --represents state of account, if 1 its deleted, else not
	CHECK (email LIKE '_%@_%._%'),
	CHECK (LEN(userName) <= 10),
	PRIMARY KEY(userId)
);


-- Create Blacklist table
CREATE TABLE Blacklist (
	userid INT NOT NULL,
    macAddress VARCHAR(255) NOT NULL,
	isDeleted INT NOT NULL DEFAULT 0, --represents state of mac address, if 1 its deleted, else not
	PRIMARY KEY(userId, macAddress),
    FOREIGN KEY (userId) REFERENCES Users(userId)
);


-- Create Alerts table
CREATE TABLE Alerts (
	alertId INT IDENTITY(1,1) UNIQUE NOT NULL,
    userId INT NOT NULL,
	interface VARCHAR(255) NOT NULL,
	attackType VARCHAR(255) NOT NULL,
    sourceIp VARCHAR(255) NOT NULL,
	sourceMac VARCHAR(255) NOT NULL,
	destinationIp VARCHAR(255) NOT NULL,
	destinationMac VARCHAR(255) NOT NULL,
	osType VARCHAR(255) NOT NULL,
	timestamp VARCHAR(255) NOT NULL, -- timestamp template is hh:mm:ss dd/mm/yy
	isDeleted INT NOT NULL DEFAULT 0, --represents state of alert, if 1 its deleted, else not
	CHECK (timestamp LIKE '[0-2][0-9]:[0-5][0-9]:[0-5][0-9] [0-3][0-9]/[0-1][0-9]/[0-9][0-9]'),
    PRIMARY KEY(alertId),
    FOREIGN KEY (userId) REFERENCES Users(userId)
);


-- Insert two default users into our database
INSERT INTO Users (email, userName, password)  
VALUES  
('shayhha@gmail.com', 'Shay', 'a0ae799a2910f035b250e5175a02576f0ed0970c18ece1e65ce706767fa85c72'),
('maximsu@ac.sce.ac.il', 'Max', '6beea10f9cf47563eb475c4c6f0126b7d4230173c9429eb9a291fa1cfb136721');
