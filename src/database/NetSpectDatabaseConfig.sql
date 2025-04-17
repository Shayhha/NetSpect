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
	userId INT IDENTITY(1,1) UNIQUE NOT NULL,
	email VARCHAR(255) UNIQUE NOT NULL,
	userName VARCHAR(255) UNIQUE NOT NULL,
	password VARCHAR(255) NOT NULL,
	lightMode INT NOT NULL DEFAULT 0, --represents the color mode of app, 1 means lightmode, else darkmode
	isDeleted INT NOT NULL DEFAULT 0, --represents state of account, if 1 its deleted, else not
	CHECK (email LIKE '_%@_%._%'),
	CHECK (LEN(userName) BETWEEN 4 AND 16),
	CHECK (lightMode BETWEEN 0 AND 1),
	CHECK (isDeleted BETWEEN 0 AND 1),
	PRIMARY KEY(userId)
);


-- Create Blacklist table
CREATE TABLE Blacklist (
	userid INT NOT NULL,
	macAddress VARCHAR(255) NOT NULL,
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
	protocol VARCHAR(255) NOT NULL,
	osType VARCHAR(255) NOT NULL,
	timestamp VARCHAR(255) NOT NULL, -- timestamp template is hh:mm:ss dd/mm/yy
	isDeleted INT NOT NULL DEFAULT 0, --represents state of alert, if 1 its deleted, else not
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