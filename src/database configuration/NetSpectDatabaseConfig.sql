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
	PRIMARY KEY(userId)
);


-- Create Alerts table
CREATE TABLE Alerts (
	alertId INT IDENTITY(1,1) UNIQUE NOT NULL,
    userId INT UNIQUE NOT NULL,
	networkInterface VARCHAR(255) NOT NULL,
	detectedAttack VARCHAR(255) NOT NULL,
	protocol VARCHAR(255) NOT NULL,
    sourceIp VARCHAR(255) NOT NULL,
	destinationIp VARCHAR(255) NOT NULL,
	osType VARCHAR(255) NOT NULL,
	timestamp VARCHAR(255) NOT NULL, -- timestamp template is hh:mm:ss dd/mm/yy
	isDeleted INT NOT NULL DEFAULT 0, --represents state of alert, if 1 its deleted, else not
	CHECK (timestamp LIKE '[0-2][0-9]:[0-5][0-9]:[0-5][0-9] [0-3][0-9]/[0-1][0-9]/[0-9][0-9]'),
    PRIMARY KEY(alertId),
    FOREIGN KEY (userId) REFERENCES Users(userId)
);


-- Insert two default users into our database
INSERT INTO Users (email, userName, password, numberOfDetectedAttacks, lightMode, isDeleted)  
VALUES  
('shayhha@gmail.com', 'Shay', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'),
('maximsu@ac.sce.ac.il', 'Max', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3');
