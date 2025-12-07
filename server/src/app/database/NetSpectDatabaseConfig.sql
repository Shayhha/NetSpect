-- Enable pgcrypto for UUID
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enable pg_cron for schedule
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Drop existing database if it exists
DROP DATABASE IF EXISTS netspect;

-- Create the database
CREATE DATABASE netspect;

-- Drop existing tables if they exist
DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS blacklist CASCADE;
DROP TABLE IF EXISTS resetcodes CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
	userid SERIAL UNIQUE NOT NULL, --represents userid of user
	email VARCHAR(255) UNIQUE NOT NULL, --represents email of user
	username VARCHAR(255) UNIQUE NOT NULL, --represents username of user
	password VARCHAR(255) NOT NULL, --represents password of user stored in SHA-256
	lightmode INT NOT NULL DEFAULT 0, --represents the color mode of app, 1 means lightmode, else darkmode
	operationmode INT NOT NULL DEFAULT 0, --represents the operation mode of application, 0 means detection, 1 means TCP/UDP collection, 2 means DNS collection
	isdeleted INT NOT NULL DEFAULT 0, --represents state of account, if 1 its deleted, else not
    CONSTRAINT users_email_check CHECK (email ~ '^[A-Za-z0-9](?:[A-Za-z0-9_%+-]*\.?[A-Za-z0-9_%+-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+$'),
    CONSTRAINT users_username_check CHECK (username ~ '^[A-Za-z][A-Za-z0-9]{3,15}$'),
	CONSTRAINT users_lightmode_check CHECK (lightmode BETWEEN 0 AND 1),
	CONSTRAINT users_operationmode_check CHECK (operationmode BETWEEN 0 AND 2),
	CONSTRAINT users_isdeleted_check CHECK (isdeleted BETWEEN 0 AND 1),
	PRIMARY KEY(userid)
);


-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    sessionid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(), --represents sessionid of session
    userid INT UNIQUE NOT NULL, --represents userid of session
    timestamp TIMESTAMP NOT NULL DEFAULT (now() at time zone 'utc'), --represents timestamp, our format is hh:mm:ss dd/mm/yy
	PRIMARY KEY(sessionid),
	FOREIGN KEY (userid) REFERENCES users(userid) ON DELETE CASCADE
);


-- Create resetcodes table
CREATE TABLE IF NOT EXISTS resetcodes (
	email VARCHAR(255) UNIQUE NOT NULL, --represents email of user
	resetcode VARCHAR(255) NOT NULL, --represents reset code for user
	timestamp TIMESTAMP NOT NULL DEFAULT (now() at time zone 'utc'), --represents timestamp, our format is hh:mm:ss dd/mm/yy
	CONSTRAINT resetcodes_email_check CHECK (email ~ '^[A-Za-z0-9](?:[A-Za-z0-9_%+-]*\.?[A-Za-z0-9_%+-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+$'),
	PRIMARY KEY(email),
	FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
);


-- Create blacklist table
CREATE TABLE IF NOT EXISTS blacklist (
	userid INT NOT NULL, --represents userid for MAC address
	macaddress VARCHAR(255) NOT NULL, --represents MAC address, lowercase letters
	CONSTRAINT blacklist_macaddress_check CHECK (macaddress ~ '^[A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2}){5}$'),
	PRIMARY KEY(userid, macaddress),
	FOREIGN KEY (userid) REFERENCES users(userid) ON DELETE CASCADE
);


-- Create alerts table
CREATE TABLE IF NOT EXISTS alerts (
	alertid SERIAL UNIQUE NOT NULL, --represents alertid for alert
	userid INT NOT NULL, --represents userid for alert
	interface VARCHAR(255) NOT NULL, --represents network interface
	attacktype VARCHAR(255) NOT NULL, --represents attack type, like ARP Spoofing, Port Scan, DoS, DNS Tunneling
	sourceip VARCHAR(255) NOT NULL, --represents source IP, IPv4 or IPv6 with lowercase letters
	sourcemac VARCHAR(255) NOT NULL, --represents source MAC, lowercase letters
	destinationip VARCHAR(255) NOT NULL, --represents destination IP, IPv4 or IPv6 with lowercase letters
	destinationmac VARCHAR(255) NOT NULL, --represents destination MAC, lowercase letters
	protocol VARCHAR(255) NOT NULL, --represents protocol of attack, can be TCP, UDP, DNS, ARP
	ostype VARCHAR(255) NOT NULL, --represents os type
	timestamp TIMESTAMP NOT NULL DEFAULT (now() at time zone 'utc'), --represents timestamp, our format is hh:mm:ss dd/mm/yy
	isdeleted INT NOT NULL DEFAULT 0, --represents state of alert, if 1 its deleted, else not
	CONSTRAINT alerts_attacktype_check CHECK (attacktype ~ '^(ARP Spoofing|Port Scan|DoS|DNS Tunneling)$'),
	CONSTRAINT alerts_sourceip_check CHECK (sourceIp ~ '^(([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7}|:))$'),
	CONSTRAINT alerts_destinationip_check CHECK (destinationip ~ '^(([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7}|:))$'),
	CONSTRAINT alerts_sourcemac_check CHECK (sourcemac ~ '^[A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2}){5}$'),
	CONSTRAINT alerts_destinationmac_check CHECK (destinationmac ~ '^[A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2}){5}$'),
	CONSTRAINT alerts_protocol_check CHECK (protocol ~ '^(TCP|UDP|DNS|ARP)$'),
	CONSTRAINT alerts_isdeleted_check CHECK (isdeleted BETWEEN 0 AND 1),
	PRIMARY KEY(alertid),
	FOREIGN KEY (userid) REFERENCES users(userid) ON DELETE CASCADE
);

-- Create alerts table indexes
CREATE INDEX IF NOT EXISTS alerts_userid_timestamp_idx ON alerts USING btree(userid, timestamp) WHERE isdeleted = 0;
CREATE INDEX IF NOT EXISTS alerts_userid_attacktype_idx ON alerts USING btree(userid, attacktype) WHERE isdeleted = 0;
CREATE INDEX IF NOT EXISTS alerts_userid_timestamp_attacktype_idx ON alerts USING btree(userid, timestamp, attacktype) WHERE isdeleted = 0;


-- Create procedure for removing deleted users from database
CREATE OR REPLACE FUNCTION remove_deleted_users()
RETURNS void AS $$
BEGIN
    DELETE FROM alerts
    WHERE userid IN (SELECT userid FROM users WHERE isdeleted = 1);

    DELETE FROM blacklist
    WHERE userid IN (SELECT userid FROM users WHERE isdeleted = 1);

    DELETE FROM resetcodes
    WHERE email IN (SELECT email FROM users WHERE isdeleted = 1);

    DELETE FROM sessions
    WHERE userid IN (SELECT userid FROM users WHERE isdeleted = 1);

    DELETE FROM users
    WHERE isdeleted = 1;
END;
$$ LANGUAGE plpgsql;


-- Schedule remove deleted users every Sunday at 03:00AM
SELECT cron.schedule(
    'remove_deleted_users',
    '0 3 * * 0',
    $$CALL remove_deleted_users();$$
);


-- Insert two default users into our database
INSERT INTO users (email, username, password)  
VALUES  
('shayhha@gmail.com', 'Shay', 'a0ae799a2910f035b250e5175a02576f0ed0970c18ece1e65ce706767fa85c72'),
('maxim.sub21@gmail.com', 'Maxim', '43011903cd7b0638011ffe1eb34d82dd45b74cb2a56a5502aa117cbb35a67d67');