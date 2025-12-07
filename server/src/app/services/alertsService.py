from app.database.database import asyncpg
from datetime import datetime


# function for getting all alerts that registered for given user from alerts table in ascending order
async def GetAlerts(connection: asyncpg.Connection, userId: int) -> list:
    # get all alerts for user in alerts table
    query = '''
        SELECT interface, attacktype, sourceip, sourcemac,
               destinationip, destinationmac, protocol, ostype, timestamp 
        FROM alerts 
        WHERE userid = $1 AND isdeleted = 0 
        ORDER BY timestamp ASC
        '''
    alertsResult = await connection.fetch(query, userId)
    alertsList = [] #represents our alerts list

    # check if we received alerts from query
    if alertsResult:
        # iterate over each alert and add it as a dictionary to list
        for alert in alertsResult:
            alert = {
                'interface': alert['interface'],
                'attackType': alert['attacktype'],
                'srcIp': alert['sourceip'],
                'srcMac': alert['sourcemac'],
                'dstIp': alert['destinationip'],
                'dstMac': alert['destinationmac'],
                'protocol': alert['protocol'],
                'osType': alert['ostype'],
                'timestamp': alert['timestamp'].strftime('%H:%M:%S %d/%m/%y') 
                    if isinstance(alert['timestamp'], datetime) else alert['timestamp']
            }
            alertsList.append(alert)

    # return list of alerts for user
    return alertsList


# function for getting number of attacks from each type in alerts table for pie chart
async def GetPieChartData(connection: asyncpg.Connection, userId: int) -> dict:
    # delete pie chart data for user in alerts table
    query = '''
        SELECT attacktype, COUNT(*) AS attackcount 
        FROM alerts 
        WHERE userid = $1 AND isdeleted = 0 
        GROUP BY attacktype
        '''
    pieChartResult = await connection.fetch(query, userId)
    pieChartData = {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0} #represents dict of attacks count

    # check if we received pie chart data from query
    if pieChartResult:
        # iterate over each alert and update our pieChartData dictionary
        for alert in pieChartResult:
            # initialize parameters based on alert values
            attackType, attackCount = alert['attacktype'], alert['attackcount']

            # check if attack type is present in our pieChartData dictionary
            if attackType in pieChartData:
                # set corrent attack type with its attack counter from database
                pieChartData[attackType] = attackCount
    
    return pieChartData


# function for getting number of attacks in each year and also in each month of each year in alerts table for analytics charts
async def GetAnalyticsChartData(connection: asyncpg.Connection, userId: int) -> dict:
    # we get the yearly attack types that occured (month index 0) and also the monthly attack types that occured (month index 1-12)
    query = '''
        SELECT EXTRACT(YEAR FROM attacktable.timestamp)::INT AS year, 0 AS month, attacktable.attacktype, COUNT(*) AS attackcount 
        FROM (
            SELECT timestamp, attacktype 
            FROM alerts 
            WHERE userid = $1 AND isdeleted = 0 
        ) AS attacktable 
        GROUP BY EXTRACT(YEAR FROM attacktable.timestamp), attacktable.attacktype 

        UNION ALL 

        SELECT EXTRACT(YEAR FROM attacktable.timestamp)::INT AS year, EXTRACT(MONTH FROM attacktable.timestamp)::INT AS month, attacktable.attacktype, COUNT(*) AS attackcount 
        FROM (
            SELECT timestamp, attacktype 
            FROM alerts 
            WHERE userid = $1 AND isdeleted = 0 
        ) AS attacktable 
        GROUP BY EXTRACT(YEAR FROM attacktable.timestamp), EXTRACT(MONTH FROM attacktable.timestamp), attacktable.attacktype 

        ORDER BY year, month, attacktype ASC
        '''
    analyticsChartResult = await connection.fetch(query, userId)

    # histogramChartData represents dictionary of years, each year has dictionary of months, where each month has dictionary of attack types with their attack counter
    # barChartData represents dictionary of years, each year has dictionary of attack types with their attack counter related to this year
    analyticsChartData = {'histogramChartData': {}, 'barChartData': {}}

    # check if we received analytics chart data from query
    if analyticsChartResult:
        # iterate over each alert and update our analyticsChartData dictionary
        for alert in analyticsChartResult:
            # initialize parameters based on row values
            year, month, attackType, attackCount = str(alert['year']), alert['month'], alert['attacktype'], alert['attackcount']

            # initialize histogramChartData for the year if not present in our dict
            if year not in analyticsChartData.get('histogramChartData'):
                analyticsChartData['histogramChartData'][year] = {f'{attackMonth:02d}': {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0} for attackMonth in range(1, 13)}

            # initialize barChartData for the year if not present in our dict
            if year not in analyticsChartData.get('barChartData'):
                analyticsChartData['barChartData'][year] = {'ARP Spoofing': 0, 'Port Scan': 0, 'DoS': 0, 'DNS Tunneling': 0}

            # check if month is not zero, if so it means its monthly attack type data
            if month != 0:
                # check if attack type is present in our histogramChartData dictionary
                if attackType in analyticsChartData.get('histogramChartData').get(year).get(f'{month:02d}'):
                    analyticsChartData['histogramChartData'][year][f'{month:02d}'][attackType] = attackCount

            # else it means its yearly attack type data
            else:
                # check if attack type is present in our barChartData dictionary
                if attackType in analyticsChartData.get('barChartData').get(year):
                    analyticsChartData['barChartData'][year][attackType] = attackCount

    return analyticsChartData


# function for adding alert for user in alerts table
async def AddAlert(connection: asyncpg.Connection, userId: int, interface: str, attackType: str, sourceIp: str, sourceMac: str,
                    destinationIp: str, destinationMac: str, protocol: str, osType: str, timestamp: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # add alert for user in alerts table
        query = '''
            INSERT INTO alerts (userid, interface, attacktype, sourceip, sourcemac,
                                destinationip, destinationmac, protocol, ostype, timestamp) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            '''
        queryResult = await connection.execute(query, userId, interface, attackType, sourceIp, sourceMac, 
                                    destinationIp, destinationMac, protocol, osType, datetime.strptime(timestamp, '%H:%M:%S %d/%m/%y'))
        rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'Added alert successfully.', 'state': True})
        else:
            resultDict.update({'message': 'Failed adding alert.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error adding alert: {e}.', 'error': True})
    finally:
        return resultDict


# function for deleting all alerts for user in alerts table
async def DeleteAlerts(connection: asyncpg.Connection, userId: int) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # delete all alerts for user in alerts table
        query = '''
            UPDATE alerts 
            SET isdeleted = 1 
            WHERE userid = $1 AND isdeleted = 0
            '''
        queryResult = await connection.execute(query, userId)
        rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'All alerts deleted successfully.', 'state': True})
        else:
            resultDict.update({'message': 'No alerts were found to delete.', 'state': True})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error deleting alerts: {e}.', 'error': True})
    finally:
        return resultDict