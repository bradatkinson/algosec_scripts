#!/usr/bin/env python3
#
#  AUTHOR: Brad Atkinson
#    DATE: 6/8/2017
# PURPOSE: Retrieve device list

from SOAPpy import SOAPProxy
import prettytable
import config


def connect_afa(server):
    """Connect To AlgoSec FA

    Args:
        server (SOAPProxy): A SOAPProxy connection

    Returns:
        response (str): A string containing the session ID
    """
    username = config.algosec['username']
    password = config.algosec['password']
    response = server.ConnectRequest(UserName=username, Password=password)
    return response


def send_query_request(query_params, server):
    """Send Query Request

    Args:
        query_params (dict): A dictionary containing the session ID
        server (SOAPProxy): A SOAPProxy connection

    Returns:
        response (xml): XML containing the devices
    """
    session_id = query_params['SessionID']
    response = server.GetDevicesListRequest(SessionID=session_id)
    return response

def disconnect_afa(disconnect_params, server):
    """Disconnect From AlgoSec FA

    Args:
        disconnect_params (dict): A dictionary containing the session ID
        server (SOAPProxy): A SOAPProxy connection

    Returns:
        response (str): A string containing the exit code
    """
    session_id = disconnect_params['SessionID']
    response = server.DisconnectRequest(SessionID=session_id)
    return response


def process_results(query_result):
    """Process Results

    Args:
        query_result (xml): XML containing the devices
    """
    table = prettytable.PrettyTable(['Name', 'ID', 'Brand', 'IP', 'Policy'])
    table.align = 'l'
    for device in query_result:
        try:
            brand = device[0]
            name = device[1]
            device_id = device[2]
            ip_addr = device[3]
            policy = device[4]
            table.add_row([name, device_id, brand, ip_addr, policy])
        except:
            pass
    table.sortby = 'Brand'
    print(table)


def main():
    """Function Calls
    """
    proxy = 'https://{0}/AFA/php/ws.php?wsdl'.format(config.algosec['algosec_ip'])
    namespace = 'https://www.algosec.com/afa-ws'
    server = SOAPProxy(proxy, namespace)

    session_id = connect_afa(server)

    request_params = {'SessionID': session_id}
    query_result = send_query_request(request_params, server)
    process_results(query_result)

    disconnect_params = {'SessionID': session_id}
    disconnect_result = disconnect_afa(disconnect_params, server)
    if disconnect_result == '1':
        print('\nDisconnected Successfully\n')


if __name__ == '__main__':
    main()
