#!/usr/bin/env python3
#
#  AUTHOR: Brad Atkinson
#    DATE: 12/5/2017
# PURPOSE: Retrieve firewall rules

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


def send_query_request(query_params, server, device_id):
    """Send Query Request

    Args:
        query_params (dict): A dictionary containing the session ID
        server (SOAPProxy): A SOAPProxy connection
        device_id (str): A string containing the device ID

    Returns:
        response (xml): XML containing the rules
    """
    session_id = query_params['SessionID']
    response = server.GetRulesByDeviceRequest(SessionID=session_id, DeviceID=device_id)
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
        query_result (xml): XML containing the rules
    """
    table = prettytable.PrettyTable(['Rule #', 'Rule ID', 'Name'])
    table.align = 'l'
    for rules in query_result:
        for rule in rules:
            rule_id = rule[1]
            rule_num = rule[2]
            name = rule[4]
            table.add_row([rule_num, rule_id, name])
    print(table)


def main():
    """Function Calls
    """
    proxy = 'https://{0}/AFA/php/ws.php?wsdl'.format(config.algosec['algosec_ip'])
    namespace = 'https://www.algosec.com/afa-ws'
    server = SOAPProxy(proxy, namespace)

    session_id = connect_afa(server)

    device_id = config.device_id
    query_params = {'SessionID': session_id}
    query_result = send_query_request(query_params, server, device_id)
    process_results(query_result)

    disconnect_params = {'SessionID': session_id}
    disconnect_result = disconnect_afa(disconnect_params, server)
    if disconnect_result == '1':
        print('\nDisconnected Successfully\n')


if __name__ == '__main__':
    main()
