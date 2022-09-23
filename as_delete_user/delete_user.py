#!/usr/bin/env python3
#
#  AUTHOR: Brad Atkinson
#    DATE: 6/8/2017
# PURPOSE: Delete user from AlgoSec FA

from SOAPpy import SOAPProxy
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


def send_query_request(query_params, server, userid):
    """Send Query Request

    Args:
        query_params (dict): A dictionary containing the session ID
        server (SOAPProxy): A SOAPProxy connection
        userid (str): A string containing the users user ID

    Returns:
        response (xml): XML containing the devices
    """
    session_id = query_params['SessionID']
    try:
        server.DeleteUserRequest(SessionID=session_id, UserName=userid)
    except Exception as error:
        print('Error deleting user: {}'.format(error))


def disconnect_afa(disconnect_params, server):
    """Disconnect From AlgoSec FA

    Args:
        disconnect_params (dict): A dictionary containing the session ID
        server (SOAPProxy): A SOAPProxy connection

    Returns:
        response (str): A string containing the exit code
    """
    session_id = disconnect_params['SessionID']
    server.DisconnectRequest(SessionID=session_id)


def main():
    """Function Calls
    """
    proxy = 'https://{}/AFA/php/ws.php?wsdl'.format(config.algosec['algosec_ip'])
    namespace = 'https://www.algosec.com/afa-ws'
    server = SOAPProxy(proxy, namespace)

    session_id = connect_afa(server)

    userid = config.user_id
    query_params = {'SessionID': session_id}
    send_query_request(query_params, server, userid)

    disconnect_params = {'SessionID': session_id}
    disconnect_afa(disconnect_params, server)


if __name__ == '__main__':
    main()
