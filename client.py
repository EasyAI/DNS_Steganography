#! /usr/bin/env python3

import sys
import socket
import base64
from TrafficFactory import DNS


def start_string(recv_data):
    '''
    Scrape the length of the packet to the end of the DNS header.
    '''
    maxEnd = 12

    while True:
        cByte = recv_data[maxEnd]

        if cByte != 0: 
            maxEnd += int(cByte)+1
        else:
            maxEnd += 5
            break

    return(maxEnd)


if __name__ == "__main__":
    '''
    Argument 1 = script
    Argument 2 = destination IP.
    Argument 3 = string to be sent. (no greater than 50 characters)
    '''
    dnsFrame = DNS.DNS_Factory()

    if len(sys.argv) == 3:

        ## Create and connect to the socket.
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.connect((sys.argv[1], 53))

        ## Format the message using base 85.
        message = base64.b85encode(sys.argv[2].encode('utf-8'))

        ## Send the message over the socket.
        client.send(dnsFrame.build_reply_header(dnsFrame.DNS_query_example, message))

        ## Wait for data to be recived.
        recv_data = client.recv(512)

        ## Print out the recived data.
        rawString, _ = dnsFrame.dissect_query_data(recv_data[start_string(recv_data):])

        print('message: {0}'.format(
            base64.b85decode(rawString[0]).decode()))

    else:
        print('Missing argument, use: [SCRIPT] [BIND_IP_ADDRESS] [MESSAGE]')
        
