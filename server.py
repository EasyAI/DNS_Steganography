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
    Argument 2 = destination IP
    '''
    dnsFrame = DNS.DNS_Factory()

    if len(sys.argv) == 2:
        bind_ip = sys.argv[1]
        bind_port = 53

        ## Create and Bind the required data for the listener socket.
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((bind_ip, bind_port))

        print('Listening on {0}:{1}'.format(bind_ip, bind_port))

        while True:
            ## Wait for data to be recived and print it out to the terminal.
            recv_data, address = server.recvfrom(512)
            print('Accepted connection from {0}:{1}'.format(address[0], address[1]))
            rawString, _ = dnsFrame.dissect_query_data(recv_data[start_string(recv_data):])
            
            print('message: {0}'.format(
                base64.b85decode(rawString[0]).decode()))

            ## Format a reply once a message has been recived.
            replyStr = 'Welcome {0}, message recived!'.format(address[0])
            message = base64.b85encode(replyStr.encode('utf-8'))

            ## Mask the reply message in DNS and send it.
            server.sendto(dnsFrame.build_reply_header(dnsFrame.DNS_query_example, message), address)

    else:
        print('Missing argument, use: [SCRIPT] [BIND_IP_ADDRESS]')


    