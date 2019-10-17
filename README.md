# DNS_Steganography

## Description
This is a script that uses DNS to hide a and send a message between a basic client and server. The message you wish to send from the client to the server is encoded using base85 within the DNS response message during transit.

### Repository Contains:
- server.py : Basic server setup in python to handle UDP messages on port 53.
- client.py : Basic client setup to send UDP messages to a server over port 53.
- TrafficFactory
  - DNS.py : Holds the current frame that is used to build and disassemble the DNS message.


## Usage
Client:
  Run the client on the commandline and use the servers IP address as an extra argument followed by the message you wish to send. e.g. ./server.py 127.0.0.1 'Hello Server!'
 
Sever:
  Run the server on the commandline and use the binding IP address as an extra argument. e.g. ./server.py 127.0.0.1

### Contact
EMAIL: jlennie1996@gmail.com
