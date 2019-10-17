#! /usr/bin/env python3

import random

'''
Traffic factory is a way that you are able to create and sctructure your own packets/frames.
'''


class DNS_Factory():
    '''
    This is used to create the basic structure for a DNS packet.

    HEADER FEILDS
    +----+----+----+----+----+----+----+----+----+----+----+
    | Transaction ID                                       |
    +----+----+----+----+----+----+----+----+----+----+----+
    | QR | Opcode  | AA | TC | RD | Z  | AD | CD | Rcode   |
    +----+----+----+----+----+----+----+----+----+----+----+
    | Number of Questions                                  |
    +----+----+----+----+----+----+----+----+----+----+----+
    | Number of Answers                                    |
    +----+----+----+----+----+----+----+----+----+----+----+
    | Number of Authority                                  |
    +----+----+----+----+----+----+----+----+----+----+----+
    | Number of Aditional                                  |
    +----+----+----+----+----+----+----+----+----+----+----+
    '''

    def __init__(self):

        ## Example DNS query for testing.
        self.DNS_query_example = b'\x26\x8b\x84\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'


    def build_new_header(self, domainURL, qc=1):
        '''
        Allow to build a brand new header.
        '''
        rHeaderID = random.randint(1, 32767)

        ## getting the Transaction ID.
        transactionID_bytes = int(rHeaderID).to_bytes(2, byteorder='big')

        # Getting the Flags.
        flags_bytes = self._set_flags()

        QC_bytes = int(qc).to_bytes(2, byteorder='big') # Question Count.
        ANC_bytes = int(0).to_bytes(2, byteorder='big') # Answer Count.
        NC_bytes = int(0).to_bytes(2, byteorder='big') # Nameserver Count.
        ADC_bytes = int(0).to_bytes(2, byteorder='big') # Aditional Count.

        ## Fresh header.
        query_header = transactionID_bytes+flags_bytes+QC_bytes+ANC_bytes+NC_bytes+ADC_bytes

        ## Fresh query.
        query = self._build_query(domainURL.split('.'))

        return(query_header+query)


    def build_reply_header(self, data, rShortName=None, flags=None):
        '''
        Create a header to reply to a recent message.
        '''

        ## getting the Transaction ID.
        transactionID_bytes = data[:2]

        # Getting the Flags.
        flags_hex = [ hex(byte) for byte in data[2:4] ]

        replyFlags_bytes = self._set_flags()

        QC_bytes = data[4:6] # Question Count.
        ANC_bytes = data[4:6] # Answer Count.
        NC_bytes = int(0).to_bytes(2, byteorder='big') # Nameserver Count.
        ADC_bytes = int(0).to_bytes(2, byteorder='big') # Aditional Count.

        ## Reply header.
        reply_header = transactionID_bytes+replyFlags_bytes+QC_bytes+ANC_bytes+NC_bytes+ADC_bytes

        ## Reply question query.
        domainInfo = self.dissect_query_data(data[12:])
        reply_question = self._build_query(domainInfo[0])

        ## Reply body.
        reply_body = self._build_reply_body(rShortName=rShortName)

        return(reply_header+reply_question+reply_body)


    def dissect_query_data(self, data):
        '''
        Used to dissect the URL out of the packet.
        '''
        currentString = ''
        dataStrings = []

        strLeng = 0
        dataEnd = 12

        for byte in data:

            if strLeng == 0:
                strLeng = byte
                if currentString != '':
                    dataStrings.append(currentString)
                    currentString = ''

            else:
                currentString += chr(byte)
                strLeng -= 1

            dataEnd += 1
            if byte == 0: break

        return(dataStrings, dataEnd)


    def _build_query(self, domainSegments):
        '''
        Used to build the query with the url in it.
        '''
        qbytes = b''

        for segment in domainSegments:
            length = len(segment)
            qbytes += bytes([length])

            for char in segment:
                qbytes += ord(char).to_bytes(1, byteorder='big')

        ## Add the termination byte.
        qbytes += int(0).to_bytes(1, byteorder='big')

        ## Set default record type (A):
        qbytes += int(1).to_bytes(2, byteorder='big')

        ## Set default class type (IN):
        qbytes += int(1).to_bytes(2, byteorder='big')

        return(qbytes)


    def _build_reply_body(self, rTTL=100, rType=1, rIPadd='0.0.0.0', rShortName=None):
        '''
        Used to build the body for a reply.
        '''
        if rShortName == None:
            rbytes = b'\xc0\x0c'

        else:
            if rShortName != None:
                rbytes = len(rShortName).to_bytes(1, byteorder='big')

                for char in rShortName:
                    rbytes += ord(chr(char)).to_bytes(1, byteorder='big')

                rbytes += b'\x00'

        ## If A record.
        if rType == 1:
            rbytes = rbytes + int(1).to_bytes(2, byteorder='big')

        rbytes = rbytes + int(1).to_bytes(2, byteorder='big')

        ## record TTL.
        rbytes += int(rTTL).to_bytes(4, byteorder='big')

        if rType == 1:
            ## Setup the IP for a specific record.
            rbytes = rbytes + int(4).to_bytes(2, byteorder='big')

            for part in rIPadd.split('.'):
                rbytes += bytes([int(part)])

        return(rbytes)


    def _set_flags(self, **kargs):
        '''
        Set any of the flags for the DNS header.
        '''

        ## flag bits section 1.
        QR = '1' if not 'QR' in kargs else kargs['QR']
        OPCODE = '0000' if not 'OPCODE' in kargs else kargs['OPCODE']
        AA = '1' if not 'AA' in kargs else kargs['AA']
        TC = '0' if not 'TC' in kargs else kargs['TC']
        RD = '0 'if not 'RD' in kargs else kargs['RD']
        fb1 = int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')

        ## flag bits section 2.
        RA = '0' if not 'RA' in kargs else kargs['RA']
        Z = '000' if not 'Z' in kargs else kargs['Z']
        RCODE = '0000' if not 'RCODE' in kargs else kargs['RCODE']
        fb2 = int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

        return(fb1+fb2)



