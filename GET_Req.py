# Copyright 2018 kiplePark
# init by hadi din
# Please refer to license.txt for license terms.
# 
# Description: Check Ticket payable amount & details functions.
#
#

import socket
import sys
import datetime
import select
from array import array
import lpr_localagent
import ERROR_Code
import LA_Commons
import logging
from datetime import timedelta , datetime

logger = logging.getLogger(__name__)  # module-level logger, so that filename is printed in log.


GET_RESP_STX_OFFSET = 0
GET_RESP_CMD_G_OFFSET = 1
GET_RESP_CHECKSUM_OFFSET = 57
GET_RESP_ETX_OFFSET = 58


def GET_Request(host, port, socket_timeout, send_buffer_size, recv_buffer_size, ticket_barcode):

    # Return multiple values as a Tuple.
    RETURN_ERRCODE = ERROR_Code.errSuccess # Assume success so not need to change until error.
    RETURN_ODATA = ""
    RETURN_TICKET = ""
    RETURN_ENTRY = ""
    RETURN_EXIT = ""
    RETURN_VALUE = ""

    if len(ticket_barcode) != 20:
        RETURN_ERRCODE = ERROR_Code.errParamLength
        return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
            RETURN_EXIT, RETURN_VALUE) # as a tuple

    STX = 0x02
    CMD_G = "G"       # Character G = ascii 0x47

    DATA = ticket_barcode
    #print(DATA)
    DATA_list = [ord(c) for c in DATA]
    ETX = 0x03

    # Print current LocalAgent time
    ###############################
    logger.debug("")
    logger.debug("")
    logger.debug ("Current LocalAgent time : {0}".format(datetime.now())) # dt.dt.now() to dt.now due to from datetime.


    ################################
    # Calculate CHECKSUM to be sent
    ################################
    num_CHECKSUM = LA_Commons.calculate_checksum(CMD_G, DATA_list)
    CHECKSUM = chr(num_CHECKSUM)


    # Preparing Message to be send
    #=============================
    MESSAGE = [CMD_G, DATA, CHECKSUM]
    print("X1")
    print(MESSAGE)
    my_MESSAGE = str()
    for myelement in MESSAGE:
        my_MESSAGE = my_MESSAGE + myelement


    # This code is just to display a human-readable string
    # of the Message to be sent to MaxPark server on the console
    ############################################################
    str_STX = str(STX)
    str_CMD_G = str(CMD_G)
    str_ETX = str(ETX)
    PACKET_DISPLAY = [str_STX, str_CMD_G, DATA, CHECKSUM, str_ETX]
    str_PACKET_DISPLAY = str()

    for myelement in PACKET_DISPLAY:
        str_PACKET_DISPLAY = str_PACKET_DISPLAY + myelement
    logger.debug("==============================")
    logger.debug("Message sent to MaxPark Server: {0}".format(str_PACKET_DISPLAY))
    logger.debug("Ticket Barcode : {0}".format(ticket_barcode))


    # Preparing Packet to be sent
    #============================
    my_PACKET = array('b',[STX])
    my_PACKET.fromstring(my_MESSAGE)
    my_PACKET.append(ETX)
    my_PACKET.tostring()
    logger.debug("==============================")

    ###################################
    # Connecting to MaxPark Comm Module
    ###################################
    logger.debug("Attempting to connect to : {0}".format(host))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create an AF_INET, STREAM socket (TCP)
        s.settimeout(socket_timeout)
    except socket.error as err_msg:
        logger.warning("Unable to instantiate socket. Error Code: " + str(err_msg[0]) + " , Error Message: " + err_msg[1])
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
            RETURN_EXIT, RETURN_VALUE) # as a tuple
    logger.debug("Socket Created")

    try:
        s.connect((host,port))
        s.settimeout(socket_timeout)
    except socket.gaierror as e:
        logger.warning("Address-related error connecting to server: %s" % e)
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
            RETURN_EXIT, RETURN_VALUE) # as a tuple
    except socket.error as e:
        logger.warning("Connection error: %s" % e)
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
            RETURN_EXIT, RETURN_VALUE) # as a tuple

    logger.debug("Client has been assigned socket name: {0}".format(s.getsockname()) )


    print("SINI")
    print(my_PACKET)
    print(my_PACKET.tostring())
    data_sent = s.send(my_PACKET)


    #####################################################

    recvbufferoffset = 1    # this is to offset the extra character 13 at the end of the message send by the server

    s.setblocking(0)
    ready = select.select([s], [], [], socket_timeout)
    if ready[0]:
        msg = s.recv(recv_buffer_size).decode("utf8")  # Receiving data from MaxPark
        # print(msg)
    else:
        s.close()
        logger.warning("Timeout. Close connection")
        RETURN_ERRCODE = ERROR_Code.errCommunicationTimeout
        return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
            RETURN_EXIT, RETURN_VALUE) # as a tuple

    #########################################
    # Close Connection to MaxPark Comm Module
    #########################################
    s.close()
    logger.debug("Close connection")


    RECV_MSG = [ord(c) for c in msg]

    ##################################################
    # Form string from received message
    # This string is to be passed to Mobile App
    # my_RECV_MSG is MaxPark Response in String Format
    ##################################################
    my_RECV_MSG = ''.join(chr(i) for i in RECV_MSG)

    ODATA = my_RECV_MSG[2:22]   # ODATA = 20 characters
    TICKET = my_RECV_MSG[22:30] # TICKET = 8 characters
    ENTRY = my_RECV_MSG[30:40]  # ENTRY = 10 characters
    EXIT = my_RECV_MSG[40:50]   # EXIT = 10 characters
    VALUE = my_RECV_MSG[50:56]  # VALUE = 6 characters


    ###################################################
    # DATA only portion
    # Packet Integrity check on STX, ETX, CMD, CHECKSUM
    # RECV_MSG is MaxPark Response in Array Format
    ###################################################
    recvDATA = RECV_MSG[2:len(msg)-2-recvbufferoffset]

    recv_STX = RECV_MSG[0]
    recv_CMD = chr(RECV_MSG[1])
    recv_ETX = RECV_MSG[len(msg)-1-recvbufferoffset]
    recv_CHECKSUM = RECV_MSG[len(msg)-2-recvbufferoffset]

    #####################
    # Calculate CHECKSUM
    #####################
    recv_calc_num_CHECKSUM = LA_Commons.calculate_checksum(CMD_G, recvDATA)




    if recv_STX != STX:
        logger.warning("Error : STX is not 0x02")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    elif recv_CMD != CMD_G:
        logger.warning("Error : CMD_G is not G")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    elif recv_ETX != ETX:
        logger.warning("Error : ETX is not 0x03")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    elif recv_calc_num_CHECKSUM != recv_CHECKSUM:
        logger.warning("Error : CHECKSUM error")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    else:
        logger.debug("Response from MaxPark Server : ")
        logger.debug("ODATA  : {0}".format(ODATA))
        logger.debug("TICKET : {0}".format(TICKET))
        logger.debug("ENTRY  : {0}".format(ENTRY))
        logger.debug("EXIT   : {0}".format(EXIT))
        logger.debug("VALUE  : {0}".format(VALUE))
        logger.debug("==============================")
        if TICKET.startswith("EROR"):
            RETURN_ERRCODE = TICKET[4:8]  # Need to substring when 'EROR' prefix detected.
        # Else already defined: RETURN_ERRCODE = ERROR_Code.errSuccess
        RETURN_ODATA = ODATA
        RETURN_TICKET = TICKET
        RETURN_ENTRY = ENTRY
        RETURN_EXIT = EXIT
        RETURN_VALUE = VALUE


    return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
            RETURN_EXIT, RETURN_VALUE) # as a tuple.


# For demo purposes, does not communicate with the Comms Module.
def GET_RequestDemo(ticket_barcode):

    # Return multiple values as a Tuple.
    RETURN_ERRCODE = ERROR_Code.errSuccess # Assume success, since no checksum or transmission errors.
    RETURN_ODATA = ""
    RETURN_TICKET = ""    #If there is an error calculating the Ticket Value, the TICKET data field will contain the
                          # letters “EROR” plus the error code. All other fields will be set to “0”
    RETURN_ENTRY = ""  # YYMMDDHHNN
    RETURN_EXIT = ""  # YYMMDDHHNN
    RETURN_VALUE = ""  # Append 2 zeros to convert Fare from RM to sen.

    if len(ticket_barcode) != 20:
        RETURN_ERRCODE = ERROR_Code.errParamLength
        return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
            RETURN_EXIT, RETURN_VALUE) # as a tuple

    # Split the input string.
    ticket_id = ticket_barcode[0:8]
    get_errcode = ticket_barcode[8:12]
    fare_in_rm = ticket_barcode[14:16]
    aut_errcode = ticket_barcode[16:20]

    RETURN_ODATA = ticket_barcode  # Always, regardless of error.
    if (get_errcode == "S000"):  # Success
        # Already RETURN_ERRCODE = ERROR_Code.errSuccess  # Assume success, since no checksum or transmission errors.

        RETURN_TICKET = ticket_id

        exit_datetime = datetime.today()
        entry_datetime = exit_datetime - timedelta(minutes= 15)

        RETURN_ENTRY = entry_datetime.strftime("%y%m%d%H%M")  # YYMMDDHHNN
        RETURN_EXIT = exit_datetime.strftime("%y%m%d%H%M")  # YYMMDDHHNN
        RETURN_VALUE = fare_in_rm + "{0:02d}".format(exit_datetime.second) # Append 2-digit seconds to provide changes.
        # + "00"  # Append 2 zeros to suffix of the 2-digit Fare from RM to sen.
    else:  # Failure
        RETURN_ERRCODE = get_errcode  # Assume success, since no checksum or transmission errors.

        RETURN_TICKET = "EROR" + get_errcode  # If there is an error calculating the Ticket Value, the TICKET data field will contain the
        # letters “EROR” plus the error code. All other fields will be set to “0”
        RETURN_ENTRY = "0" * 10  # YYMMDDHHNN
        RETURN_EXIT = "0" * 10  # YYMMDDHHNN
        RETURN_VALUE = "0" * 6


    return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
            RETURN_EXIT, RETURN_VALUE) # as a tuple.
