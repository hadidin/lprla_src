# Copyright 2018 kiplePark

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


def push_plate_no(host, port, socket_timeout, send_buffer_size, recv_buffer_size, plate_no):

    # port=4700;

    STX = 0x02
    CMD_G = "G"       # Character G = ascii 0x47

    DATA = plate_no
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
    # print("X1")
    # print(MESSAGE)
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
    logger.debug("Ticket Barcode : {0}".format(plate_no))


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
        # return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
        #     RETURN_EXIT, RETURN_VALUE) # as a tuple
    logger.debug("Socket Created")

    try:
        s.connect((host,port))
        s.settimeout(socket_timeout)
    except socket.gaierror as e:
        logger.warning("Address-related error connecting to server: %s" % e)
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        # return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
        #     RETURN_EXIT, RETURN_VALUE) # as a tuple
    except socket.error as e:
        logger.warning("Connection error: %s" % e)
        # RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        # return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
        #     RETURN_EXIT, RETURN_VALUE) # as a tuple

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
        print(msg)
    else:
        s.close()
        logger.warning("Timeout. Close connection")
        RETURN_ERRCODE = ERROR_Code.errCommunicationTimeout
        # return (RETURN_ERRCODE, RETURN_ODATA, RETURN_TICKET, RETURN_ENTRY,
        #     RETURN_EXIT, RETURN_VALUE) # as a tuple

    #########################################
    # Close Connection to MaxPark Comm Module
    #########################################
    s.close()
    logger.debug("Close connection")


    RECV_MSG = [ord(c) for c in msg]

    return (RECV_MSG) # as a tuple.


