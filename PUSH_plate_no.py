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

from pprint import pprint


logger = logging.getLogger(__name__)  # module-level logger, so that filename is printed in log.


GET_RESP_STX_OFFSET = 0
GET_RESP_CMD_G_OFFSET = 1
GET_RESP_CHECKSUM_OFFSET = 57
GET_RESP_ETX_OFFSET = 58


def push_plate_no(host, port, socket_timeout, send_buffer_size, recv_buffer_size, plate_no, maxpark_cam_id):

    # port=4700;

    STX = 0x02
    CMD_L = "LD"       # Character G = ascii 0x47

    if(len(plate_no)>16):
        logger.error("Plate is longer than 16 char")
        return ("false")
        sys.exit()


    DATA = maxpark_cam_id + plate_no.rjust(16, ' ') + '000' + 'KiplePark@'
    # DATA = maxpark_cam_id + plate_no.rjust(16, ' ') + '000'
    print('dataraw='+DATA)
    # DATA_list = [ord(c) for c in DATA]
    ETX = 0x03

    # Print current LocalAgent time
    ###############################
    logger.debug("")
    logger.debug("")
    logger.debug ("Current LocalAgent time : {0}".format(datetime.now())) # dt.dt.now() to dt.now due to from datetime.

# ============================CALCULATE CHECKSUM====================================================================
    num_CHECKSUM = LA_Commons.calculate_checksumV2(CMD_L,
                                                   [ord(c) for c in DATA])

    MESSAGE = [CMD_L, DATA, chr(num_CHECKSUM)]

    my_MESSAGE = str()
    for myelement in MESSAGE:
        my_MESSAGE = my_MESSAGE + myelement

    # Preparing Packet to be sent
    # ============================
    my_PACKET = array('b', [STX])
    my_PACKET.fromstring(my_MESSAGE)
    my_PACKET.append(ETX)
# ===========================CALCULATE CHECKSUM END=================================================================




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


    print("push_plateline122")
    print(my_PACKET)
    # print(type(my_PACKET))
    print("push_plateline133")

    try:
        data_sent = s.send(my_PACKET)
        # datetime.time.sleep(8)
    except:
        logger.error("failed to sent packet to comm module")
        return ("false")

    # chunk = s.recv(4096)
    # print('chunk='+chunk)



    #####################################################

    recvbufferoffset = 1    # this is to offset the extra character 13 at the end of the message send by the server

    s.setblocking(0)
    ready = select.select([s], [], [], socket_timeout)
    if ready[0]:
        msg = s.recv(recv_buffer_size).decode("utf8")  # Receiving data from MaxPark
        print('response from simulator' + msg)
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

    ##################################################
    # Form string from received message
    # This string is to be passed to Mobile App
    # my_RECV_MSG is MaxPark Response in String Format
    ##################################################
    my_RECV_MSG = ''.join(chr(i) for i in RECV_MSG)

    status = msg[23:25]
    print('response= '+status)

    return (status)




