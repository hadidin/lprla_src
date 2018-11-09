# Copyright 2018 kiplePark
# init by hadi din
# Please refer to license.txt for license terms.
#
# Description: Ping to check if alive functions.
#
#

import socket
import sys
import datetime
import time
import select
from array import array
import lpr_localagent
import ERROR_Code
import LA_Commons
import logging

logger = logging.getLogger(__name__)  # module-level logger, so that filename is printed in log.

PING_PARKING_SERVER = "000000000000"


def IDLE_Message(host, port, socket_timeout, send_buffer_size, recv_buffer_size, ping_status):
    RETURN_ERRCODE = ERROR_Code.errSuccess

    STX = 0x02
    CMD_IDLE = "$"  # Character $ = ascii 0x24

    if ping_status == PING_PARKING_SERVER:
        DATA = PING_PARKING_SERVER
    else:
        current_localagent_datetime = time.strftime("%Y%m%d%H%M")
        DATA = current_localagent_datetime

    # DATA = localagent_datetime
    DATA_list = [ord(c) for c in DATA]
    ETX = 0x03

    # Print current LocalAgent time
    ###############################
    logger.debug("")
    logger.debug("")
    logger.debug("Current LocalAgent time : {0}".format(datetime.datetime.now()))

    ################################
    # Calculate CHECKSUM to be sent
    ################################
    num_CHECKSUM = LA_Commons.calculate_checksum(CMD_IDLE, DATA_list)
    CHECKSUM = chr(num_CHECKSUM)

    # This code is just to display a human-readable string
    # of the Message to be sent to MaxPark server on the console
    ############################################################
    str_STX = str(STX)
    str_CMD_IDLE = str(CMD_IDLE)
    str_ETX = str(ETX)
    PACKET_DISPLAY = [str_STX, str_CMD_IDLE, DATA, CHECKSUM, str_ETX]
    str_PACKET_DISPLAY = str()
    for myelement in PACKET_DISPLAY:
        str_PACKET_DISPLAY = str_PACKET_DISPLAY + myelement
    # str_PACKET_DISPLAY = "1234567890123456789012345678901234567890"
    LOCAL_AGENT_DATETIME = str_PACKET_DISPLAY[2:14]  # 12 characters
    logger.debug("==============================")
    logger.debug("Message sent to MaxPark Server: {0}".format(str_PACKET_DISPLAY))
    logger.debug("Local Agent Date/Time : {0}".format(LOCAL_AGENT_DATETIME))

    # Preparing Message to be send
    # =============================
    MESSAGE = [CMD_IDLE, DATA, CHECKSUM]
    my_MESSAGE = str()
    for myelement in MESSAGE:
        my_MESSAGE = my_MESSAGE + myelement

    # Preparing Packet to be sent
    # ============================
    my_PACKET = array('b', [STX])
    my_PACKET.fromstring(my_MESSAGE)
    my_PACKET.append(ETX)
    my_PACKET.tostring()


    logger.debug("==============================")

    ###################################
    # Connecting to MaxPark Comm Module
    ###################################
    logger.debug("Attempting to connect to : {0}".format(host))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create an AF_INET, STREAM socket (TCP)
        s.settimeout(socket_timeout)
    except socket.error as err_msg:
        logger.warning(
            "Unable to instantiate socket. Error Code: " + str(err_msg[0]) + " , Error Message: " + err_msg[1])
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        return (RETURN_ERRCODE,)

    logger.debug("Socket Created")

    try:
        s.connect((host, port))
        s.settimeout(socket_timeout)
    except socket.gaierror as e:
        logger.warning("Address-related error connecting to server: %s" % e)
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        return (RETURN_ERRCODE,)
    except socket.error as e:
        logger.warning("Connection error: %s" % e)
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        return (RETURN_ERRCODE,)

    logger.debug("Client has been assigned socket name: {0}".format(s.getsockname()))

    # hadi debug print
    # print("sss")
    print(my_PACKET.tostring())
    data_sent = s.send(my_PACKET)

    #####################################################

    STX = 0x02
    CMD_T = "T"  # Character T = ascii 0x54
    ETX = 0x03

    recvbufferoffset = 1  # this is to offset the extra character 13 at the end of the message send by the server

    s.setblocking(0)
    ready = select.select([s], [], [], socket_timeout)
    if ready[0]:
        msg = s.recv(recv_buffer_size).decode("utf8")  # Receiving data from MaxPark
        print(msg)
    else:
        s.close()
        logger.warning("Timeout. Close connection")
        RETURN_ERRCODE = ERROR_Code.errCommunicationTimeout
        return (RETURN_ERRCODE,)

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

    DATETIME = my_RECV_MSG[2:14]  # DATETIME = 12 characters
    YEAR = int(DATETIME[0:4])
    MONTH = int(DATETIME[4:6])
    DAY = int(DATETIME[6:8])
    HOUR = int(DATETIME[8:10])
    MINUTE = int(DATETIME[10:12])

    ###################################################
    # DATA only portion
    # Packet Integrity check on STX, ETX, CMD, CHECKSUM
    # RECV_MSG is MaxPark Response in Array Format
    ###################################################
    recvDATA = RECV_MSG[2:len(msg) - 2 - recvbufferoffset]

    recv_STX = RECV_MSG[0]
    recv_CMD = chr(RECV_MSG[1])
    recv_ETX = RECV_MSG[len(msg) - 1 - recvbufferoffset]
    recv_CHECKSUM = RECV_MSG[len(msg) - 2 - recvbufferoffset]

    #####################
    # Calculate CHECKSUM
    #####################
    recv_calc_num_CHECKSUM = LA_Commons.calculate_checksum(CMD_T, recvDATA)

    if recv_STX != STX:
        logger.warning("Error : STX is not 0x02")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    elif ((ping_status == PING_PARKING_SERVER) and (recv_CMD != CMD_IDLE)):
        logger.warning("Error : CMD_IDLE is not $ for ping")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
        return (RETURN_ERRCODE,)
    elif ((ping_status != PING_PARKING_SERVER) and (recv_CMD != CMD_T)):
        logger.warning("Error : CMD_T is not T for IDLE")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
        return (RETURN_ERRCODE,)
    elif recv_ETX != ETX:
        logger.warning("Error : ETX is not 0x03")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
        return (RETURN_ERRCODE,)
    elif ((ping_status == PING_PARKING_SERVER) and (ord(CMD_IDLE) != recv_CHECKSUM)):
        logger.warning("Error : CHECKSUM should be $ for ping, but is not")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
        return (RETURN_ERRCODE,)
    elif ((ping_status != PING_PARKING_SERVER) and (recv_calc_num_CHECKSUM != recv_CHECKSUM)):
        logger.warning("Error : CHECKSUM error for IDLE")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
        return (RETURN_ERRCODE,)
    else:
        if (ping_status != PING_PARKING_SERVER):
            # Supposed to set RPi3 time here as per MaxPark time, but was not needed as RPi3 follows Internet Time
            ######################################################################################################
            logger.debug("Response from MaxPark Server : ")
            logger.debug("DATETIME  : {0}".format(DATETIME))
            logger.debug("==============================")

    if ((ping_status == PING_PARKING_SERVER) and (DATETIME == PING_PARKING_SERVER)):
        # Parking Server is Alive
        RETURN_ERRCODE = ERROR_Code.errSuccess
    elif ((ping_status == PING_PARKING_SERVER) and (DATETIME != PING_PARKING_SERVER)):
        logger.warning("Error: Ping reply is not as expected, it is : {0}".format(DATETIME))
        RETURN_ERRCODE = ERROR_Code.errGeneral
        return (RETURN_ERRCODE,)
    elif (ping_status != PING_PARKING_SERVER):
        RETURN_ERRCODE = ERROR_Code.errSuccess  # Actually can use 'pass', since RETURN_ERRCODE already set above.
    else:
        logger.error("Error: Code flow show not reach here.")
        RETURN_ERRCODE = ERROR_Code.errGeneral
        return (RETURN_ERRCODE,)

    return (RETURN_ERRCODE,)
