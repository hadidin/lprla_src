# Copyright 2018 kiplePark
# init by hadi din
#
# Please refer to license.txt for license terms.
# 
# Description: Pay Ticket functions.
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
from datetime import datetime
import LA_Commons

logger = logging.getLogger(__name__)  # module-level logger, so that filename is printed in log.

AUT_RESP_STX_OFFSET = 0
AUT_RESP_CMD_A_OFFSET = 1
AUT_RESP_CHECKSUM_OFFSET = 49
AUT_RESP_ETX_OFFSET = 50


def AUT_Request(host, port, socket_timeout, send_buffer_size, recv_buffer_size, ticket_number, payment_auth_code, payment_amount):

    # Return multiple values as a Tuple.
    RETURN_ERRCODE = ERROR_Code.errSuccess  # Assume success so not need to change until error.
    RETURN_TICKET = ""
    RETURN_RECEIPT = ""
    RETURN_VALUE = ""
    RETURN_GST = ""
    RETURN_PAID_DATETIME = ""  # Known as PDATE in specification PDF.
    RETURN_GRACE = ""

    if len(ticket_number) != 8:
        RETURN_ERRCODE = ERROR_Code.errParamLength
    if len(payment_auth_code) != 12:
        RETURN_ERRCODE = ERROR_Code.errParamLength
    if len(payment_amount) != 6:
        RETURN_ERRCODE = ERROR_Code.errParamLength

    if RETURN_ERRCODE == ERROR_Code.errParamLength:
        return (RETURN_ERRCODE, RETURN_TICKET, RETURN_RECEIPT, RETURN_VALUE, RETURN_GST,
                RETURN_PAID_DATETIME, RETURN_GRACE)  # as a tuple.

    aut_ticket_data = ticket_number + payment_auth_code + payment_amount

    STX = 0x02
    CMD_A = "A"       # Character A = ascii 0x41
    DATA = aut_ticket_data
    DATA_list = [ord(c) for c in DATA]
    ETX = 0x03

    # Print current LocalAgent time
    ###############################
    logger.debug("")
    logger.debug("")
    logger.debug("Current LocalAgent time : {0}".format(datetime.now())) # dt.dt.now() to dt.now due to from datetime.


    ################################
    # Calculate CHECKSUM to be sent
    ################################
    num_CHECKSUM = LA_Commons.calculate_checksum(CMD_A, DATA_list)
    CHECKSUM = chr(num_CHECKSUM)


    # Preparing Message to be send
    #=============================
    MESSAGE = [CMD_A, DATA, CHECKSUM]
    my_MESSAGE = str()
    for myelement in MESSAGE:
        my_MESSAGE = my_MESSAGE + myelement


    # This code is just to display a human-readable string
    # of the Message to be sent to MaxPark server on the console
    ############################################################
    str_STX = str(STX)
    str_CMD_A = str(CMD_A)
    str_ETX = str(ETX)
    PACKET_DISPLAY = [str_STX, str_CMD_A, DATA, CHECKSUM, str_ETX]
    str_PACKET_DISPLAY = str()
    for myelement in PACKET_DISPLAY:
        str_PACKET_DISPLAY = str_PACKET_DISPLAY + myelement
    TICKET_NUMBER = str_PACKET_DISPLAY[2:10]
    PAYMENT_AUTHORIZATION_CODE = str_PACKET_DISPLAY[10:22]
    PAYMENT_AMOUNT = str_PACKET_DISPLAY[22:28]

    logger.debug("==============================")
    logger.debug("Message sent to MaxPark Server: {0}".format(str_PACKET_DISPLAY))
    logger.debug("Ticket Number              : {0}".format(TICKET_NUMBER))              # 8 characters
    logger.debug("Payment Authorizaion Code  : {0}".format(PAYMENT_AUTHORIZATION_CODE)) # 12 charaters
    logger.debug("Payment Amount             : {0}".format(PAYMENT_AMOUNT))             # 6 characters


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
        return (RETURN_ERRCODE, RETURN_TICKET, RETURN_RECEIPT, RETURN_VALUE, RETURN_GST,
                RETURN_PAID_DATETIME, RETURN_GRACE)  # as a tuple.

    logger.debug("Socket Created")


    try:
        s.connect((host,port))
        s.settimeout(socket_timeout)
    except socket.gaierror as e:
        logger.warning("Address-related error connecting to server: %s" % e)
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        return (RETURN_ERRCODE, RETURN_TICKET, RETURN_RECEIPT, RETURN_VALUE, RETURN_GST,
                RETURN_PAID_DATETIME, RETURN_GRACE)  # as a tuple.
    except socket.error as e:
        logger.warning("Connection error: %s" % e)
        RETURN_ERRCODE = ERROR_Code.errNetworkSocket
        return (RETURN_ERRCODE, RETURN_TICKET, RETURN_RECEIPT, RETURN_VALUE, RETURN_GST,
                RETURN_PAID_DATETIME, RETURN_GRACE)  # as a tuple.

    logger.debug("Client has been assigned socket name: {0}".format(s.getsockname()) )


    data_sent = s.send(my_PACKET)


    #####################################################

    recvbufferoffset = 1    # this is to offset the extra character 13 at the end of the message send by the server

    s.setblocking(0)
    ready = select.select([s], [], [], socket_timeout)
    if ready[0]:
        msg = s.recv(recv_buffer_size).decode("utf8")  # Receiving data from MaxPark
    else:
        s.close()
        logger.warning("Timeout. Close connection")
        RETURN_ERRCODE = ERROR_Code.errCommunicationTimeout
        return (RETURN_ERRCODE, RETURN_TICKET, RETURN_RECEIPT, RETURN_VALUE, RETURN_GST,
                RETURN_PAID_DATETIME, RETURN_GRACE)  # as a tuple.


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

    logger.debug("Ticket code : %s" % my_RECV_MSG )
    TICKET = my_RECV_MSG[2:10]     # TICKET = 8 characters
    RECEIPT = my_RECV_MSG[10:20]   # RECEIPT = 10 characters
    VALUE = my_RECV_MSG[20:26]     # VALUE = 6 characters
    GST = my_RECV_MSG[26:30]       # GST = 4 characters
    PDATE = my_RECV_MSG[30:42]     # PDATE = 12 characters
    GRACE = my_RECV_MSG[42:45]     # GRACE = 3 characters
    STATUS = my_RECV_MSG[45:49]    # STATUS = 4 characters


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
    recv_calc_num_CHECKSUM = LA_Commons.calculate_checksum(CMD_A, recvDATA)


    if recv_STX != STX:
        logger.warning("Error : STX is not 0x02")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    elif recv_CMD != CMD_A:
        logger.warning("Error : CMD_A is not A")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    elif recv_ETX != ETX:
        logger.warning("Error : ETX is not 0x03")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    elif recv_calc_num_CHECKSUM != recv_CHECKSUM:
        logger.warning("Error : CHECKSUM error")
        RETURN_ERRCODE = ERROR_Code.errCommunicationChecksumAndFormat
    else:
        logger.debug("Response from MaxPark Server : ")
        logger.debug("TICKET  : {0}".format(TICKET))
        logger.debug("RECEIPT : {0}".format(RECEIPT))
        logger.debug("VALUE   : {0}".format(VALUE))
        logger.debug("GST     : {0}".format(GST))
        logger.debug("PDATE   : {0}".format(PDATE))
        logger.debug("GRACE   : {0}".format( GRACE))
        logger.debug("STATUS  : {0}".format(STATUS))
        logger.debug("==============================")
        if STATUS == "S000":
            pass # Already defined: RETURN_ERRCODE = ERROR_Code.errSuccess
        else:
            RETURN_ERRCODE = STATUS
        RETURN_TICKET = TICKET
        RETURN_RECEIPT = RECEIPT
        RETURN_VALUE = VALUE
        RETURN_GST = GST
        RETURN_PAID_DATETIME = PDATE
        RETURN_GRACE = GRACE



    return (RETURN_ERRCODE, RETURN_TICKET, RETURN_RECEIPT, RETURN_VALUE, RETURN_GST,
            RETURN_PAID_DATETIME, RETURN_GRACE)  # as a tuple.


# For demo purposes. To be used with GET_RequestDemo().
g_mock_aut_errcode = "S000"
g_mock_aut_exit_grace_period = 20  # In minutes, as 2 char string.

def AUT_RequestDemo_ExtractMockErrcode(ticket_barcode):
    global g_mock_aut_errcode

    aut_errcode = ticket_barcode[16:20]
    g_mock_aut_errcode = aut_errcode


def AUT_RequestDemo_ExtractMockExitGracePeriod(ticket_barcode):
    global g_mock_aut_exit_grace_period

    value = ticket_barcode[12:14]
    g_mock_aut_exit_grace_period = value


# For demo purposes, does not communicate with the Comms Module.
g_int_ReceiptRunningNumber = 12345678
def AUT_RequestDemo(ticket_number, payment_auth_code, payment_amount):
    global g_int_ReceiptRunningNumber

    # Return multiple values as a Tuple.
    RETURN_ERRCODE = ERROR_Code.errSuccess  # Assume success so not need to change until error.
    RETURN_TICKET = ticket_number
    RETURN_RECEIPT = ""
    RETURN_VALUE = ""
    RETURN_GST = ""
    RETURN_PAID_DATETIME = ""  # YYYYMMDDHHNN # Known as PDATE in specification PDF.
    RETURN_GRACE = ""

    if len(ticket_number) != 8:
        RETURN_ERRCODE = ERROR_Code.errParamLength
    if len(payment_auth_code) != 12:
        RETURN_ERRCODE = ERROR_Code.errParamLength
    if len(payment_amount) != 6:
        RETURN_ERRCODE = ERROR_Code.errParamLength

    if RETURN_ERRCODE == ERROR_Code.errParamLength:
        return (RETURN_ERRCODE, RETURN_TICKET, RETURN_RECEIPT, RETURN_VALUE, RETURN_GST,
                RETURN_PAID_DATETIME, RETURN_GRACE)  # as a tuple.

    if (g_mock_aut_errcode == "S000"):  # Success
        # Already RETURN_ERRCODE = ERROR_Code.errSuccess  # Assume success so not need to change until error.

        now_datetime = datetime.today()

        RETURN_RECEIPT = "CR" + str(g_int_ReceiptRunningNumber)
        g_int_ReceiptRunningNumber += 1

        RETURN_VALUE = payment_amount
        RETURN_GST = calculate_GST_in_sen_as_str(payment_amount)
        RETURN_PAID_DATETIME = now_datetime.strftime("%Y%m%d%H%M")  # YYYYMMDDHHNN # Known as PDATE in specification PDF.
        RETURN_GRACE = "0" + str(g_mock_aut_exit_grace_period)
    else:  # Failure
        RETURN_ERRCODE = g_mock_aut_errcode

        RETURN_RECEIPT = "0" * 10
        RETURN_VALUE = "0" * 6
        RETURN_GST = "0000"
        RETURN_PAID_DATETIME = "0" * 12  # YYYYMMDDHHNN # Known as PDATE in specification PDF.
        RETURN_GRACE = "000"

    return (RETURN_ERRCODE, RETURN_TICKET, RETURN_RECEIPT, RETURN_VALUE, RETURN_GST,
            RETURN_PAID_DATETIME, RETURN_GRACE)  # as a tuple.


def calculate_GST_in_sen_as_str(str_payment_amount_in_sen):

    payment_amount_in_sen = int(str_payment_amount_in_sen)

    gst = int(round(payment_amount_in_sen * 6 / 100))
    str_gst = "{0:0=4}".format(gst)

    return str_gst
