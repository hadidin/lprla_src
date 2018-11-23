# Copyright 2018 kiplePark
# init by hadi din
# Please refer to license.txt for license terms.
#
# Description: Always Connected to comm module to receive data
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


def COMM_LISTENER(psocket2qrcmod,MaxParkCommModule_IP,MaxPark_QRCommModule_Port):
    # TODO Cache the kiplePark Backend Login Token & its Expiry Date.
    # login_to_backend_with_expiry_check()

    # Constant
    STX = 0x02
    STX_LEN = 1  # 1 byte
    CHECKSUM_LEN = 1  # 1 byte
    ETX = 0x03
    ETX_LEN = 1  # 1 byte
    CMD_LEN = 2  # 2 bytes
    strCMD_PN = "PN"
    strCMD_QR = "QR"
    strCMD_XT = "XT"
    strCMD_PM = "PM"
    strREPLY_PG = "PG"
    strREPLY_PD = "PD"
    strREPLY_AQ = "AQ"



    SOCKET_CONNECT_TIMEOUT=30
    SOCKET_WAITSTX_TIMEOUT=60

    if (psocket2qrcmod is None):  # If needed create the Socket.

        #######################################
        # Connecting to MaxPark QR Comms Module
        #######################################
        logger.debug("Attempting to create socket.")
        try:
            psocket2qrcmod = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)  # create an AF_INET, STREAM socket (TCP)
        except socket.error as err_msg:
            logger.warning(
                "Unable to instantiate socket. Error Code: " + str(err_msg[0]) + " , Error Message: " + err_msg[1])
        # ToDo need to exit if block if error.
        logger.debug("Socket Created")

        logger.debug("Attempting to connect to : {0}".format(MaxParkCommModule_IP))
        try:
            psocket2qrcmod.settimeout(SOCKET_CONNECT_TIMEOUT)
            psocket2qrcmod.connect((MaxParkCommModule_IP, MaxPark_QRCommModule_Port))
            logger.debug("Client has been assigned socket name: {0}".format(psocket2qrcmod.getsockname()))

        except socket.timeout as e:
            logger.info("Timeout connecting: %s" % e)
            psocket2qrcmod.close()
            psocket2qrcmod = None
        except socket.gaierror as e:
            logger.warning("Address-related error connecting to server: %s" % e)
            psocket2qrcmod.close()
            psocket2qrcmod = None
        except socket.error as e:
            logger.warning("Connection error: %s" % e)
            psocket2qrcmod.close()
            psocket2qrcmod = None
        except:
            logger.warning("Other error connnecting")
            psocket2qrcmod.close()
            psocket2qrcmod = None

    # if Connecting to MaxPark QR Comms Module

    bSTX_received = False
    if (psocket2qrcmod is not None):  # Wait for STX

        psocket2qrcmod.settimeout(SOCKET_WAITSTX_TIMEOUT)
        try:
            recv_buffer = psocket2qrcmod.recv(STX_LEN)  # as bytes so do not need .decode("utf8")
            if (recv_buffer[0] == STX):
                bSTX_received = True
                logger.info("Received STX")
        except socket.timeout as e:
            logger.info("Timeout warning recv STX: %s" % e)
        except socket.gaierror as e:
            logger.warning("Address-related error recv STX: %s" % e)
            psocket2qrcmod.close()
            psocket2qrcmod = None
        except socket.error as e:
            logger.warning("Connection error recv STX: %s" % e)
            psocket2qrcmod.close()
            psocket2qrcmod = None
        except:
            logger.warning("Other error recv STX")
            psocket2qrcmod.close()
            psocket2qrcmod = None

    # if Wait for STX

    bCMD_received = False
    if (bSTX_received):  # Wait for CMD

        psocket2qrcmod.settimeout(SOCKET_WAITSTX_TIMEOUT)
        try:
            recv_buffer = psocket2qrcmod.recv(CMD_LEN).decode("utf8")
            if (recv_buffer == strCMD_PN):
                bCMD_received = True
                logger.info("Received CMD %s" % strCMD_PN)

                # ToDo Will need to mode to individual files.
                try:
                    recv_buffer = psocket2qrcmod.recv(8 + 3).decode("utf8")

                    PN_TICKET = recv_buffer[0:8]  # Ticket = 8 characters
                    logger.info("Received CMD -> PN_TICKET: %s" % PN_TICKET)
                    try:
                        PN_SIZE = int(recv_buffer[8:11])  # Size (padded) = 3 characters
                        logger.info("Received CMD -> PN_SIZE: %s" % PN_SIZE)
                    except:
                        logger.warning("Integer conversion error strCMD_PN -> PN_SIZE")
                        psocket2qrcmod.close()
                        psocket2qrcmod = None

                    recv_buffer = psocket2qrcmod.recv(PN_SIZE).decode("utf8")  # the IDQR

                    PN_IDQR = recv_buffer[0:PN_SIZE]  # PN_IDQR is Variable Length.
                    logger.info("Received CMD -> PN_IDQR: %s" % PN_IDQR)

                    # ToDo Checksum & ETX
                    recv_buffer = psocket2qrcmod.recv(CHECKSUM_LEN + ETX_LEN)

                    reply_PG_send_buffer = PN_TICKET + str(PN_SIZE) + PN_IDQR
                    reply_PD_send_buffer = PN_TICKET

                    # result = VALIDATE_Req.ValidateUser(PN_IDQR)
                    # logger.info("response : {0}".format(result))

                    MESSAGE = None


                    # Preparing Message to be send (continued)
                    # ========================================
                    my_MESSAGE = str()
                    for myelement in MESSAGE:
                        my_MESSAGE = my_MESSAGE + myelement

                    # Preparing Packet to be sent
                    # ============================
                    my_PACKET = array('b', [STX])
                    my_PACKET.fromstring(my_MESSAGE)
                    my_PACKET.append(ETX)
                    my_PACKET.tostring()

                    psocket2qrcmod.send(my_PACKET)


                except socket.timeout as e:
                    logger.info("Timeout warning recv strCMD_PN: %s" % e)
                except socket.gaierror as e:
                    logger.warning("Address-related error recv strCMD_PN: %s" % e)
                    psocket2qrcmod.close()
                    psocket2qrcmod = None
                except socket.error as e:
                    logger.warning("Connection error recv strCMD_PN: %s" % e)
                    psocket2qrcmod.close()
                    psocket2qrcmod = None
                except:
                    logger.warning("Other error recv strCMD_PN")
                    psocket2qrcmod.close()
                    psocket2qrcmod = None
            # if (recv_buffer == strCMD_PN)

            elif (recv_buffer == strCMD_QR):
                bCMD_received = True
                logger.info("Received CMD %s" % strCMD_QR)

                # ToDo Will need to mode to individual files.
                try:
                    recv_buffer = psocket2qrcmod.recv(8 + 25 + 3).decode("utf8")

                    QR_TICKET = recv_buffer[0:8]  # Ticket = 8 characters
                    logger.info("Received CMD -> QR_TICKET: %s" % QR_TICKET)

                    QR_TICKQR = recv_buffer[8:33]  # TicketQR = 25 characters
                    logger.info("Received CMD -> QR_TICKQR: %s" % QR_TICKQR)

                    try:
                        QR_SIZE = int(recv_buffer[33:36])  # Size (padded) = 3 characters
                        logger.info("Received CMD -> QR_SIZE: %s" % QR_SIZE)
                    except:
                        logger.warning("Integer conversion error strCMD_QR -> QR_SIZE")
                        psocket2qrcmod.close()
                        psocket2qrcmod = None

                    reply_AQ_send_buffer = QR_TICKET + QR_TICKQR

                    recv_buffer = psocket2qrcmod.recv(QR_SIZE).decode("utf8")  # the IDQR

                    QR_IDQR = recv_buffer[0:QR_SIZE]  # # QR_IDQR is Variable Length.
                    logger.info("Received CMD -> QR_IDQR: %s" % QR_IDQR)

                    # ToDo Checksum & ETX
                    recv_buffer = psocket2qrcmod.recv(CHECKSUM_LEN + ETX_LEN)


                except socket.timeout as e:
                    logger.info("Timeout warning recv strCMD_QR: %s" % e)
                except socket.gaierror as e:
                    logger.warning("Address-related error recv strCMD_QR: %s" % e)
                    psocket2qrcmod.close()
                    psocket2qrcmod = None
                except socket.error as e:
                    logger.warning("Connection error recv strCMD_QR: %s" % e)
                    psocket2qrcmod.close()
                    psocket2qrcmod = None
                except:
                    logger.warning("Other error recv strCMD_QR")
                    psocket2qrcmod.close()
                    psocket2qrcmod = None
            # elif (recv_buffer == strCMD_QR)

            elif (recv_buffer == strCMD_XT):
                bCMD_received = True
                logger.info("Received CMD %s" % strCMD_XT)

            elif (recv_buffer == strCMD_PM):
                bCMD_received = True
                logger.info("Received CMD %s" % strCMD_PM)

            else:
                bCMD_received = False  # reset for readability
                logger.info("Received unknown CMD %s" % recv_buffer)

        except socket.timeout as e:
            logger.info("Timeout warning recv CMD: %s" % e)
        except socket.gaierror as e:
            logger.warning("Address-related error recv CMD: %s" % e)
            psocket2qrcmod.close()
            psocket2qrcmod = None
        except socket.error as e:
            logger.warning("Connection error recv CMD: %s" % e)
            psocket2qrcmod.close()
            psocket2qrcmod = None
        except:
            logger.warning("Other error recv CMD")
            psocket2qrcmod.close()
            psocket2qrcmod = None
    # if Wait for CMD