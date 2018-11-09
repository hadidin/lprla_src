import socket
import os
import sys
# import threading
import logging
import logging.handlers
import json

#for handle config from txt file
import configparser

# Continue logger configuration at 'main'.
logger = logging.getLogger() # Get the 'root' logger & configure it. Run multiple times is ok,
#  since there is only one instance.


import IDLE_Msg
import ERROR_Code
import GET_Req
import PUSH_plate_no
import base64
import time
from ftplib import FTP


from flask import Flask, jsonify
from flask import abort
from flask import make_response
from flask import request
import requests


app = Flask(__name__)

if getattr(sys, 'frozen', False):
    # we are running in a bundle
    actual__file__dir = sys._MEIPASS
else:
    # we are running in a normal Python environment
    actual__file__dir = os.path.dirname(os.path.abspath(__file__))


config = configparser.ConfigParser()
config.read(os.path.join(actual__file__dir, 'conf/config.ini'))


# Communications Module
#======================
MaxParkCommModule_IP = config['CommModule']['CommModule_IP']  # IP Address of MaxPark Comm Module
MaxParkCommModule_Port = int(config['CommModule']['CommModule_Port'])  # Port used
SOCKET_TIMEOUT = int(config['CommModule']['SOCKET_TIMEOUT'])  # timeout units in seconds
SEND_BUFFER_SIZE = int(config['CommModule']['SEND_BUFFER_SIZE'])
RECV_BUFFER_SIZE = int(config['CommModule']['RECV_BUFFER_SIZE'])
ENABLE_PERIODIC_IDLE_MSG = int(config['CommModule']['ENABLE_PERIODIC_IDLE_MESSAGE'])
IDLE_TASK_TIMER = int(config['CommModule']['IDLE_TASK_TIMER']) # run Idle task every x minutes -> units in minutes



# FTP Module
#===========
MaxPark_FTP_Server = config['FTP']['FTP_Server']
MaxPark_FTP_Username = config['FTP']['FTP_Username']
MaxPark_FTP_Password = config['FTP']['FTP_Password']
MaxPark_FTP_Source = config['FTP']['Source']
RPi3_Destination = config['FTP']['Destination']
MaxPark_FTP_Interval = int(config['FTP']['FTP_Interval'])


# AWS Module
#===========
AWS_Bucket_Name = config['AWS']['AWS_BUCKET_NAME']


# General Parameters
#===================
NON_PING_PARKING_SERVER = "101010101010"
g_intIs_Demo_Mode = None  # Bypass the Comms Module for certain commands & removes need for real Tickets.
g_PNSAppServices_IPWhiteList = "" # IP White List for PNS App Services.


# Lpr Parameter
#===================
camera_mapping_conf = config['CAMRERA_MAPPING']['Camera_list']
lpr_ftp_server = config['CAMRERA_MAPPING']['lpr_ftp_server']
lpr_ftp_user = config['CAMRERA_MAPPING']['lpr_ftp_user']
lpr_ftp_pswd = config['CAMRERA_MAPPING']['lpr_ftp_pswd']
lpr_ftp_folder = config['CAMRERA_MAPPING']['lpr_ftp_folder']


# Detect OS in order to detect LAN IP of localhost automatically
if os.name != "nt":
    import fcntl
    import struct


    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                                                            bytes(ifname[:15], 'utf8')))[20:24])


def get_lan_ip():
    return "0.0.0.0"
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
        ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip


def initialize_logger():

    # Get the values from the INI file.
    strLogDirectory = config['Logging']['Log_Directory']
    intIs_Log_To_Console = int(config['Logging']['Is_Log_To_Console'])
    intBackup_Rotate_Count = int(config['Logging']['Backup_Rotate_Count'])

    strLog_Level = str.upper(config['Logging']['Log_Level'])
    log_level_to_use = logging.INFO
    if (strLog_Level == "CRITICAL" ):
        log_level_to_use = logging.CRITICAL
    elif (strLog_Level == "ERROR"):
        log_level_to_use = logging.ERROR
    elif (strLog_Level == "WARNING"):
        log_level_to_use = logging.WARNING
    elif (strLog_Level == "INFO"):
        log_level_to_use = logging.INFO
    elif (strLog_Level == "DEBUG"):
        log_level_to_use = logging.DEBUG
    else:
        log_level_to_use = logging.INFO

    str_log_line_format = '%(asctime)s %(name)s:%(funcName)s:%(lineno)-5d> %(levelname)s: %(message)s'
    str_log_file_path = os.path.join(actual__file__dir, strLogDirectory + "localagent.log")
    log_level = log_level_to_use  # INFO to have logging from localagent.py, not the sub-modules which needs DEBUG.

    # Refer to https://docs.python.org/3/howto/logging.html
    #
    # Configure for the file to log. This is the sample for a log file which continues to grow.
    # logging.basicConfig(filename= str_log_file_path, level= log_level,
    #     format= str_log_line_format)

    logger.setLevel(log_level)  # This is to set the level for Flask. INFO needed for Running on https://192.168 ... .

    timedRotatingFileHandler = logging.handlers.TimedRotatingFileHandler(
                    filename= str_log_file_path,
                    when='midnight', interval= 1, backupCount= intBackup_Rotate_Count)
    timedRotatingFileHandler.setLevel(log_level)
    formatterTRH = logging.Formatter(str_log_line_format)
    timedRotatingFileHandler.setFormatter(formatterTRH)
    logger.addHandler(timedRotatingFileHandler)

    if (intIs_Log_To_Console > 0):
        # define a Handler which writes DEBUG messages or higher to the sys.stderr (console)
        console = logging.StreamHandler()
        console.setLevel(log_level)
        # set a format which is simpler for console use
        formatter = logging.Formatter(str_log_line_format)
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        logger.addHandler(console)
    else:
        print("Goto config.ini to enable logging to console: (Is_Log_To_Console).")

def main():
    # Get the values from the INI file.
    global g_intIs_Demo_Mode
    g_intIs_Demo_Mode = int(config['LocalAgent']['Demo_Mode'])

    initialize_logger()
    # Use Critical to always print first line in log.
    logger.critical("\n --- Application started & 'main' was called. This is not really Critical. --- \n")

    # Read the IP White List for PNS App Services.
    global g_PNSAppServices_IPWhiteList
    g_PNSAppServices_IPWhiteList = config['LocalAgent']['PNS_AppServices_IP_WhiteList']
    g_PNSAppServices_IPWhiteList = g_PNSAppServices_IPWhiteList.split(",")
    g_PNSAppServices_IPWhiteList = list(map(str.strip, g_PNSAppServices_IPWhiteList))
    logger.info("PNS App Services IP Address White List:")
    logger.info(g_PNSAppServices_IPWhiteList)

    if (ENABLE_PERIODIC_IDLE_MSG > 0): # IDLE is enabled
        run_Idle_task_periodically()  # Since flask is an infinite loop, start Timer loop here.

    if int(config['LocalAgent']['Http']):
        # Auto configure LAN IP and start Flask as HTTP
        # print('HTTP')
        app.run(host=get_lan_ip(), port=int(config['LocalAgent']['Port']), debug=False)
    else:
        # Auto configure LAN IP and start Flask as HTTPS
        # print('HTTPS')
        context = (os.path.join(actual__file__dir, config['Certs']['Certificate']),
                   os.path.join(actual__file__dir, config['Certs']['Key']))
        app.run(host=get_lan_ip(), port=int(config['LocalAgent']['Port']), debug=False,
                ssl_context=context)

    return

@app.route('/testget', methods=['GET'])
def test_get():
    return "<!DOCTYPE html><html><head><title>Flask Testing GET Method</title></head><body><h1>HTML Test Page</h1><p>Indicates GET method is successful.</p></body></html>", 200


@app.route('/localagent/v1/ping_parking_server', methods=['POST'])
def v1_ping_parking_server():
    if (not request.json) or (not 'ping' in request.json):
        abort(400)

    ping_data = request.json['ping'] # ping Parking Server

    if (ping_data != "000000000000"):
        abort(400)

    logger.info("")
    logger.info("--- v1_ping_parking_server ---")
    logger.info("Ping Parking Server, Ping = " + ping_data)

    logger.info("Communicating with Comms Module")
    response = IDLE_Msg.IDLE_Message(MaxParkCommModule_IP,
                                     MaxParkCommModule_Port,
                                     SOCKET_TIMEOUT,
                                     SEND_BUFFER_SIZE,
                                     RECV_BUFFER_SIZE,
                                     ping_data)
    logger.info("response : {0}".format(response))

    logger.info("Send to PNS Server")

    return_json = {
        'err_code': response[0]
    }

    returnHttpStatus = 200
    if response[0] != ERROR_Code.errSuccess:
        returnHttpStatus= 400

    return jsonify(return_json), returnHttpStatus

@app.route('/localagent/v1/get_ticket', methods=['POST'])
def v1_get_ticket():
    if (not request.json) or (not 'odata' in request.json):
        abort(400)
    #sleep(9)

    original_barcode_id = request.json['odata']  # 2D barcode data.
    logger.info("")
    logger.info("--- v1_get_ticket ---")
    logger.info("Received from PNS Server")
    logger.info("odata= " + original_barcode_id)

    if (g_intIs_Demo_Mode > 0):
        logger.info("Communicating in Demo Mode")
        # AUT_Req.AUT_RequestDemo_ExtractMockErrcode(original_barcode_id)
        # AUT_Req.AUT_RequestDemo_ExtractMockExitGracePeriod(original_barcode_id)
        response = GET_Req.GET_RequestDemo(original_barcode_id)
    else:
        logger.info("Communicating with Comms Module")
        response = GET_Req.GET_Request(MaxParkCommModule_IP,
                                       MaxParkCommModule_Port,
                                       SOCKET_TIMEOUT,
                                       SEND_BUFFER_SIZE,
                                       RECV_BUFFER_SIZE,
                                       original_barcode_id)

    logger.info("response : {0}".format(response))
    logger.info("Send to PNS Server")

    return_json = {
        'err_code': response[0],
        'odata': response[1],
        'ticket': response[2],
        'entry': response[3],
        'exit': response[4],
        'value': response[5]
    }

    returnHttpStatus = 200
    if response[0] != ERROR_Code.errSuccess:
        returnHttpStatus= 400

    return jsonify(return_json), returnHttpStatus



#init by hadi din
@app.route('/localagent/v1/push_plate_no', methods=['POST'])
def push_plate_no():

    print(request.data)
    plate_no = request.json['body']["result"]["PlateResult"]["license"]
    camera_id = request.json['body']["vzid"]["sn"]
    base64img = request.json['body']["result"]["PlateResult"]["imageFile"]

    datenow=time.strftime("%Y%m%d%H%M")

    cam_mapping = json.loads(camera_mapping_conf)

    total_cam=len(cam_mapping['camera_mapping'])
    for x in range(total_cam):
        # lpr_sn=cam_mapping['camera_mapping'][x]['lpr_sn']
        if(camera_id==cam_mapping['camera_mapping'][x]['lpr_sn']):
            maxpark_cam_id=cam_mapping['camera_mapping'][x]['maxpark_cam_id']

    picture_name = lpr_ftp_folder + "/" + datenow + maxpark_cam_id + plate_no + ".jpg"
    # picture_name = datenow + maxpark_cam_id + plate_no + ".jpg"

    print("Plateno=" + plate_no + "<<>>Camera_sn=" + camera_id+"<<>>Maxpark_camera_id="+maxpark_cam_id)
    imgdata=base64.b64decode(base64img)
    filename = picture_name  # I assume you have a way of picking unique filenames
    with open(filename, 'wb') as f:
        f.write(imgdata)

    # session = ftplib.FTP('example.com', 'username', 'password')
    # file = open('cup.mp4', 'rb')  # file to send
    # session.storbinary('STOR ' + 'cup.mp4', file)  # send the file
    # file.close()  # close file and FTP
    # session.quit()
    print(filename)

    # filename = 'exampleFile.txt'
    ftp = FTP(lpr_ftp_server)
    ftp.login(user=lpr_ftp_user, passwd=lpr_ftp_pswd)
    # ftp.storbinary('STOR ' + filename, open(filename, 'rb'))
    ftp.storbinary('STOR ' + filename, open(filename, 'rb'))
    ftp.quit()




    logger.info("")
    logger.info("--- v1_push plate no ---")
    logger.info("Plateno=" + plate_no + "<<>>Camera_sn=" + camera_id+"<<>>Maxpark_camera_id="+maxpark_cam_id)

    logger.info("Communicating with Comms Module")
    response = PUSH_plate_no.push_plate_no(MaxParkCommModule_IP,
                                     MaxParkCommModule_Port,
                                     SOCKET_TIMEOUT,
                                     SEND_BUFFER_SIZE,
                                     RECV_BUFFER_SIZE,
                                     plate_no)
    logger.info("response : {0}".format(response))

    logger.info("Send to PNS Server")

    return_json = {
        'plate_no': plate_no,
        'camera_sn': camera_id,
        'maxpark_cam_id': maxpark_cam_id,
        'filename': filename,
        'ftp_server': lpr_ftp_server


    }

    returnHttpStatus = 200

    return jsonify(return_json), returnHttpStatus




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("EXCEPTION: KeyboardInterrupt")

    finally:
        # logger.critical(
        #     "\n --- Application finally ends. This is not really Critical. --- \n")
        # logging.shutdown()
        # logger.info("FINALLY: Program Ended")
        print("FINALLY: Program Ended")
