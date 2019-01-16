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
import COMM_LISTENER
import kp_catch_trx
import lpr_push_display
import base64
import time
import ftplib
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
# MaxParkCommModule_IP = config['CommModule']['CommModule_IP']  # IP Address of MaxPark Comm Module
# MaxParkCommModule_Port = int(config['CommModule']['CommModule_Port'])  # Port used
SOCKET_TIMEOUT = int(config['CommModule']['SOCKET_TIMEOUT'])  # timeout units in seconds
SEND_BUFFER_SIZE = int(config['CommModule']['SEND_BUFFER_SIZE'])
RECV_BUFFER_SIZE = int(config['CommModule']['RECV_BUFFER_SIZE'])
ENABLE_PERIODIC_IDLE_MSG = int(config['CommModule']['ENABLE_PERIODIC_IDLE_MESSAGE'])
IDLE_TASK_TIMER = int(config['CommModule']['IDLE_TASK_TIMER']) # run Idle task every x minutes -> units in minutes



# General Parameters
#===================
NON_PING_PARKING_SERVER = "101010101010"
g_intIs_Demo_Mode = None  # Bypass the Comms Module for certain commands & removes need for real Tickets.
g_PNSAppServices_IPWhiteList = "" # IP White List for PNS App Services.


# Lpr Parameter
#===================
camera_mapping_conf = config['LPR_MODULE']['Camera_list']
lpr_ftp_server = config['LPR_MODULE']['lpr_ftp_server']
lpr_ftp_user = config['LPR_MODULE']['lpr_ftp_user']
lpr_ftp_pswd = config['LPR_MODULE']['lpr_ftp_pswd']
lpr_ftp_folder = config['LPR_MODULE']['lpr_ftp_folder']
lpr_ftp_temp_source = config['LPR_MODULE']['lpr_ftp_temp_source']
LPR_CommModule_IP = config['LPR_MODULE']['LPR_CommModule_IP']
LPR_CommModule_Port = int(config['LPR_MODULE']['LPR_CommModule_Port'])
LPR_CommModule_IP_Receive = config['LPR_MODULE']['LPR_CommModule_IP_Receive']
LPR_CommModule_Port_Receive = int(config['LPR_MODULE']['LPR_CommModule_Port_Receive'])
lpr_server_url = config['LPR_MODULE']['lpr_server_url']
txtSN = config['LPR_MODULE']['lpr_led_text_SN']
txtSX = config['LPR_MODULE']['lpr_led_text_SX']
txtSA = config['LPR_MODULE']['lpr_led_text_SA']
txtSE = config['LPR_MODULE']['lpr_led_text_SE']
txtSB = config['LPR_MODULE']['lpr_led_text_SB']
txtTK = config['LPR_MODULE']['lpr_led_text_TK']


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
    # response = COMM_LISTENER.COMM_LISTENER(LPR_CommModule_IP_Receive,
    #                                        LPR_CommModule_Port_Receive,
    #                                        SOCKET_TIMEOUT,
    #                                        SEND_BUFFER_SIZE,
    #                                        RECV_BUFFER_SIZE)

    os.chdir(os.path.dirname(__file__))
    print(os.getcwd())
    logger.info('===========current directory')
    logger.info(os.getcwd())

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



#init by hadi din


def check_pns_whitelisted_ip():
    if (request.remote_addr not in g_PNSAppServices_IPWhiteList):
        logger.warning("Rejected following IP not in the white list= " + request.remote_addr)
        abort(403)


@app.route('/localagent/v1/push_plate_no', methods=['POST'])
def push_plate_no():

    # print(request.data)
    check_pns_whitelisted_ip()

    push_id = request.json['id']
    plate_no = request.json['body']["result"]["PlateResult"]["license"]
    #remove white space from plate number
    plate_no=plate_no.replace(" ", "")
    camera_id = request.json['body']["vzid"]["sn"]
    base64img = request.json['body']["result"]["PlateResult"]["imageFile"]

    datenow=time.strftime("%Y%m%d")

    cam_mapping = json.loads(camera_mapping_conf)

    total_cam=len(cam_mapping['camera_mapping'])
    global x
    for x in range(total_cam):

        # lpr_sn=cam_mapping['camera_mapping'][x]['lpr_sn']
        if(camera_id==cam_mapping['camera_mapping'][x]['lpr_sn']):
            maxpark_cam_id=cam_mapping['camera_mapping'][x]['maxpark_cam_id']
            print("xxxxxx"+maxpark_cam_id)


    picture_name = lpr_ftp_temp_source + "/" + datenow + maxpark_cam_id + plate_no + ".jpg"
    print(picture_name)
    # picture_name = datenow + maxpark_cam_id + plate_no + ".jpg"

    print("Plateno=" + plate_no + "<<>>Camera_sn=" + camera_id+"<<>>Maxpark_camera_id="+maxpark_cam_id)
    imgdata=base64.b64decode(base64img)
    filename = picture_name  # I assume you have a way of picking unique filenames




    with open(filename, 'wb') as f:
        f.write(imgdata)
        f.close()

    # session = ftplib.FTP('example.com', 'username', 'password')
    # file = open('cup.mp4', 'rb')  # file to send
    # session.storbinary('STOR ' + 'cup.mp4', file)  # send the file
    # file.close()  # close file and FTP
    # session.quit()
    print(filename)

    # upload picture to ftp folder
    logger.info("===================Starting upload file to ftp folder==============")
    logger.info(filename)

    try:
        ftp = FTP(lpr_ftp_server)
        ftp.login(user=lpr_ftp_user, passwd=lpr_ftp_pswd)
        # ftp.storbinary('STOR ' + filename, open(filename, 'rb'))
        ftp.storbinary('STOR ' + filename, open(filename, 'rb'))
        ftp.quit()

        #remove temp file after upload to ftp success
        try:
            os.remove(filename)
        except os.error as e:
            logger.error("Failed to delete temp file %s" % e)

    except ftplib.error_perm as e:
        logger.error("Failed to connect to ftp server using given info host=%s , username=%s , password=%s ,folder=%s , %s" % (lpr_ftp_server,lpr_ftp_user,lpr_ftp_pswd,lpr_ftp_folder,e) )

    # print("lpr_ftp_server=" + lpr_ftp_server + "<<>>lpr_ftp_user=" + lpr_ftp_user + "<<>>lpr_ftp_pswd=" + lpr_ftp_pswd)
    # session = ftplib.FTP(lpr_ftp_server, lpr_ftp_user, lpr_ftp_pswd)
    # file = open(filename, 'rb')  # file to send
    # session.storbinary('STOR ' + filename, file)  # send the file
    # file.close()  # close file and FTP
    # session.quit()


    # time.sleep(5)
    logger.info("")
    logger.info("--- v1_push plate no ---")
    logger.info("Plateno=" + plate_no + "<<>>Camera_sn=" + camera_id+"<<>>Maxpark_camera_id="+maxpark_cam_id)

    logger.info("Communicating with Comms Module")
    response = PUSH_plate_no.push_plate_no(LPR_CommModule_IP,
                                           LPR_CommModule_Port,
                                            SOCKET_TIMEOUT,
                                            SEND_BUFFER_SIZE,
                                            RECV_BUFFER_SIZE,
                                            plate_no,maxpark_cam_id)
    logger.info("response : {0}".format(response))

    if(response == 'false'):
        return_json = {
            'err_code': 'LPR401',
            'plate_no': plate_no,
            'camera_sn': camera_id,
            'maxpark_cam_id': maxpark_cam_id,
            'filename': filename,
            'ftp_server': lpr_ftp_server
        }
        returnHttpStatus = 400
        return jsonify(return_json), returnHttpStatus
    else:
        # logger.info("Send to PNS Server")

        service='TCS'

        if (response == 'SN'):
            text2display = txtSN
        if (response == 'SX'):
            text2display = txtSX
        if (response == 'SA'):
            text2display = txtSA
        if (response == 'SE'):
            text2display = txtSE
        if (response == 'SB'):
            text2display = txtSB
        if (response == 'TK'):
            text2display = txtTK
            service = 'TCN'

        text2display=text2display.replace("<plate_no>", plate_no)

        data = base64.b64encode(text2display.encode())
        data_utf = data.decode("utf-8")


        #push to device operation
        textdic = json.loads(text2display)
        lpr_push_display.push_display(lpr_server_url, textdic, push_id, camera_id)

        #send data to kiplepark cloud
        # kp_catch_trx.catch_trx('https://sandbox.kiplepark.com',response,service,plate_no,'SIG0030',camera_id)


        return_json =   {
                            "operation": [
                                {
                                    "type": "open_gate"
                                },
                                {
                                    "type": "led_display",
                                    "msg": textdic
                                }
                            ]
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

