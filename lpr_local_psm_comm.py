import requests
import logging
import json
import base64
import mysql.connector
from mysql.connector import Error
from flask import request
from time import gmtime, strftime
import flask

logger = logging.getLogger(__name__)  # module-level logger, so that filename is printed in log.

def push_log(response,camera_sn,plate_no,small_image,big_image,db_host,db_username,db_pswd,db_name,text2display):

    #camera extra info
    check_camera_extra_info = check_camera_db_info(camera_sn, db_host, db_username, db_pswd, db_name)
    # xx="'"+check_camera_extra_info+"'"
    print(check_camera_extra_info)
    python_obj = json.loads(check_camera_extra_info)

    in_out_flag = python_obj["in_out_flag"]
    lane_name = python_obj["lane_name"]
    lane_id = python_obj["lane_id"]

    # entry success
    if (response == 'SN'):
        check_result = 6
        is_success = 1
        is_season_subscriber = 1
        parking_type = 1

    # exit success
    if (response == 'SX'):
        check_result = 9
        is_success = 1
        is_season_subscriber = 1
        parking_type = 1

    # anti passback error
    if (response == 'SA'):
        if (in_out_flag == 0):
            check_result = 4 #entry passback
            is_success = 0
        if (in_out_flag == 1):
            check_result = 7 #exit passback
            is_success = 0
        is_season_subscriber = 9 #unknown
        parking_type = 9

    # Expired Registration Error
    if (response == 'SE'):
        check_result = 3
        is_success = 0
        is_season_subscriber = 1
        parking_type = 1

    # Blacklisted Registration
    if (response == 'SB'):
        check_result = 5
        is_success = 0
        is_season_subscriber = 1 #subcribe but got blacklist by operator
        parking_type = 1

    # normal ticket
    if (response == 'TK'):#normal ticket
        #check_result = 6
        if (in_out_flag == 0):
            check_result = 6
        if (in_out_flag == 1):
            check_result = 9
        is_success = 1
        is_season_subscriber = 0
        parking_type = 0

    insert_to_db(camera_sn,plate_no,small_image,big_image,db_host,db_username,db_pswd,db_name,in_out_flag,check_result,is_success,is_season_subscriber,parking_type,lane_id,text2display)

    # return return_json

def check_camera_db_info(camera_sn,db_host,db_username,db_pswd,db_name):
    try:
        mySQLConnection = mysql.connector.connect(host=db_host,
                                                  database=db_name,
                                                  user=db_username,
                                                  password=db_pswd)
        cursor = mySQLConnection.cursor(prepared=True)
        sql_select_query = """select in_out_flag,name,id from psm_lane_config where camera_sn = %s"""
        cursor.execute(sql_select_query, (camera_sn,))
        records = cursor.fetchall()
        for row in records:
            in_out_flag = int(row[0].decode("utf-8"))
            lane_name = row[1].decode("utf-8")
            lane_id = row[2]

            # print(row[2])

    except mysql.connector.Error as error:
        print("Failed to get record from database: {}".format(error))
    finally:
        # closing database connection.
        if (mySQLConnection.is_connected()):
            cursor.close()
            mySQLConnection.close()
            print("connection is closed")

    return_json = {
        "in_out_flag": in_out_flag,
        "lane_name": lane_name,
        "lane_id": lane_id
    }

    return json.dumps(return_json)


def insert_to_db(camera_sn,plate_no,small_image,big_image,db_host,db_username,db_pswd,db_name,in_out_flag,check_result,is_success,is_season_subscriber,parking_type,lane_id,failed_remark):
    datenow = strftime("%Y-%m-%d %H:%M:%S")
    try:
        connection = mysql.connector.connect(host=db_host,
                                                  database=db_name,
                                                  user=db_username,
                                                  password=db_pswd)
        sql_insert_query = """insert into psm_entry_log set lane_id= %s, camera_sn= %s, plate_no= %s, small_picture= %s, big_picture= %s, in_out_flag= %s, is_success= %s, check_result= %s, is_season_subscriber= %s, parking_type= %s, failed_remark= %s, create_time= %s """

        cursor = connection.cursor()
        cursor.execute(sql_insert_query, (lane_id,camera_sn,plate_no,small_image,big_image,in_out_flag,is_success,check_result,is_season_subscriber,parking_type,failed_remark,datenow))
        connection.commit()
    except mysql.connector.Error as error:
        print("Failed to get record from database: {}".format(error))
    finally:
        # closing database connection.
        if (connection.is_connected()):
            cursor.close()
            connection.close()

