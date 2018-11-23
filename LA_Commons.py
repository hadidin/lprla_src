# Copyright 2018 kiplePark
# init by hadi din
# Please refer to license.txt for license terms.
# 
# Description: Place common functions in this file.
#
#

import logging

logger = logging.getLogger(__name__)  # module-level logger, so that filename is printed in log.


CHECKSUM_OFFSET = 0x20 # 2017Sep26: New Algorithm to solve D012 error when checkcsum = 0x03 which is ETX.

#
# Calculates the numerical value of the checksum from the CMD and all DATA bytes.
#
# 4.2.1c
#CHECKSUM = 1 byte
#= xor of CMD and all DATA bytes
#
# 2017Sep26: New Algorithm to solve D012 error when checkcsum = 0x03 which is ETX.
#If value is less than 0x20 then add 0x20
#Eg. If xor of CMD and DATA results in 0x0A, then CHECKSUM = 0x2A
#
def calculate_checksum(command_byte, list_of_data_bytes ):
    return_numerical_checksum = 0
    i = 0
    while i < len(list_of_data_bytes):
        return_numerical_checksum = return_numerical_checksum ^ list_of_data_bytes[i]
        i += 1
    # while

    return_numerical_checksum = return_numerical_checksum ^ ord(command_byte)

    # 2017Sep26: START : New Algorithm to solve D012 error when checkcsum = 0x03 which is ETX.
    # If value is less than 0x20 then add 0x20
    if(return_numerical_checksum < CHECKSUM_OFFSET ):
        return_numerical_checksum += CHECKSUM_OFFSET
    # 2017Sep26: END

    logger.info("Checksum (numerical= " + hex(return_numerical_checksum))
    return return_numerical_checksum

def calculate_checksumV2(str_command_bytes, list_of_data_bytes ):
    i = 1
    while i < len(str_command_bytes):
        list_of_data_bytes.insert(0, ord(str_command_bytes[i])) # Append would work for checksum, as order not important.
        i += 1
    # while

    return calculate_checksum(str_command_bytes[0], list_of_data_bytes)

def calculate_checksum_2chrcmd(command_byte, list_of_data_bytes ):
    # return_numerical_checksum = 0
    # i = 0
    # while i < len(list_of_data_bytes):
    #     return_numerical_checksum = return_numerical_checksum ^ list_of_data_bytes[i]
    #     i += 1
    # # while
    # return_numerical_checksum = return_numerical_checksum ^ ord(command_byte[0])


    s=command_byte+list_of_data_bytes
    sum = 0
    for c in s:
        sum += ord(c)
    sum = -(sum % 256)
    calc_checksum= '%2X' % (sum & 0xFF)

    print(calc_checksum)


    logger.info("Checksum (numerical= " + hex(calc_checksum))
    return calc_checksum
