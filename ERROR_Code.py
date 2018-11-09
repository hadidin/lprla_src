# Copyright 2018 kiplePark
# init by hadi din
# Please refer to license.txt for license terms.
# 
# Description: Error codes that are returned by the functions.
#
#

PREFIX_FOR_PNS = "PNS_" # Prefix to indicate that this is our Error Codes.

errSuccess = PREFIX_FOR_PNS + "OK" # Success.
errGeneral = PREFIX_FOR_PNS + "0" # General error. Try using others before this.
errParamLength = PREFIX_FOR_PNS + "1" # E.g. Length of ID not correct. Currently, no way of knowing which paramm.


errCommunicationGeneral = PREFIX_FOR_PNS + "100" # Other network errors not classified below.
errNetworkSocket = PREFIX_FOR_PNS + "101" # E.g. Cannot create socket.
errCommunicationTimeout = PREFIX_FOR_PNS + "102" # E.g. Connection or transmission timeouts.
errCommunicationChecksumAndFormat = PREFIX_FOR_PNS + "103" # E.g. Maybe after version upgrade.
errCommunicationFTPServer = PREFIX_FOR_PNS + "104" # FTP Server related Errors. E.g. Permissions mis-config.
errCommunicationS3Bucket = PREFIX_FOR_PNS + "105" # S3 Bucket related Errors. E.g. Permissions mis-config.

errLocalFileSystemGeneral = PREFIX_FOR_PNS + "200" # Other general local file system operation errors.

errNoDataFoundGeneral = PREFIX_FOR_PNS + "300" # No data found for parameter(s) requested.


# For Parking Provider Errors, please refer to the PDFs. These should not have the "PNS_" Prefix.