import requests
import logging
import json
from datetime import timedelta, datetime

logger = logging.getLogger(__name__)  # module-level logger, so that filename is printed in log.

def catch_trx(kp_server_url,response,service,plate_no,site_id,camera_id):
    url = kp_server_url + '/api/device/operation'

    # Return a Bool.
    RETURN_STATUSBOOL = True  # Assume success so not need to change until error.

    # Since using JSON in request to Server, it will auto set
    # Content-Type in the header to application/json.
    # http://docs.python-requests.org/en/master/user/quickstart/#custom-headers
    json_payload =  {
                        "response" : response,
                        "service": service,
                        "plate_no": plate_no,
                        "site_id": site_id,
                        "camera_id": camera_id
                    }
    logger.debug(json_payload)
    my_headers = {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZDA2YmE4My05YTllLTQ3N2EtYjNjMy1jYjM5ZDU1NzYxNDgiLCJ1bmlxdWVfbmFtZSI6ImRkMDZiYTgzLTlhOWUtNDc3YS1iM2MzLWNiMzlkNTU3NjE0OCIsImp0aSI6IjdiMmQ4YWRhLWRiNzYtNDJlNC1iZDZjLWRjM2YxMmY0YjgyOSIsImlhdCI6IjE1NDI4MDM0NjMuMzc0MTgiLCJBY2NvdW50OklkIjoiZGQwNmJhODMtOWE5ZS00NzdhLWIzYzMtY2IzOWQ1NTc2MTQ4IiwiQWNjb3VudDpVc2VyTmFtZSI6InNhdHlhLnNyZWVAZ3JlZW5wYWNrZXQuY29tIiwiQWNjb3VudDpUYWciOiJLaXBsZVBheSIsIlVNUzpUb2tlbiI6InlQUHd4cTdCRXcyc3dYNFdrbkp3b1Z5alVGcWxvcHRoIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiVVNFUiIsIm5iZiI6MTU0Mjc3NDY2MywiZXhwIjoxNTQzMjA2NjY1LCJpc3MiOiJLaXBsZSIsImF1ZCI6IktpcGxlIn0.pU2Ey6GKHpY0BzqiWZlLl0pxPIPGjel3FjrDgoif4q8'}

    try:
        r = requests.post(url, json=json_payload, headers=my_headers, timeout=4)
        # r = requests.put(url, json=json_payload, timeout=4)
        # logger.info("send put method to LPR" + json.dumps(json_payload, indent=4, sort_keys=True))
        logger.info("send post method to kp url=%s , body=%s" % (url, json.dumps(json_payload)))
    except requests.exceptions.ConnectionError:
        logger.warning("Timeout connecting to kiple Server")
        RETURN_STATUSBOOL = False
        return RETURN_STATUSBOOL
    except requests.exceptions.Timeout:
        logger.warning("Timeout reading from kiple Server")
        RETURN_STATUSBOOL = False
        return RETURN_STATUSBOOL

    logger.info("Status Code= " + str(r.status_code))