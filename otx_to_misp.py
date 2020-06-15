from datetime import datetime, timedelta

from OTXv2 import OTXv2
from pandas.io.json import json_normalize

from config import MISP_KEY, OTX_KEY

import requests
from pymisp import PyMISP
import time
import json


# service parameters
misp_url = ''


def readTimestamp():
        fname = "timestamp"
        f = open(fname, "r")
        mtimestamp = f.read()
        f.close()
        return mtimestamp

def saveTimestamp(timestamp=None):
        mtimestamp = timestamp
        if not timestamp:
                mtimestamp = datetime.now().isoformat()

        fname = "timestamp"
        f = open(fname, "w")
        f.write(mtimestamp)
        f.close()


if __name__ == "__main__":

    otx = OTXv2(OTX_KEY)

    # The getall() method downloads all the OTX pulses and their assocciated indicators of compromise (IOCs) from your account.
    # This includes all of the following:
    # - OTX pulses to which you subscribed through the web UI
    # - Pulses created by OTX users to whom you subscribe
    # - OTX pulses you created.
    # If this is the first time you are using your account, the download includes all pulses created by AlienVault.
    # All users are subscribed to these by default.

    mtime = readTimestamp()
    pulses = otx.getsince(mtime)
    print("Retrived %d pulses" % len(pulses))

    # Summary of information retrieved from OTX
    for p in pulses:
        print(json.dumps(p, indent=2, sort_keys=True))
