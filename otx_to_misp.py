"""
# The getall() method downloads all the OTX pulses and their associated
    # indicators of compromise (IOCs) from your account.
    # This includes all of the following:
    # - OTX pulses to which you subscribed through the web UI
    # - Pulses created by OTX users to whom you subscribe
    # - OTX pulses you created.
    # If this is the first time you are using your account, the download
      includes all pulses created by AlienVault.
    # All users are subscribed to these by default.
"""

from datetime import datetime, timedelta

from OTXv2 import OTXv2
from pandas.io.json import json_normalize

from config import MISP_KEY, OTX_KEY

import requests
from pymisp import PyMISP
import time
import json


misp_url = ''


def read_timestamp():
    with open("timestamp") as input_file:
        m_timestamp = input_file.read()
        return m_timestamp


def save_timestamp(timestamp=None):
    m_timestamp = timestamp
    if not timestamp:
        m_timestamp = datetime.now().isoformat()

    with open("timestamp", "w") as output_file:
        output_file.write(m_timestamp)


def main():
    otx = OTXv2(OTX_KEY)

    try:
        mtime = read_timestamp()
    except FileNotFoundError:
        save_timestamp()
        mtime = read_timestamp()

    pulses = otx.getsince(mtime)
    print("Retrieved {} pulses".format(len(pulses)))

    # Summary of information retrieved from OTX
    for p in pulses:
        print(json.dumps(p, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
