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

from config import OTX_KEY, MISP_URL, MISP_KEY

import requests
from pymisp import ExpandedPyMISP, PyMISP
from pymisp import MISPEvent, MISPOrganisation, MISPObject
import time
import datetime
import json
import argparse


misp_url = MISP_URL
misp_key = MISP_KEY
misp_verifycert = False

def init(url, key):
    return ExpandedPyMISP(url, key, misp_verifycert, debug=False)

def get_orgc(name):
    misp = init(misp_url, misp_key)
    orgc = misp.get_organisation(name)
    return orgc

def pulse_to_misp(pulse):
    misp = init(MISP_URL, MISP_KEY)

    misp_event = MISPEvent()
    misp_event.info = pulse['author_name'] + ' | ' + pulse['name']
    for tag in pulse['tags']:
        misp_event.add_tag(tag)
    misp_org = MISPOrganisation()
    misp_org.name = 'AlienVault'
    misp_org.id = misp.get_organisation('AlienVault')['Organisation']['id']
    misp_org.uuid = misp.get_organisation('AlienVault')['Organisation']['uuid']
    misp_event.Orgc = misp_org
    misp_event.published = False
    misp_event.date = datetime.datetime.strptime(pulse['modified'], '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%d')

    for indicator in pulse['indicators']:
        """
        u'FileHash-SHA256',
        u'domain',
        u'URL',
        u'hostname',
        u'URI',
        u'email',
        u'FileHash-SHA1',
        u'Mutex',
        u'IPv4',
        u'FileHash-MD5']
        """
        if indicator['type'] == 'URL':
            if indicator['is_active'] == 1:
                url_object = MISPObject(indicator['title'])
                url_object.add_attribute("Date-created", type="datetime", value=indicator['created'], disable_correlation=True , to_ids=False)
                url_object.add_attribute("URL", type="url", value=indicator['indicator'], disable_correlation=False , to_ids=True)
                misp_event.add_object(url_object)

    return misp_event

def main():
    otx = OTXv2(OTX_KEY)

    parser = argparse.ArgumentParser(
        description='Help usage')
    parser.add_argument('--max_age', type=int, help='Number of days to fetch')
    args = parser.parse_args()

    if (args.max_age):
        pasttime = datetime.datetime.now() - datetime.timedelta(days = args.max_age)
        pasttime_beginning = datetime.datetime(pasttime.year, pasttime.month, pasttime.day,0,0,0,0)
        pasttime_beginning_time = int(time.mktime(pasttime_beginning.timetuple()))
        x_from = pasttime_beginning_time
        mtime=datetime.datetime.utcfromtimestamp(x_from).strftime('%Y-%m-%d %H:%M:%S')
    else:
        pasttime = datetime.datetime.now() - datetime.timedelta(days = 1)
        pasttime_beginning = datetime.datetime(pasttime.year, pasttime.month, pasttime.day,0,0,0,0)
        pasttime_beginning_time = int(time.mktime(pasttime_beginning.timetuple()))
        x_from = pasttime_beginning_time
        mtime=datetime.datetime.utcfromtimestamp(x_from).strftime('%Y-%m-%d %H:%M:%S')

    pulses = otx.getsince(mtime)
    print("Retrieved {} pulses".format(len(pulses)))

    # Summary of information retrieved from OTX
    counter=0
    for pulse in pulses:
        if counter<1:
            print(json.dumps(pulse, indent=2, sort_keys=True))

            misp = init(MISP_URL, MISP_KEY)

            try:
                misp_event=pulse_to_misp(pulse)
                counter+=1
            except KeyError as err:
                misp_event = 0
            if misp_event != 0:
                misp.add_event(misp_event)
        else:
            break


if __name__ == "__main__":
    main()
