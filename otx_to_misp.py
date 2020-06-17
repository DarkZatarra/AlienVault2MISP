import argparse
import json
import time

from datetime import datetime, timedelta

from OTXv2 import OTXv2
from pymisp import (
    ExpandedPyMISP,
    MISPEvent,
    MISPOrganisation,
    MISPObject
)

from config import OTX_KEY, MISP_URL, MISP_KEY


def init(url, key):
    return ExpandedPyMISP(
        url=url,
        key=key,
        ssl=False,
        debug=False
    )


def get_orgc(name):
    misp = init(MISP_URL, MISP_KEY)
    orgc = misp.get_organisation(name)
    return orgc


def add_mips_attribute(pulse, pulse_attr, mips_object_name, attr_rel, attr_type, mips_event):
    if pulse[pulse_attr]:
        misp_object = MISPObject(mips_object_name)
        for value in pulse[pulse_attr]:
            misp_object.add_attribute(
                attr_rel,
                type=attr_type,
                value=value,
                disable_correlation=True,
                to_ids=False
            )
        mips_event.add_object(misp_object)


def pulse_to_misp(misp, pulse):
    misp_event = MISPEvent()
    misp_event.info = '{} | {}'.format(pulse['author_name'], pulse['name'])

    for tag in pulse['tags']:
        misp_event.add_tag(tag)

    misp_org = MISPOrganisation()
    misp_org.name = 'AlienVault'
    misp_org.id = misp.get_organisation('AlienVault')['Organisation']['id']
    misp_org.uuid = misp.get_organisation('AlienVault')['Organisation']['uuid']
    misp_event.Orgc = misp_org
    misp_event.published = True
    misp_event.date = datetime.strptime(pulse['modified'], '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%d')

    add_mips_attribute(pulse, 'targeted_countries', 'Targeted Countries', 'regions', 'target-location', misp_event)
    add_mips_attribute(pulse, 'industries', 'Sectors', 'sectors', 'text', misp_event)
    add_mips_attribute(pulse, 'adversary', 'Adversary', 'Threat-actor', 'threat-actor', misp_event)
    add_mips_attribute(pulse, 'references', 'References', 'external-references', 'link', misp_event)

    if pulse['tlp']:
        misp_event.add_tag('tlp:{}'.format(pulse['tlp']))
    
    verify_list = []   
    objects_created = []

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

        # Here come the type and active conditions
        if indicator['is_active'] == 1:
            if indicator['type'] == 'FileHash-SHA256':
                if 'sha256' not in verify_list:
                    sha256_object = MISPObject('SHA256 hashes')
                    verify_list.append('sha256')
                sha256_object.add_attribute(
                    "sha256",
                    type="sha256",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(sha256_object)

            if indicator['type'] == 'domain':
                if 'domain' not in verify_list:
                    domain_object = MISPObject('Domains')
                    verify_list.append('domain')
                domain_object.add_attribute(
                    "domain",
                    type="domain",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(domain_object)

            if indicator['type'] == 'URL':
                if 'url' not in verify_list:
                    url_object = MISPObject('URLs')
                    verify_list.append('url')
                url_object.add_attribute(
                    "url",
                    type="url",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(url_object)

            if indicator['type'] == 'hostname':
                if 'hostname' not in verify_list:
                    hostname_object = MISPObject('Hostnames')
                    verify_list.append('hostname')
                hostname_object.add_attribute(
                    "hostname",
                    type="hostname",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(hostname_object)

            if indicator['type'] == 'URI':
                if 'uri' not in verify_list:
                    uri_object = MISPObject('URIs')
                    verify_list.append('uri')
                uri_object.add_attribute(
                    "uri",
                    type="uri",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(uri_object)

            if indicator['type'] == 'email':
                if 'email' not in verify_list:
                    email_object = MISPObject('Emails')
                    verify_list.append('email')
                email_object.add_attribute(
                    "from",
                    type="email-src",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(email_object)

            if indicator['type'] == 'FileHash-SHA1':
                if 'sha1' not in verify_list:
                    sha1_object = MISPObject('SHA1 hashes')
                    verify_list.append('sha1')
                sha1_object.add_attribute(
                    "sha1",
                    type="sha1",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(sha1_object)

            if indicator['type'] == 'Mutex':
                if 'mutex' not in verify_list:
                    mutex_object = MISPObject('Mutex')
                    verify_list.append('mutex')
                mutex_object.add_attribute(
                    "mutex",
                    type="mutex",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(mutex_object)

            if indicator['type'] == 'IPv4':
                if 'ipv4' not in verify_list:
                    ipv4_object = MISPObject('IPs')
                    verify_list.append('ipv4')
                ipv4_object.add_attribute(
                    "ip-dst",
                    type="ip-dst",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(ipv4_object)

            if indicator['type'] == 'FileHash-MD5':
                if 'md5' not in verify_list:
                    md5_object = MISPObject('MD5 hashes')
                    verify_list.append('md5')
                md5_object.add_attribute(
                    "md5",
                    type="md5",
                    value=indicator['indicator'],
                    disable_correlation=False,
                    to_ids=True
                )
                objects_created.append(md5_object)

    for object_created in objects_created:
        misp_event.add_object(object_created)

    # And finally we attach the object to the event

    return misp_event


def calculate_time(days=1):
    pasttime = datetime.now() - timedelta(days=days)
    pasttime_beginning = datetime(pasttime.year, pasttime.month, pasttime.day, 0, 0, 0, 0)
    x_from = int(time.mktime(pasttime_beginning.timetuple()))
    return datetime.utcfromtimestamp(x_from).strftime('%Y-%m-%d %H:%M:%S')


def main():
    otx = OTXv2(OTX_KEY)

    parser = argparse.ArgumentParser(description='Help usage')
    parser.add_argument('--max_age', type=int, help='Number of days to fetch')
    args = parser.parse_args()

    if args.max_age:
        mtime = calculate_time(days=args.max_age)
    else:
        mtime = calculate_time()

    pulses = otx.getsince(mtime)
    print("Retrieved {} pulses".format(len(pulses)))

    # Summary of information retrieved from OTX
    for pulse in pulses:
        print(json.dumps(pulse, indent=2, sort_keys=True))

        misp = init(MISP_URL, MISP_KEY)

        try:
            misp_event = pulse_to_misp(misp, pulse)
            misp.add_event(misp_event)
        except KeyError as err:
            print(str(err))


if __name__ == "__main__":
    main()
