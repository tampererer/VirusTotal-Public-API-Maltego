# -*- coding: utf-8 -*-
from MaltegoTransform import *
import requests
import json
import random

apiurl = "https://www.virustotal.com/vtapi/v2/"
apikey = [
        "<Your API Key>", 
        "<Your API Key>", 
        "<Your API Key>", 
#        "<Your API Key>", 
#        "<Your API Key>"
        ]
apikey = random.choice(apikey)

# domain_reports
def domain_reports():
    try:
        params = {'apikey': apikey, 'domain': data}
        response = requests.get(apiurl + 'domain/report', params=params)
        response_json = response.json()
        respcode = int(response_json['response_code'])
#        print apikey
#        print response_json

        if respcode == 1:
            if 'domain_siblings' in response_json:
                for item in response_json['domain_siblings']:
                    me = mt.addEntity("maltego.Domain", '%s' % item)
                    me.setLinkLabel("VT domain_siblings")
            if 'detected_communicating_samples' in response_json:
                for item in response_json['detected_communicating_samples']:
                    me = mt.addEntity("maltego.Hash", '%s' % item['sha256'])
                    me.setLinkLabel("VT communicating_hash" + ", positives:" + str(item['positives']) + "/" + str(item['total']))
            if 'detected_referrer_samples' in response_json:
                for item in response_json['detected_referrer_samples']:
                    me = mt.addEntity("maltego.Hash", '%s' % item['sha256'])
                    me.setLinkLabel("VT referrer_samples" + ", positives:" + str(item['positives']) + "/" + str(item['total']))
            if 'detected_downloaded_samples' in response_json:
                for item in response_json['detected_downloaded_samples']:
                    me = mt.addEntity("maltego.Hash", '%s' % item['sha256'])
                    me.setLinkLabel("VT downloaded_hash" + ", positives:" + str(item['positives']) + "/" + str(item['total']))
            if 'detected_urls' in response_json:
                for item in response_json['detected_urls']:
                    me = mt.addEntity("maltego.URL", '%s' % item['url'])
                    me.setLinkLabel("VT positives:" + str(item['positives']) + "/" + str(item['total']))
            if 'subdomains' in response_json:
                for item in response_json['subdomains']:
                    me = mt.addEntity("maltego.Domain", '%s' % item)
                    me.setLinkLabel("VT subdomain")
            if 'resolutions' in response_json:
                for item in response_json['resolutions']:
                    me = mt.addEntity("maltego.IPv4Address", '%s' % item['ip_address'])
                    me.setLinkLabel("VT, " + item['last_resolved'])
            if 'categories' in response_json:
                for item in response_json['categories']:
                    me = mt.addEntity("maltego.Phrase", '%s' % item)
                    me.setLinkLabel("VT category")
            if 'Webutation domain info' in response_json:
                item = response_json['Webutation domain info']
                me = mt.addEntity("maltego.Phrase", '%s' % "Verdict:" + item['Verdict'] + ", SafetyScore:" + str(item['Safety score']))
                me.setLinkLabel("VT Webutation domain info")

    except:
        pass

    return mt

# ip_reports
def ip_reports():
    try:
        params = {'apikey': apikey, 'ip': data}
        response = requests.get(apiurl + 'ip-address/report', params=params)
        response_json = response.json()
        respcode = int(response_json['response_code'])

        if respcode == 1:
            if 'detected_communicating_samples' in response_json:
                for item in response_json['detected_communicating_samples']:
                    me = mt.addEntity("maltego.Hash", '%s' % item['sha256'])
                    me.setLinkLabel("VT communicating_hash" + ", positives:" + str(item['positives']) + "/" + str(item['total']))
            if 'detected_downloaded_samples' in response_json:
                for item in response_json['detected_downloaded_samples']:
                    me = mt.addEntity("maltego.Hash", '%s' % item['sha256'])
                    me.setLinkLabel("VT downloaded_hash" + ", positives:" + str(item['positives']) + "/" + str(item['total']))
            if 'detected_urls' in response_json:
                for item in response_json['detected_urls']:
                    me = mt.addEntity("maltego.URL", '%s' % item['url'])
                    me.setLinkLabel("VT positives:" + str(item['positives']) + "/" + str(item['total']))
            if 'resolutions' in response_json:
                for item in response_json['resolutions']:
                    me = mt.addEntity("maltego.Domain", '%s' % item['hostname'])
                    me.setLinkLabel("VT, " + item['last_resolved'])
            if 'country' in response_json:
                me = mt.addEntity("maltego.Location", '%s' % response_json['country'])
                me.setLinkLabel("VT")

    except:
        pass

    return mt

# url_reports
def url_reports():
    try:
        params = {'apikey': apikey, 'resource': data}
        response = requests.post(apiurl + 'url/report', params=params)
        response_json = response.json()
        respcode = int(response_json['response_code'])

        if respcode == 1:
            if 'positives' in response_json:
                me = mt.addEntity("maltego.Phrase", '%s' % str(response_json['positives']) + "/" + str(response_json['total']))
                me.setLinkLabel("VT, " + response_json['scan_date'])

    except:
        pass

    return mt

# file_reports
def file_reports():
    try:
        params = {'apikey': apikey, 'resource': data}
        response = requests.get(apiurl + 'file/report', params=params)
        response_json = response.json()
        respcode = int(response_json['response_code'])

        if respcode == 1:
            if 'positives' in response_json:
                me = mt.addEntity("maltego.Phrase", '%s' % str(response_json['positives']) + "/" + str(response_json['total']))
                me.setLinkLabel("VT, " + response_json['scan_date'])
            if 'Microsoft' in response_json['scans']:
                if response_json['scans']['Microsoft']['detected']:
                    me = mt.addEntity("maltego.Avdetection", '%s' % response_json['scans']['Microsoft']['result'])
                    me.setLinkLabel("VT Microsoft")
            if 'TrendMicro' in response_json['scans']:
                if response_json['scans']['TrendMicro']['detected']:
                    me = mt.addEntity("maltego.Avdetection", '%s' % response_json['scans']['TrendMicro']['result'])
                    me.setLinkLabel("VT TrendMicro")
            if 'Kaspersky' in response_json['scans']:
                if response_json['scans']['Kaspersky']['detected']:
                    me = mt.addEntity("maltego.Avdetection", '%s' % response_json['scans']['Kaspersky']['result'])
                    me.setLinkLabel("VT Kaspersky")
            if 'Sophos' in response_json['scans']:
                if response_json['scans']['Sophos']['detected']:
                    me = mt.addEntity("maltego.Avdetection", '%s' % response_json['scans']['Sophos']['result'])
                    me.setLinkLabel("VT Sophos")
            if 'ESET-NOD32' in response_json['scans']:
                if response_json['scans']['ESET-NOD32']['detected']:
                    me = mt.addEntity("maltego.Avdetection", '%s' % response_json['scans']['ESET-NOD32']['result'])
                    me.setLinkLabel("VT ESET-NOD32")
            if 'F-Secure' in response_json['scans']:
                if response_json['scans']['F-Secure']['detected']:
                    me = mt.addEntity("maltego.Avdetection", '%s' % response_json['scans']['F-Secure']['result'])
                    me.setLinkLabel("VT F-Secure")
            if 'Symantec' in response_json['scans']:
                if response_json['scans']['Symantec']['detected']:
                    me = mt.addEntity("maltego.Avdetection", '%s' % response_json['scans']['Symantec']['result'])
                    me.setLinkLabel("VT Symantec")
            if 'eGambit' in response_json['scans']:
                if response_json['scans']['eGambit']['detected']:
                    me = mt.addEntity("maltego.Avdetection", '%s' % response_json['scans']['eGambit']['result'])
                    me.setLinkLabel("VT eGambit")

    except:
        pass

    return mt

# file_rescan
def file_rescan():
    try:
        params = {'apikey': apikey, 'resource': data}
        response = requests.post(apiurl + 'file/rescan', params=params)
        response_json = response.json()
        respcode = int(response_json['response_code'])

        if respcode == 1:
            me = mt.addEntity("maltego.Phrase", '%s' % "Rescanning... Please wait...")
            me.setLinkLabel("VT")

    except:
        pass

    return mt

# url_scan
def url_scan():
    try:
        params = {'apikey': apikey, 'url': data}
        response = requests.post(apiurl + 'url/scan', params=params)
        response_json = response.json()
        respcode = int(response_json['response_code'])

        if respcode == 1:
            me = mt.addEntity("maltego.Phrase", '%s' % "Rescanning... Please wait...")
            me.setLinkLabel("VT")

    except:
        pass

    return mt

# md5
def md5():
    try:
        params = {'apikey': apikey, 'resource': data}
        response = requests.get(apiurl + 'file/report', params=params)
        response_json = response.json()
        respcode = int(response_json['response_code'])

        if respcode == 1:
            if 'md5' in response_json:
                me = mt.addEntity("maltego.Hash", '%s' % response_json['md5'])
                me.setLinkLabel("md5")

    except:
        pass

    return mt

# sha256
def sha256():
    try:
        params = {'apikey': apikey, 'resource': data}
        response = requests.get(apiurl + 'file/report', params=params)
        response_json = response.json()
        respcode = int(response_json['response_code'])

        if respcode == 1:
            if 'sha256' in response_json:
                me = mt.addEntity("maltego.Hash", '%s' % response_json['sha256'])
                me.setLinkLabel("sha256")

    except:
        pass

    return mt

# 

# 

# 

# main
func = sys.argv[1]
data = sys.argv[2]

mt = MaltegoTransform()
mresult = eval(func)()
mresult.returnOutput()


