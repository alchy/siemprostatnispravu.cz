#!/root/py3/bin/python

'''
check for DNS tunneling
inspired by:
  https://www.elastic.co/blog/detecting_dns_tunnels_with_packetbeat_and_watcher
'''


import json
import time
import signal
import smtplib
import hashlib
from datetime import datetime
from elasticsearch import Elasticsearch
from email.message import EmailMessage

from extlib import get_network_from_ipaddress, get_network_from_hostname


''' elasticsearch and program debug options '''
DEBUG           = False
ES_USER         = 'python'
ES_PASS         = 'secret'
ES_SIZE         = 1000
ES_TIMEOUT      = 1000


''' email and alert specific options '''
ALERT_NAME      = "possible DNS tunneling"
ALERT_SENDER    = "someuser@somedomain"
ALERT_RECIPIENT = "someuser@somedomain"
ALERT_FILE      = "/tmp/_tmp_" + hashlib.md5(ALERT_NAME.encode('utf-8')).hexdigest()
ALERT_TRIGGER   = False

''' control specific variables, exceptions and tresholds '''
DOMAINS_EXCLUDED = [ "sophosxl.com",
                     "akadns.net",
                     "akamai.net",
                     "akamaiedge.net",
                     "apple.com",
                     "azure.com",
                     "azureedge.net",
                     "amazonaws.com",
                     "edgekey.net",
                     "facebook.com",
                     "google.com",
                     "googlevideo.com",
                     "idnes.cz",
                     "kaspersky.com",
                     "mcafee.com",
                     "msn.com",
                     "microsoft.com",
                     "outlook.com",
                     "seznam.cz",
                     "szn.cz",
                     "trafficmanager.net",
                     "wbx2.com",
                     "windows.net",
                     "yahoo.com" ]


DOMAIN = {}
DOMAIN_TIME_PROCESSED = "now-24h"                       # time window to process
DOMAIN_WARNING_TRESHOLD = 128                           # report domain if this is exceeded
DOMAIN_NOT_REPORT_SUB = 1024                            # how many subdomains is in the report


''' event processing '''
def processing(hit):
  domain_shrt = hit['dns']['question']['etld_plus_one']
  domain_full = hit['dns']['question']['name']
  domain_qtpe = hit['dns']['question']['type']

  try:
    DOMAIN[domain_shrt].add(domain_full)
  except KeyError:
    DOMAIN[domain_shrt] = set()
    DOMAIN[domain_shrt].add(domain_full)

  if DEBUG:
    print(domain_shrt)
    print(domain_full)


''' main function '''
if __name__ == "__main__":

  es = Elasticsearch( 'localhost',
                       http_auth = ( ES_USER, ES_PASS ),
                       scheme = 'http',
                       port = 9200 )

  es_index = "packetbeat-*"
  es_query = { "_source": { "includes": [ "dns.question.etld_plus_one", "dns.question.name", "dns.question.type" ] },
               "query" : {
                 "bool": {
                   "must": [
                     { "match":  { "tap": "internet" } },
                     { "exists": { "field": "dns.question.etld_plus_one" } }
                   ],
                   "must_not": [
                     { "terms": { "dns.question.etld_plus_one": DOMAINS_EXCLUDED } },
                     { "match": { "dns.question.type.keyword": "PTR" } },
                   ],
                   "filter": { "range": { "@timestamp": { "from": DOMAIN_TIME_PROCESSED } } }
                 }
               },
               "size": ES_SIZE
             }

  if DEBUG:
    print("[d] querying elasticsearch...")

  response = es.search( index = es_index,
                        body = es_query,
                        scroll = '2m',
                        request_timeout = ES_TIMEOUT )

  if DEBUG:
    print("[d] elasticsearch responded...")
    print(response)

  scroll_id = response['_scroll_id']
  scroll_size = len(response['hits']['hits'])

  if DEBUG:
    print("scroll id: ", scroll_id, " scroll size: ", scroll_size)

  while scroll_size > 0:
    for hit in response['hits']['hits']:
      if DEBUG:
        print(hit['_source'])

      processing(hit['_source'])

    if DEBUG:
       print("[d] next scroll...")

    response = es.scroll(scroll_id = scroll_id, scroll = '2m')
    scroll_size = len(response['hits']['hits'])

  if DEBUG:
    print("[d] processed all input (scroll done)...")

  with open(ALERT_FILE, "w") as file:

    for domain_full in DOMAIN:
       domain_count = len(DOMAIN[domain_full])
       if domain_count > DOMAIN_WARNING_TRESHOLD:
         ALERT_TRIGGER = True
         print("Please check the subdomains of the following domain. The DNS DOMAIN_WARNING_TRESHOLD (",
                DOMAIN_WARNING_TRESHOLD, " vs. ", domain_count, ") is exceeded for ",
                "this domain and it might be a sign of DNS tunneling. ",
                "If it is a false positive, please add the domain to the exception ",
                "list or modify DOMAIN_WARNING_TRESHOLD.", file = file)
         print("", file = file)
         print("domain: ", domain_full, file = file)
         print("count:  ", domain_count, file = file)
         subdomains_reported = 0
         for domain_shrt in DOMAIN[domain_full]:
           print("  subdomains: " , domain_shrt, file = file)
           subdomains_reported += 1
           if subdomains_reported > DOMAIN_NOT_REPORT_SUB:
             print("  WARNING! The subdomain list is too long to report. List is truncated.", file = file)
             break
         print("", file = file)

  if ALERT_TRIGGER:
    with open(ALERT_FILE, "r") as file:

      msg = EmailMessage()
      msg.set_content(file.read())

      msg['Subject'] = 'OIKB ALERT: ' + ALERT_NAME
      msg['From'] = ALERT_SENDER
      msg['To'] = ALERT_RECIPIENT

      s = smtplib.SMTP('localhost')
      s.send_message(msg)
      s.quit()
