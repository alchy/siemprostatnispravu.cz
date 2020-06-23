#!/opt/rh/rh-python36/root/usr/bin/python

import time
import json
import socket
import requests
from requests.auth import HTTPBasicAuth
from elasticsearch import Elasticsearch

proxyDict = {
              "http"  : "xxx.xx.xxx.xx:3128",
              "https" : "xxx.xx.xxx.xx:3128"
            }

umbrella_url = "https://reports.api.umbrella.com/v1/organizations/xxxxxxxxxxx/security-activity"
umbrella_key = "*****"
umbrella_scr = "*****"

elastic_key = "*****"
elastic_scr = "*****"
limit = 500

pooling_interval_hours = 1
pooling_interval_seconds = pooling_interval_hours * 3600


def getIP(d):
  """
  This method returns the first IP address string
  that responds as the given domain name
  """
  try:
    data = socket.gethostbyname(d)
    ip = str(data)
    return(ip)
  except Exception:
    # fail gracefully!
    return "0.0.0.0"


def get_umbrella_report(start, stop, stipTimestamp):
  print("[d] start time: ", time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start)))
  print("[d] stop  time: ", time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stop)))

  #umbrella_params = { "limit": limit, "start": start, "stop": stop, "stopTimestamp": stopTimestamp}
  umbrella_params = { "limit": limit, "start": start, "stop": stop }
  response = requests.get(umbrella_url,
                          params = umbrella_params,
                          auth = HTTPBasicAuth(umbrella_key, umbrella_scr),
                          proxies = proxyDict)
  return(response)


def connect_elastic():
  # https://medium.com/naukri-engineering/elasticsearch-tutorial-for-beginners-using-python-b9cb48edcedc
  #es = Elasticsearch(["https://" + elastic_key + ":" + elastic_scr + "@clcsec.dc.vzp.cz:9200/"])
  es = Elasticsearch("clcsec.dc.vzp.cz",
                      http_auth = (elastic_key, elastic_scr),
                      port = 9200,
                      use_ssl = True,
                      ca_certs =    '/data/scripts/umbrella/pki/ca.pem',
                      client_cert = '/data/scripts/umbrella/pki/ssl-clcsec-dc-vzp-cz.pem',
                      client_key =  '/data/scripts/umbrella/pki/ssl-clcsec-dc-vzp-cz.key')

  if es.ping():
    print("[d] connected to Elastic")
    return(es)
  else:
    print("[d] could not connect to Elastic!")
    return(False)


def query_origin(es, query_domain):
  body = {
    "size": 0,
    "query": {
      "bool": {
        "must": [
          { "match": { "dns_query.keyword": query_domain } },
          { "range": { "@timestamp": { "gte" : "now-" + str(pooling_interval_seconds) + "s" } } }
        ]
      }
    },
    "aggs": {
      "src_fqdn_aggs": {
        "terms": {
          "field": "src_fqdn.keyword",
          "size": 10
        }
      }
    }
  }
  res = es.search(index = "syslog-gtm-*", body = body)
  query_origin_fqdns = []
  query_origin_ips = []
  for item in (res["aggregations"]["src_fqdn_aggs"]["buckets"]):
    query_origin_fqdns.append(item["key"])
    query_origin_ips.append(getIP(item["key"]))
  return(query_origin_fqdns, query_origin_ips)


if __name__ == "__main__":

  stop = epoch_time = int(time.time())
  start = int(stop - pooling_interval_seconds)
  stopTimestamp = stop

  response = get_umbrella_report(start, stop, stopTimestamp)
  if response.status_code == 200:

    json_response = json.loads(response.text)
    es = connect_elastic()
    if es:

      for json_event in json_response["requests"]:
        json_event["@timestamp"] = json_event["datetime"]

        # ECS categorization <event>
        json_event["event"] = { \
                               "action": "dns-query-blocked", \
                               "category": "malware", \
                               "module": "dns-protection", \
                               "outcome": "failure", \
                               "type": [ "connection", "denied" ]
                              }

        # ECS mandatory categorization <user, host, source, destination>
        tmp_destination = json_event["destination"]
        del json_event["destination"]
        query_origin_fqdns, query_origin_ips = query_origin(es, tmp_destination)
        json_event["user"] = { "name": "n/a" }
        json_event["host"] = { "name": query_origin_fqdns }
        json_event["source"] = { "ip": query_origin_ips }
        json_event["destination"] = { "ip": getIP(tmp_destination), "domain": tmp_destination }

        # ECS DNS
        registered_domain = tmp_destination.split('.')[-2:]
        registered_domain = ".".join(registered_domain)
        json_event["dns"] = { "question" : { "registered_domain": registered_domain } }

        # non-ECS (custom)
        json_event["message"] = "DNS request blocked by Umbrella"
        json_event["source_type"] = "umbrella"

        print(json_event)

        index_name = "umbrella-" + time.strftime('%Y-%m', time.localtime(start))
        print("[d] index name: ", "umbrella-" + index_name)
        res = es.index(index = index_name, body = json_event)
        print(res)

    else:
      print("[d] can't connect to elastic...")
  else:
    print("[d] can't connect to umbrela API...")
