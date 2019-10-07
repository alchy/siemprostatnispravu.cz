#!/root/py3/bin/python

'''
windows event id: 4624
        https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624
'''


import json
import time
import socket
import signal
from dns import resolver, reversename
from datetime import datetime
from elasticsearch import Elasticsearch


DEBUG           = True
ES_USER         = 'python'
ES_PASS         = '3507bcd4bd8655c1731265f2f4d7272b'
ES_SIZE         = 1023
ES_TIMEOUT      = 1024


class GracefulKiller:
  kill_now = False
  def __init__(self):
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)

  def exit_gracefully(self,signum, frame):
    self.kill_now = True


def processing(hit):
  if DEBUG:
    print("[d] prociessing function called...")
  ext_index = hit['_index']
  ext_id = hit['_id']
  ext = {}

  ext['@timestamp' ] = hit['_source']['@timestamp']
  ext['origin'] = hit['_source']['winlog']['computer_name'].lower()
  ext['action'] = "logon"

  ''' include original message before we update with ours '''
  ext['message'] = hit['_source']['message']

  ''' make a single detail array from the specific attributes '''
  ''' get logontype '''
  try:
    if hit['_source']['winlog']['event_data']['LogonType'] == 2:
      ext['logon_type'] = "interactive"
    elif hit['_source']['winlog']['event_data']['LogonType'] == 3:
      ext['logon_type'] = "network"
    elif hit['_source']['winlog']['event_data']['LogonType'] == 4:
      ext['logon_type'] = "batch"
    elif hit['_source']['winlog']['event_data']['LogonType'] == 5:
      ext['logon_type'] = "service"
    elif hit['_source']['winlog']['event_data']['LogonType'] == 7:
      ext['logon_type'] = "unlock"
    elif hit['_source']['winlog']['event_data']['LogonType'] == 8:
      ext['logon_type'] = "cleartext"
    elif hit['_source']['winlog']['event_data']['LogonType'] == 9:
      ext['logon_type'] = "run as"
    elif hit['_source']['winlog']['event_data']['LogonType'] == 10:
      ext['logon_type'] = "remote interactive"
    elif hit['_source']['winlog']['event_data']['LogonType'] == 11:
      ext['logon_type'] = "cached interactive"
    else:
      ext['logon_type'] = "unknown"
  except KeyError:
      ext['logon_type'] = "no data available for conversion"

  ext['detail'] = ( ext['logon_type'] )

  ''' get status '''
  ext['status'] = "unknown"
  if "Audit Success" in hit['_source']['winlog']['keywords']:
    ext['status'] = "passed"
  if "Audit Failure" in hit['_source']['winlog']['keywords']:
    ext['status'] = "failed"

  ''' get user '''
  try:
    ext['src_user'] = hit['_source']['winlog']['event_data']['TargetUserName'].lower()
  except KeyError:
    ext['src_user'] = "unknown"

  ''' get src (src is where the req. is coming from)'''
  try:
    ext['src_ip'] = hit['_source']['winlog']['event_data']['IpAddress']                                 # get ip address
    socket.inet_aton(ext['src_ip'])                                                                     # check if it is ipv4 \
    ext['src_fqdn'] = str(resolver.query(reversename.from_address(ext['src_ip']),"PTR")[0])[:-1]        # make src_ip fqdn    |
  except KeyError:
    ext['src_ip'] = "0.0.0.1"                                                                           # no ip address at all
  except OSError:                                                                                       # it was no ipv4      /
    ext['src_ip'] = "0.0.0.1"                                                                           # failed, assign something
  except resolver.NXDOMAIN:                                                                             # reverse resolve impossible
    ext['src_fqdn'] = "unresolvable.somedomain"                                                         # failed, unresolvable, assign something

  ''' get dst (src is where the req. is coming for)'''
  ''' convert the hostname to ip address '''
  try:
    ext['dst_fqdn'] = hit['_source']['winlog']['computer_name'].lower()                                 # convert name to lowercase
    ext['dst_ip'] = socket.gethostbyname(ext['dst_fqdn'])                                               # make it ipv4
  except socket.gaierror:                                                                               # reverese can't be made
    ext['dst_ip'] = "0.0.0.1"                                                                           # failed, unresolvable, assign something
  ''' convert the ip address to hostname '''
  try:
    ext['src_fqdn'] = str(resolver.query(reversename.from_address(ext['src_ip']),"PTR")[0])[:-1]        # make src_ip fqdn, otherwise suffix loss
  except resolver.NXDOMAIN:                                                                             # reverse resolve impossible
    ext['src_fqdn'] = "unresolvable.somedomain"                                                         # failed, unresolvable, assign something

  ext['parsed'] = 'true'
  return(ext_index, ext_id, json.dumps(ext, indent = 2))


if __name__ == "__main__":
  killer = GracefulKiller()

  ES_USER = 'python'
  ES_PASS = '3507bcd4bd8655c1731265f2f4d7272b'

  es = Elasticsearch( 'localhost',
                       http_auth = ( ES_USER, ES_PASS ),
                       scheme = 'http',
                       port = 9200 )

  es_index = "winlogbeat-*"
  es_query = { "query": {
                 "match": {
                   "winlog.event_id" : 4624 }
                         }, "size": ES_SIZE  }

  try:
    while not killer.kill_now:
      if DEBUG:
        print("[d] querying elasticsearch...")

      response = es.search( index = es_index,
                            body = es_query,
                            request_timeout = ES_TIMEOUT )

      if DEBUG:
        print("[d] elasticsearchi responded, processing results...")

      for hit in response['hits']['hits']:
        if DEBUG:
          print(json.dumps(hit, indent = 2))

        ext_index, ext_id, ext = processing(hit)

        if DEBUG:
            print("[d] query processed and saved into elasticsearch...")
            print("[d] ID:    ", ext_id)
            print("[d] INDEX: ", ext_index)
            print(ext)

        res = es.index( index = ext_index, id = ext_id, body = ext )
        if DEBUG:
          print(res['result'])

    print("End of the program. I was killed gracefully :)")
  except Exception as e:
    print("Error while parsing. Program exit :(", str(e), json.dumps(response, indent = 2))

