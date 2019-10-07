#!/root/py3/bin/python

'''
windows event id: 4625
        https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625
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
ES_SIZE         = 1
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
    print("[d] processing function called...")

  ext = {}
  ext['@timestamp' ] = hit['@timestamp']
  ext['origin'] = hit['winlog']['computer_name'].lower()
  ext['action'] = "logon"

  ''' include original message before we update with ours '''
  ext['message'] = hit['message']

  ''' make a single detail array from the specific attributes '''
  ''' get logontype '''
  try:
    if hit['winlog']['event_data']['LogonType'] == 2:
      ext['logon_type'] = "interactive"
    elif hit['winlog']['event_data']['LogonType'] == 3:
      ext['logon_type'] = "network"
    elif hit['winlog']['event_data']['LogonType'] == 4:
      ext['logon_type'] = "batch"
    elif hit['winlog']['event_data']['LogonType'] == 5:
      ext['logon_type'] = "service"
    elif hit['winlog']['event_data']['LogonType'] == 7:
      ext['logon_type'] = "unlock"
    elif hit['winlog']['event_data']['LogonType'] == 8:
      ext['logon_type'] = "cleartext"
    elif hit['winlog']['event_data']['LogonType'] == 9:
      ext['logon_type'] = "run as"
    elif hit['winlog']['event_data']['LogonType'] == 10:
      ext['logon_type'] = "remote interactive"
    elif hit['winlog']['event_data']['LogonType'] == 11:
      ext['logon_type'] = "cached interactive"
    else:
      ext['logon_type'] = "unknown"
  except KeyError:
      ext['logon_type'] = "no data available for conversion"

  ''' get substatus '''
  try:
    if   hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000064":
      ext['substatus'] = "user name does not exist"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc000006a":
      ext['substatus'] = "user name is correct but the password is wrong"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000234":
      ext['substatus'] = "user is currently locked out"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000072":
      ext['substatus'] = "account is currently disabled"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc000006f":
      ext['substatus'] = "outside his day of week or time of day restrictions"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000070":
      ext['substatus'] = "workstation restriction"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000193":
      ext['substatus'] = "account expiration"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000071":
      ext['substatus'] = "expired password"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000133":
      ext['substatus'] = "clocks between DC and other computer too far out of sync"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000224":
      ext['substatus'] = "user is required to change password at next logon"
    elif hit['winlog']['event_data']['SubStatus'].lower() == "0xc0000225":
      ext['substatus'] = "user has not been granted the requested logon type"
    else:
      ext['substatus'] = "unknown substatus"
  except KeyError:
      ext['substatus'] = "no data available for conversion"

  ext['detail'] = ( ext['logon_type'], ext['substatus'] )

  ''' get status '''
  ext['status'] = "unknown"
  if "Audit Success" in hit['winlog']['keywords']:
    ext['status'] = "passed"
  if "Audit Failure" in hit['winlog']['keywords']:
    ext['status'] = "failed"

  ''' get user '''
  try:
    ext['src_user'] = hit['winlog']['event_data']['TargetUserName'].lower()
  except KeyError:
    ext['src_user'] = "unknown"

  ''' get src (src is where the req. is coming from)'''
  ''' convert the hostname to ipaddress '''
  try:
    ext['src_fqdn'] = hit['winlog']['event_data']['WorkstationName']                                    # get worksation name (not a fqdn)
    ext['src_ip'] = socket.gethostbyname(ext['src_fqdn'])                                               # try to resolv it
    ext['src_fqdn'] = str(resolver.query(reversename.from_address(ext['src_ip']),"PTR")[0])[:-1]        # make src_ip fqdn    |
  except socket.gaierror:                                                                               # reverese can't be made
    ext['src_ip'] = "0.0.0.1"                                                                           # failed, unresolvable, assign something
  except KeyError:
    ext['src_ip'] = "0.0.0.1"                                                                           # no ip address at all
  except OSError:                                                                                       # it was no ipv4      /
    ext['src_ip'] = "0.0.0.1"                                                                           # failed, assign something
  except resolver.NXDOMAIN:                                                                             # reverse resolve impossible
    ext['src_fqdn'] = "unresolvable.somedomain"                                                         # failed, unresolvable, assign something

  ''' get dst (src is where the req. is coming for)'''
  ''' convert the hostname to ip address '''
  try:
    ext['dst_fqdn'] = hit['winlog']['computer_name'].lower()                                            # convert name to lowercase
    ext['dst_ip'] = socket.gethostbyname(ext['dst_fqdn'])                                               # make it ipv4
  except socket.gaierror:                                                                               # reverese can't be made
    ext['dst_ip'] = "0.0.0.1"                                                                           # failed, unresolvable, assign something
  ''' convert the ip address to hostname '''
  try:
    ext['dst_fqdn'] = str(resolver.query(reversename.from_address(ext['dst_ip']),"PTR")[0])[:-1]        # make src_ip fqdn, otherwise suffix loss
  except resolver.NXDOMAIN:                                                                             # reverse resolve impossible
    ext['dst_fqdn'] = "unresolvable.somedomain"                                                         # failed, unresolvable, assign something

  ext['parsed'] = 'true'
  return(json.dumps(ext, indent = 2))


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
                   "winlog.event_id" : 4625 }
                         }, "size": ES_SIZE  }

  try:
    while not killer.kill_now:
      if DEBUG:
        print("[d] querying elasticsearch...")

      response = es.search( index = es_index,
                            body = es_query,
                            request_timeout = ES_TIMEOUT )

      if DEBUG:
        print("[d] elasticsearch responded, processing results...")

      for hit in response['hits']['hits']:
        if DEBUG:
          print(json.dumps(hit, indent = 2))

        if DEBUG:
            print("[d] query processed and saved into elasticsearch...")
            print("[d] ID:    ", hit['_id'])
            print("[d] INDEX: ", hit['_index'])

        res = es.index( index = hit['_index'], id = hit['_id'], body = processing(hit['_source']) )
        if DEBUG:
          print(res['result'])

    print("End of the program. I was killed gracefully :)")
  except Exception as e:
    print("Error while parsing. Program exit :(", str(e), json.dumps(response, indent = 2))
