import os
import io
import csv
import copy
import json
import time
import ctypes
import locale
import subprocess
import socket, struct
from shutil import copyfile
from datetime import datetime

DEBUG = True

sql_user            = "*****"
sql_pass            = "*****"
sql_dump            = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump"
sql_dump_debug      = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump.debug"
sql_dump_converted  = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump.tmp"
sql_json            = "C:\\Users\\obitadmin\\Elasticsearch\\json\\kav_events-" + \
                      datetime.now().strftime('%Y%m%d%H%M%S') + ".json" 

enforce_encoding = True


def ip_conversion(integer_ip):
  
  try:
  
    ip = socket.inet_ntoa(struct.pack('!L', int(integer_ip)))
  except:
  
    ip = "0.0.0.0"
  try:

    fqdn = socket.gethostbyaddr(ip)[0]
  except:

    fqdn = "n/a"
  return(ip, fqdn)


if __name__ == "__main__":

  sql_query = "SELECT  [tmRiseTime], [tmRegistrationTime], [wstrTaskDisplayName], [wstrGroupName], [strEventType], [wstrEventTypeDisplayName], " \
                       "[wstrDescription], [wstrPar1], [wstrPar2], [wstrPar3], " \
                       "[wstrPar4], [wstrPar5], [wstrPar6], [wstrPar7], [wstrPar8], [wstrPar9] " \
                       "FROM [KAV].[dbo].[v_akpub_ev_event] " \
                       "WHERE [tmRiseTime] > DATEADD(minute, -10, SYSDATETIMEOFFSET()) " \
                       "AND [tmRiseTime] < DATEADD(minute, 10, SYSDATETIMEOFFSET())"
                       #"AND [strEventType] LIKE '%GNRL_EV_VIRUS_FOUND_AND_BLOCKED%'"

  if DEBUG:
    print("[d] exporting events from database...")
  cmd    = [
             'SQLCMD.EXE',
             '-U', sql_user, 
             '-P', sql_pass,
             '-o', sql_dump,
             '-s', '|',
             '-W',
             '-Q', sql_query
            ]
  print("[d] reading database")
  print("[d]", sql_query)

  task = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
  task.wait()

  copyfile(sql_dump, sql_dump_debug)

  if DEBUG:
    print("[d] PHP binary re-encoding")
  cmd   = [
            'C:\\Users\\obitadmin\\Elasticsearch\\php\\php.exe',
            'C:\\Users\\obitadmin\\Elasticsearch\\convert.php',
            'C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump',
            sql_dump_converted
          ]
  task = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
  task.wait()

  if DEBUG:
    print("[d] stdout read: ", task.stdout.read())

  if enforce_encoding:
    src_file_encoding='utf-8'
    dst_file_encoding='utf-8'
  else:
    src_file_encoding = locale.getpreferredencoding()
    dst_file_encoding = locale.getpreferredencoding()
  print("[d] preferred encoding: ", src_file_encoding)

  line_nr = 0
  with io.open(sql_json,'wt', encoding = dst_file_encoding) as json_out:
    with io.open(sql_dump_converted,'rt', encoding = src_file_encoding) as csvfile:
      reader = csv.DictReader(csvfile, delimiter ='|')
      for row in reader:
        if line_nr > 1:
          row['src_type'] = 'kaspersky'
          try:
            # https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-date-format.html#strict-date-time
            # basic_date_time_no_millis
            # A basic formatter that combines a basic date and time without millis, separated by a T: yyyyMMdd'T'HHmmssZ.
            # UTC time with offset to Elasticsearch
            m, s = divmod(time.timezone, 60)
            h, m = divmod(m, 60)
            time_offset = "-%.2d%.2d" % (abs(h - time.localtime().tm_isdst), m)
            row['tmRiseTime'] = datetime.strptime(row['tmRiseTime'], '%Y-%m-%d %H:%M:%S.%f')
            row['tmRiseTime'] = row['tmRiseTime'].strftime("%Y%m%dT%H%M%S") + time_offset
            row['tmRegistrationTime'] = datetime.strptime(row['tmRegistrationTime'], '%Y-%m-%d %H:%M:%S.%f')
            row['tmRegistrationTime'] = row['tmRegistrationTime'].strftime("%Y%m%dT%H%M%S") + time_offset
            
            if "GNRL_EV_VIRUS_FOUND" in row['strEventType']:

              if DEBUG:
                print("[d] processing GNRL_EV_VIRUS_FOUND")

              domain, user = row['wstrPar7'].split('\\')
              row['user'] = {"name": user, "domain": domain }
              row['event'] = { "action": "malware-found", 
                               "category": "malware",
                               "type": "denied" }
      
            if "GNRL_EV_ATTACK_DETECTED" in row['strEventType']:

              if DEBUG:
                print("[d] processing GNRL_EV_ATTACK_DETECTED")

              row['event'] = { "action": "network-scanning", 
                               "category": [ "intrusion_detection",  "network" ],
                               "type": [ "connection", "denied" ] }

              ip, fqdn = ip_conversion(row['wstrPar6'])
              row['host'] = { "ip": ip, "name": fqdn }
        
              ip, fqdn = ip_conversion(row['wstrPar3'])
              row['source'] = { "ip": ip, "domain": fqdn }

            converted = json.dumps(row, sort_keys=True)+"\n"
          except:

            if DEBUG:
              print('[d] exception: ', row)
        line_nr += 1
      if DEBUG:

        print("[d] total lines: ", line_nr)
