import os
import io
import csv
import copy
import json
import time
import ctypes
import locale
import subprocess
from shutil import copyfile
from datetime import datetime


sql_user            = "qradar"
sql_pass            = "qradar2018!"
sql_dump            = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump"
sql_dump_debug      = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump.debug"
sql_dump_converted  = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump.tmp"
sql_json            = "C:\\Users\\obitadmin\\Elasticsearch\\json\\kav_events-" + \
                      datetime.now().strftime('%Y%m%d%H%M%S') + ".json" 

enforce_encoding = True

sql_query = "SELECT  [tmRiseTime], [tmRegistrationTime], [wstrTaskDisplayName], [wstrGroupName], [strEventType], [wstrEventTypeDisplayName], " \
                    "[wstrDescription], [wstrPar1], [wstrPar2], [wstrPar3], " \
                    "[wstrPar4], [wstrPar5], [wstrPar6], [wstrPar7], [wstrPar8], [wstrPar9] " \
                    "FROM [KAV].[dbo].[v_akpub_ev_event] " \
                    "WHERE [tmRiseTime] > DATEADD(minute, -10, SYSDATETIMEOFFSET()) " \
                    "AND [tmRiseTime] < DATEADD(minute, 10, SYSDATETIMEOFFSET())"
                    #"AND [strEventType] LIKE '%GNRL_EV_VIRUS_FOUND_AND_BLOCKED%'"
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

print("[d] PHP binary re-encoding")
cmd   = [
          'C:\\Users\\obitadmin\\Elasticsearch\\php\\php.exe',
          'C:\\Users\\obitadmin\\Elasticsearch\\convert.php',
          'C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump',
          sql_dump_converted
        ]
task = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
task.wait()
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
          m, s = divmod(time.timezone, 60)
          h, m = divmod(m, 60)
          time_offset = "%.2d%.2d" % (h, m)
          row['tmRiseTime'] = datetime.strptime(row['tmRiseTime'], '%Y-%m-%d %H:%M:%S.%f')
          row['tmRiseTime'] = row['tmRiseTime'].strftime("%Y%m%dT%H%M%S") + time_offset
          row['tmRegistrationTime'] = datetime.strptime(row['tmRegistrationTime'], '%Y-%m-%d %H:%M:%S.%f')
          row['tmRegistrationTime'] = row['tmRegistrationTime'].strftime("%Y%m%dT%H%M%S") + time_offset

          if "GNRL_EV_VIRUS_FOUND_AND_BLOCKED" in row['strEventType']:
            domain, user = row['wstrPar7'].split('\\')
            row['user'] = {"name": user, "domain": domain }
            row['message'] = row['wstrEventTypeDisplayName']
            row['event'] = {"name": "Malware", "action": "Blocked"}
            print(row)
          converted = json.dumps(row, sort_keys=True)+"\n"
          json_out.write(converted)  
        except:
          pass
          #print('[d] exception: ', row)
      line_nr += 1
    print("[d] total lines: ", line_nr)
