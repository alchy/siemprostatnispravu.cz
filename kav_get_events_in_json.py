import os
import io
import csv
import copy
import json
import locale
import subprocess

sql_freq = 1 			# in minutes
sql_user = "****"
sql_pass = "****"
sql_dump = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump"
sql_json = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.json"

enforce_encoding = True

cmd    = [
           'SQLCMD.EXE',
           '-U', sql_user,
           '-P', sql_pass,
           '-o', sql_dump,
           '-s', '|',
           '-W',
           #'-f', "65001",
           '-Q', 'select * from KAV.dbo.v_akpub_ev_event WHERE tmRiseTime ' + \
                 '> DATEADD(minute, -' + str(sql_freq) +', SYSDATETIMEOFFSET());'
          ]
print("[d] reading database")
task = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
task.wait()

if enforce_encoding:
  src_file_encoding='852'
  dst_file_encoding='cp1250'
else:
  src_file_encoding = locale.getpreferredencoding()
  dst_file_encoding = locale.getpreferredencoding()

print("[d] preferred encoding: ", src_file_encoding)

print("[d] converting results")
line_nr = 0
with io.open(sql_json,'w', encoding = dst_file_encoding) as json_out:
  with io.open(sql_dump,'r', encoding = dst_file_encoding) as csvfile:
    reader = csv.DictReader(csvfile, delimiter ='|')
    for row in reader:
        json_out.write(json.dumps(row, sort_keys=True)+"\n")
