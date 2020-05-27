import os
import io
import csv
import copy
import json
import ctypes
import locale
import datetime
import subprocess

sql_freq = 10 # cron schedule, in minutes
sql_user = "****"
sql_pass = "****"
sql_dump = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump"
sql_dump_converted = "C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump.tmp"
sql_json = "C:\\Users\\obitadmin\\Elasticsearch\\json\\kav_events-" + \
            datetime.datetime.now().strftime('%Y%m%d%H%M%S') + ".json" 

enforce_encoding = True

print("[d] exporting events from database...")
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
	src_file_encoding='utf-8'
	dst_file_encoding='utf-8'
else:
	src_file_encoding = locale.getpreferredencoding()
	dst_file_encoding = locale.getpreferredencoding()
print("[d] preferred encoding: ", src_file_encoding)

print("[d] binary re-encoding: ", src_file_encoding)
cmd   = [
          'C:\\Users\\obitadmin\\Elasticsearch\\php\\php.exe',
          'C:\\Users\\obitadmin\\Elasticsearch\\convert.php',
          'C:\\Users\\obitadmin\\Elasticsearch\\dump\\kav_events.dump',
          sql_dump_converted
        ]
task = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
task.wait()
print(task.stdout.read())


print("[d] converting results")
line_nr = 0
with io.open(sql_json,'wt', encoding = dst_file_encoding) as json_out:
	with io.open(sql_dump_converted,'rt', encoding = src_file_encoding) as csvfile:
		reader = csv.DictReader(csvfile, delimiter ='|')
		for row in reader:
			if line_nr > 1:
				row['src_type'] = 'kaspersky'
				converted = json.dumps(row, sort_keys=True)+"\n"
				json_out.write(converted)
			line_nr += 1
