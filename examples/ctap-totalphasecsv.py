"""
Parses CTAP messages from TotalPhase USB Analyzer CSV Exports.
"""

from ctap import u2fhid
import struct
import csv
import re
import sys

### CSV Filtering

def filter_csv_comments(file_object):
	for line in file_object:
		if not line.startswith('#'): # pass lines that don't start with #
			yield line
		else:
			if re.search("total\s+phase",line,re.IGNORECASE):
				print("Skipping Total Phase Header line")
			elif line.count(',') > 0: # probably header row
				yield line.strip('# ')


### main

if len(sys.argv) > 1:
	file = sys.argv[1]
else:
	print("Usage: ctap.py <filename>")

ctap_devices = []

with open(file, mode='r', newline='') as file:
	reader = csv.DictReader(filter_csv_comments(file))
	headers = reader.fieldnames
	command = 0

	print(headers)

	#Keep the message and message size state for request and response separate
	msg = bytearray()
	msg_req = bytearray()
	msg_res = bytearray()
	msg_size = 0
	msg_size_req = 0
	msg_size_res = 0
	command = 0
	command_req = 0
	command_res = 0
	

	for row in reader:
		#print (row['Len'])
		if (re.search("txn", row["Record"]) and (row['Len'] == "64 B")):
			#and (row['Dev'] == "01")  and (row['Ep'] != "00")
			
			if (re.match("OUT",row["Record"])):
				msg_type = "request"
				direction_indicator = "request "
				msg = msg_req
				msg_size = msg_size_req
				command = command_req
			else:
				msg_type = "response"
				direction_indicator = "response"
				msg = msg_res
				msg_size = msg_size_res
				command = command_res

			report = bytearray.fromhex( row['Data'])

			
			#(prefix,size,), report = struct.unpack("IB", report[:5]), report[5:]
			#report, postfix = report[:size], report[size:]

			(channelID,cmd,), report = struct.unpack(">IB", report[:5]), report[5:]
			#print("%s" % format(channelID, '08x'))
			if format(channelID, '08x') == 'ffffffff': #look for CTAP channel requests
				if not ((row["Dev"],row["Ep"]) in ctap_devices):					
					ctap_devices.append((row["Dev"],row["Ep"]))
					print("Detected CTAP channel request.  Device %s endpoint %s added to CTAP devices list" % (row["Dev"],row["Ep"]))

			if ((row["Dev"],row["Ep"]) in ctap_devices):
				#print("Device OK")

				#print(channelID)
				#print(cmd)
				if( cmd&0x80 ):
					command = cmd&0x7f
					(msg_size,), report = struct.unpack(">H", report[:2]), report[2:]
					print("Index %s Channel [%s] %s Command 0x%s [%i bytes]" % (row['Index'], format(channelID, '08x'), direction_indicator, format(cmd&0x7f, '02x'), msg_size))
					msg = report
					if( len(msg) > msg_size):
						msg = msg[:msg_size] # strip 0s
						u2fhid(command, msg, msg_type) # msg complete
				else:
					print("Index %s Channel [%s] %s Cont 0x%s" % (row['Index'], format(channelID, '08x'), direction_indicator, format(cmd&0x7f, '02x')))
					if msg:
						msg += report
						if( len(msg) > msg_size):
							msg = msg[:msg_size] # strip 0s
							u2fhid(command, msg, msg_type) # msg complete
					else:
						print("Index %s Channel [%s] %s Cont 0x%s without corresponding command packet" % (row['Index'], format(channelID, '08x'), direction_indicator, format(cmd&0x7f, '02x')))

				#save state 
				if (msg_type == "request"):
					msg_req = msg
					msg_size_req = msg_size
					command_req = command
				else:
					msg_res = msg
					msg_size_res = msg_size
					command_res = command

			else:
				print("Device %s endpoint %s not on CTAP devices list" % (row["Dev"],row["Ep"]))
