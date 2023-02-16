"""
Quick and dirty parsing of CTAP messages.
This is a proof of concept, and a work in progress. Please ignore its ugliness for now...
"""

import zmq
import binascii
import struct
import base64
#from cryptography import x509
import cbor2

### U2F

U2F_REGISTER_ID = 5

# U2FHID native commands
class U2FHID:
	PING  = 0x01  # Echo data through local processor only
	MSG   = 0x03  # Send U2F message frame
	LOCK  = 0x04  # Send lock channel command
	INIT  = 0x06  # Channel initialization
	WINK  = 0x08  # Send device identification wink
	SYNC  = 0x3c  # Protocol resync command
	ERROR = 0x3f  # Error response

class INS:
	REGISTER     = 0x01  # Registration command
	AUTHENTICATE = 0x02  # Authenticate/sign command
	VERSION      = 0x03  # Read version string command

# Authentication control byte

class AUTH:
	ENFORCE     =  0x03    # Enforce user presence and sign
	CHECK_ONLY  =  0x07    # Check only
	FLAG_TUP    =  0x01    # Test of user presence set

class SW:
	NO_ERROR                 = 0x9000
	WRONG_DATA               = 0x6A80
	CONDITIONS_NOT_SATISFIED = 0x6985
	COMMAND_NOT_ALLOWED      = 0x6986
	INS_NOT_SUPPORTED        = 0x6D00

### CTAP2

# CTAP commands
class CTAPHID:
	PING      = 0x01  # Echo data through local processor only
	MSG       = 0x03  # Send U2F message frame
	LOCK      = 0x04  # Send lock channel command
	INIT      = 0x06  # Channel initialization
	WINK      = 0x08  # Send device identification wink
	CBOR      = 0x10  # 
	CANCEL    = 0x11  #
	KEEPALIVE = 0x3b  #
	ERROR     = 0x3f  # Error response

class Authenticator:
	MakeCredential   = 0x01
	GetAssertion     = 0x02
	GetInfo          = 0x04
	ClientPIN        = 0x06
	Reset            = 0x07
	GetNextAssertion = 0x08
	VendorFirst      = 0x40
	VendorLast       = 0xbf



# maintain some state
current_transaction = 0	# transaction
current_cbor_cmd = 0 # cbor cmd
# TODO: also maintain channel IDs to support concurrent transactions

### U2FHID protocol messages
# https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-hid-protocol-ps-20141009.html#u2fhid-protocol-implementation
# https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-u2f_hid.h-v1.0-ps-20141009.txt

def u2fhid(cmd, msg, msg_type):
	if( msg_type == "request"):
		#print(">>> {%i %s}" % (cmd,binascii.hexlify(msg)) )
		u2fhid_request(cmd, msg)
	else:
		#print("<<< {%i %s}" % (cmd,binascii.hexlify(msg)) )
		u2fhid_response(cmd, msg)

def u2fhid_request(cmd, msg):
	print('--------------------------------------------------------------------------------')
	match cmd:
		case U2FHID.PING:
			print("U2FHID_PING[TODO]")
		case U2FHID.MSG:
			print("U2FHID_MSG request:")
			u2f_request(msg)
		case U2FHID.INIT:
			(nonce,), msg = struct.unpack(">Q", msg[:8]), msg[8:]
			assert(len(msg)==0)
			print("U2FHID_INIT[nonce=%s]" % format(nonce, '08x'))
		case U2FHID.WINK:
			print("U2FHID_WINK[TODO]")
		case U2FHID.SYNC:
			print("U2FHID_SYNC")
		case U2FHID.LOCK:
			print("U2FHID_LOCK[TODO]")
		case CTAPHID.CBOR:
			(ctap_cmd,), msg = struct.unpack("B", msg[:1]), msg[1:]
			print("CTAPHID_CBOR[%i]" % ctap_cmd)
			cbor(ctap_cmd,msg)
		case _:
			print("unknown command=%i" % cmd)

def u2fhid_response(cmd, msg):
	match cmd:
		case U2FHID.PING:
			print("U2FHID_PING[TODO]")
		case U2FHID.MSG:
			print("U2FHID_MSG response:")
			u2f_response(msg)
		case U2FHID.INIT:
			(nonce,channelID,version, major, minor, build, caps), msg = struct.unpack(">QIBBBBB", msg[:17]), msg[17:]
			assert(len(msg)==0)
			print("U2FHID_INIT[nonce=%s][channelID=%s][version=%i][major=%i][minor=%i][build=%i][caps=%i]" % (format(nonce, '16x'), format(channelID, '08x'), version, major, minor, build, caps) )
		case U2FHID.ERROR:
			print("U2FHID_ERROR[TODO]")
		case U2FHID.WINK:
			print("U2FHID_WINK[TODO]")
		case U2FHID.SYNC:
			print("U2FHID_SYNC")
		case U2FHID.LOCK:
			print("U2FHID_LOCK[TODO]")
		case CTAPHID.CBOR:
			(ctap_cmd,), msg = struct.unpack("B", msg[:1]), msg[1:]
			print("CTAPHID_CBOR[%i]" % ctap_cmd)
			cbor(ctap_cmd,msg)
		case CTAPHID.KEEPALIVE:
			(status_code,), msg = struct.unpack("B", msg[:1]), msg[1:]
			#assert(len(msg)==0)
			match status_code:
				case 1:
					status = 'processing'
				case 2:
					status = 'waiting for UP'
				case _:
					status = 'unknonw status code'
			print("CTAPHID_KEEPALIVE[%s]" % status)
		case _:
			print("unknown command=%i" % cmd)

### U2F protocol messages

# CLA INS P1 P2 LC1 LC2 LC3 <request-data>
def u2f_request(msg):
	global current_transaction
	(cla,ins,p12,lc1,lc23), msg = struct.unpack(">BBHBH", msg[:7]), msg[7:]
	lc123 = lc1 * 65536 + lc23
	print("\tCLA=%i INS=%i Pn=%04x LCn=%06x" % (cla,ins,p12,lc123))
	assert(cla==0)
	current_transaction = ins # remember what response is expected
	match ins:
		case INS.REGISTER:
			print("\tREGISTER=%i" % ins)
			(challenge,application) = struct.unpack('>32s32s', msg[:lc123])
			print("\t[challenge=%s][application=%s]" % (binascii.hexlify(challenge), binascii.hexlify(application)) )
		case INS.AUTHENTICATE:
			match p12:
				case 0x0700:
					print("\tAUTHENTICATE (check-only)")
					#  CLA=0 2 0700 000081
					(challenge,application,handle_len), msg = struct.unpack('>32s32sB', msg[:65]), msg[65:]
					print("\t[challenge=%s][application=%s]" % (binascii.hexlify(challenge), binascii.hexlify(application)) )
					(handle, msg) = msg[:handle_len], msg[handle_len:]
					print("\t[handle=%s]" % (binascii.hexlify(handle)) )
					#print("\t[rest=%s]" % (binascii.hexlify(msg)) )
				case 0x0300:
					print("\tAUTHENTICATE (enforce-user-presence-and-sign)")
					# CLA=0 INS=2 Pn=0300 LCn=000081
					print("\tlc=%06x" % lc123)
					(challenge,application,handle_len), msg = struct.unpack('>32s32sB', msg[:65]), msg[65:]
					print("\t[challenge=%s][application=%s]" % (binascii.hexlify(challenge), binascii.hexlify(application)) )
					(handle, msg) = msg[:handle_len], msg[handle_len:]
					print("\t[handle=%s]" % (binascii.hexlify(handle)) )
				case _:
					print("\tAuthN control byte=%04x" % p12)
		case INS.VERSION:
			print("\tVERSION=%i" % ins)
		case _:
			print("\tunknown instruction=%i" % ins)

def u2f_response(msg):
	global current_transaction
	(sw,msg) = struct.unpack('>H', msg[-2:])[0], msg[:-2]
	ins = current_transaction
	print("\tSW=%04x (response to %i)" % (sw,ins))
	match sw:
		case SW.NO_ERROR:
			match ins:
				case INS.REGISTER:
					#print("... {%s}" % (binascii.hexlify(msg)) )
					(rfu,pubkey,handle_len), msg = struct.unpack(">B65sB", msg[:67]), msg[67:]
					assert(rfu==U2F_REGISTER_ID)
					print("\t[pubkey=%s]" % (binascii.hexlify(pubkey)) )
					(handle, msg) = msg[:handle_len], msg[handle_len:]
					print("\t[handle=%s]" % (binascii.hexlify(handle)) )
					#cert = x509.load_der_x509_certificate(msg)
					cert_len = struct.unpack('>H', msg[2:4])[0]
					print('\t[certificate=%s]' % base64.b64encode(msg[:4+cert_len]).decode('ascii'))
					print('\t[signature=%s]' % binascii.hexlify(msg[4+cert_len:]))
				case INS.AUTHENTICATE:
					print("\tAUTHENTICATE=%i" % ins)
					(up,ctr,), msg = struct.unpack(">BI", msg[:5]), msg[5:]
					print('\t[up=%d][counter=%i][signature=%s]' % (up,ctr,binascii.hexlify(msg)))
				case INS.VERSION:
					print("\tVERSION=%i" % ins)
				case _:
					print("\tunknown response=%i" % ins)
		case SW.WRONG_DATA:
			print("\tWrong Data")
		case SW.CONDITIONS_NOT_SATISFIED:
			print("\tConditions not satisfied")
		case SW.COMMAND_NOT_ALLOWED:
			print("\tCommand not Allowed")
		case SW.INS_NOT_SUPPORTED:
			print("\tInstruction not supported")
		case 0x6985:
			print("\tConditions of use not satisfied")
		case _:
			print("\tunexpected status word: %04x" % sw)

def cbor(cmd,data):
	global current_cbor_cmd
	match cmd:
		case 0:
			cbor_response(current_cbor_cmd, data)
		case Authenticator.MakeCredential:
			print("\tMakeCredential:")
			cbormap = cbor2.decoder.loads(data)
			# required
			clientDataHash = cbormap[1]
			rp = cbormap[2]
			user = cbormap[3]
			pubKeyCredParams = cbormap[4]
			print("\t\tclientDataHash: %s" % binascii.hexlify(clientDataHash))
			print("\t\trp: %s" % rp)
			print("\t\tuser: %s" % user)
			print("\t\tpubKeyCredParams: %s" % pubKeyCredParams)
			# TODO: what else is there?
			del cbormap[1]; del cbormap[2]; del cbormap[3]; del cbormap[4]
			for i in cbormap:
				print("\t\t\tTODO", cbormap[i])
			
		case Authenticator.GetAssertion:
			print("\tGetAssertion:")
			cbormap = cbor2.decoder.loads(data)
			# required
			rpId = cbormap[1]
			print("\t\t%s: %s" % ("rpId",rpId) )
			del(cbormap[1])
			clientDataHash = cbormap[2]
			print("\t\t%s: %s" % ("clientDataHash",binascii.hexlify(clientDataHash)) )
			del(cbormap[2])
			# optional
			if 3 in cbormap:
				allowList = cbormap[3]
				#print("\t\t%s: %s" % ("allowList",(allowList)) )
				print("\t\t%s:" % ("allowList") )
				for allow in allowList:
					print("\t\t\t%s: %s" % ("id",binascii.hexlify(allow["id"])) )
					print("\t\t\t%s: %s" % ("type",allow["type"]) )
					if "transports" in allow:
						print("\t\t\t%s: %s" % ("transports",allow["transports"]) )
				del(cbormap[3])
			# and the rest...
			for i in cbormap:
				print("\t\t\tTODO???", i, cbormap[i])
		case Authenticator.GetInfo:
			print("\tGetInfo")
		case _:
			print("\t\tTODO", cmd)
			print("\t\t: %s" % binascii.hexlify(data))
	current_cbor_cmd = cmd	# remember cmd to be able to interpret response

def cbor_response(cmd, data):
	match cmd:
		case Authenticator.MakeCredential:
			print("\tMakeCredential (response):")
			#print("\t\t: %s" % binascii.hexlify(data))
			cbormap = cbor2.decoder.loads(data)
			# required
			fmt = cbormap[1]
			print("\t\t%s: %s" % ("fmt",fmt) )
			authData = cbormap[2]
			print("\t\t%s: %s" % ("authData", binascii.hexlify(authData)) )
			attStmt = cbormap[3]
			#print("\t\t%s: %s" % ("attStmt",attStmt) )
			print("\t\tattStmt:")
			attestationStatement(fmt,attStmt)
			# optional
			if 4 in cbormap:
				epAtt = cbormap[4]
				print("\t\t%s: %s" % ("epAtt",epAtt) )
			if 5 in cbormap:
				largeBlobKey = cbormap[5]
				print("\t\t%s: %s" % ("largeBlobKey",largeBlobKey) )

		case Authenticator.GetAssertion:
			print("\tGetAssertion (response):")
			#print("\t\t: %s" % binascii.hexlify(data))
			cbormap = cbor2.decoder.loads(data)
			# required
			credential = cbormap[1]
			print("\t\t%s:" % ("credential") )
			print("\t\t\t%s: %s" % ("id",binascii.hexlify(credential["id"])) )
			print("\t\t\t%s: %s" % ("type",credential["type"]) )
			if "transports" in credential:
				print("\t\t\t%s: %s" % ("transports",credential["transports"]) )
			del(cbormap[1])
			authData = cbormap[2]
			print("\t\t%s: %s" % ("authData",binascii.hexlify(authData)) )
			del(cbormap[2])
			signature = cbormap[3]
			print("\t\t%s: %s" % ("signature",binascii.hexlify(signature)) )
			del(cbormap[3])
			# optional
			if 4 in cbormap:
				user = cbormap[4]
				print("\t\t%s: %s" % ("user",user) )
				del(cbormap[4])
			# and the rest...
			for i in cbormap:
				print("\t\t\tTODO???", i, cbormap[i])
		case Authenticator.GetInfo:
			print("\tGetInfo (response):")
			cbormap = cbor2.decoder.loads(data)
			# required
			versions = cbormap[1]
			print("\t\t%s: %s" % ("versions",versions) )
			del(cbormap[1])
			aaguid = cbormap[3]
			print("\t\t%s: %s" % ("aaguid",binascii.hexlify(aaguid)) )
			del(cbormap[3])
			# optional
			if 2 in cbormap:
				extensions = cbormap[2]
				print("\t\t%s: %s" % ("extensions",extensions) )
				del(cbormap[2])
			if 4 in cbormap:
				options = cbormap[4]
				print("\t\t%s: %s" % ("options",options) )
				del(cbormap[4])
			if 5 in cbormap:
				maxMsgSize = cbormap[5]
				print("\t\t%s: %s" % ("maxMsgSize",maxMsgSize) )
				del(cbormap[5])
			if 6 in cbormap:
				pinUvAuthProtocols = cbormap[6]
				print("\t\t%s: %s" % ("pinUvAuthProtocols",pinUvAuthProtocols) )
				del(cbormap[6])
			# and the rest...
			for i in cbormap:
				print("\t\t\tTODO???", i, cbormap[i])
		case _:
			print("\tTODO (response):")
			print("\t\t: %s" % binascii.hexlify(data))

def attestationStatement(fmt,attStmt):
	match fmt:
		case "packed":
			sig = attStmt['sig']
			print("\t\t\t%s: %s" % ("sig",binascii.hexlify(sig)) )
			del attStmt['sig']
			alg = attStmt['alg']
			print("\t\t\t%s: %s" % ("alg",alg) )
			del attStmt['alg']
			x5c = attStmt['x5c']
			print("\t\t\tx5c:")
			for cert in x5c:
				print("\t\t\t\t%s" % (base64.b64encode(cert) ))
			del attStmt['x5c']
			# should be nothing left...
			for i in attStmt:
				print("\t\t\tTODO???", i)
		case _:
			print("\t\t\tTODO", fmt)


### main

context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect('tcp://127.0.0.1:5678')
# subscribe to all messages (empty prefix filter)
socket.setsockopt_string(zmq.SUBSCRIBE, '')

command = 0
while True:
	report = socket.recv()
	#print(binascii.hexlify(report))

	(prefix,size,), report = struct.unpack("IB", report[:5]), report[5:]
	report, postfix = report[:size], report[size:]
	if(len(postfix)==4):
		msg_type = "response"
	else:
		msg_type = "request"
	(channelID,cmd,), report = struct.unpack(">IB", report[:5]), report[5:]
	if( cmd&0x80 ):
		command = cmd&0x7f
		(msg_size,), report = struct.unpack(">H", report[:2]), report[2:]
#		print("[%s] Command %i [%i bytes]" % (format(channelID, '08x'), cmd&127, msg_size))
		msg = report
		if( len(msg) > msg_size):
			msg = msg[:msg_size] # strip 0s
			u2fhid(command, msg, msg_type) # msg complete
	else:
#		print("[%s] Cont %i [%i bytes]" % (format(channelID, '08x'), cmd&0x7f, size))
		msg += report
		if( len(msg) > msg_size):
			msg = msg[:msg_size] # strip 0s
			u2fhid(command, msg, msg_type) # msg complete