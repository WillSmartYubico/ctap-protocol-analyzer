"""
Quick and dirty parsing of CTAP messages.
This is a proof of concept, and a work in progress. Please ignore its ugliness for now...
"""

#import zmq
import binascii
import struct
import base64
#from cryptography import x509
import cbor2
import json

import csv
import re
import sys

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
	MakeCredential                      = 0x01
	GetAssertion                        = 0x02
	GetInfo                             = 0x04
	ClientPIN                           = 0x06
	Reset                               = 0x07
	GetNextAssertion                    = 0x08
	AuthenticatorBioEnrollment          = 0x09
	PrototypeAuthenticatorBioEnrollment = 0x40
	AuthenticatorCredentialManagement   = 0x41
	VendorFirst                         = 0x40
	VendorLast                          = 0xbf

CTAP2_OK = 0x00

status_codes = {
  0x00: 'CTAP1_ERR_SUCCESS',    # Indicates successful response. (CTAP2_OK)
  0x01: 'CTAP1_ERR_INVALID_COMMAND',    # The command is not a valid CTAP command.
  0x02: 'CTAP1_ERR_INVALID_PARAMETER',  # The command included an invalid parameter.
  0x03: 'CTAP1_ERR_INVALID_LENGTH',     # Invalid message or item length.
  0x04: 'CTAP1_ERR_INVALID_SEQ',        # Invalid message sequencing.
  0x05: 'CTAP1_ERR_TIMEOUT',    # Message timed out.
  0x06: 'CTAP1_ERR_CHANNEL_BUSY',       # Channel busy. Client SHOULD retry the request after a short delay. Note that the client MAY abort the transaction if the command is no longer relevant.
  0x0A: 'CTAP1_ERR_LOCK_REQUIRED',      # Command requires channel lock.
  0x0B: 'CTAP1_ERR_INVALID_CHANNEL',    # Command not allowed on this cid.
  0x11: 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE',       # Invalid/unexpected CBOR error.
  0x12: 'CTAP2_ERR_INVALID_CBOR',       # Error when parsing CBOR.
  0x14: 'CTAP2_ERR_MISSING_PARAMETER',  # Missing non-optional parameter.
  0x15: 'CTAP2_ERR_LIMIT_EXCEEDED',     # Limit for number of items exceeded.
  0x17: 'CTAP2_ERR_FP_DATABASE_FULL',   # Fingerprint data base is full, e.g., during enrollment.
  0x18: 'CTAP2_ERR_LARGE_BLOB_STORAGE_FULL',    # Large blob storage is full. (See § 6.10.3 Large, per-credential blobs.)
  0x19: 'CTAP2_ERR_CREDENTIAL_EXCLUDED',        # Valid credential found in the exclude list.
  0x21: 'CTAP2_ERR_PROCESSING', # Processing (Lengthy operation is in progress).
  0x22: 'CTAP2_ERR_INVALID_CREDENTIAL', # Credential not valid for the authenticator.
  0x23: 'CTAP2_ERR_USER_ACTION_PENDING',        # Authentication is waiting for user interaction.
  0x24: 'CTAP2_ERR_OPERATION_PENDING',  # Processing, lengthy operation is in progress.
  0x25: 'CTAP2_ERR_NO_OPERATIONS',      # No request is pending.
  0x26: 'CTAP2_ERR_UNSUPPORTED_ALGORITHM',      # Authenticator does not support requested algorithm.
  0x27: 'CTAP2_ERR_OPERATION_DENIED',   # Not authorized for requested operation.
  0x28: 'CTAP2_ERR_KEY_STORE_FULL',     # Internal key storage is full.
  0x2B: 'CTAP2_ERR_UNSUPPORTED_OPTION', # Unsupported option.
  0x2C: 'CTAP2_ERR_INVALID_OPTION',     # Not a valid option for current operation.
  0x2D: 'CTAP2_ERR_KEEPALIVE_CANCEL',   # Pending keep alive was cancelled.
  0x2E: 'CTAP2_ERR_NO_CREDENTIALS',     # No valid credentials provided.
  0x2F: 'CTAP2_ERR_USER_ACTION_TIMEOUT',        # A user action timeout occurred.
  0x30: 'CTAP2_ERR_NOT_ALLOWED',        # Continuation command, such as, authenticatorGetNextAssertion not allowed.
  0x31: 'CTAP2_ERR_PIN_INVALID',        # PIN Invalid.
  0x32: 'CTAP2_ERR_PIN_BLOCKED',        # PIN Blocked.
  0x33: 'CTAP2_ERR_PIN_AUTH_INVALID',   # PIN authentication,pinUvAuthParam, verification failed.
  0x34: 'CTAP2_ERR_PIN_AUTH_BLOCKED',   # PIN authentication using pinUvAuthToken blocked. Requires power cycle to reset.
  0x35: 'CTAP2_ERR_PIN_NOT_SET',        # No PIN has been set.
  0x36: 'CTAP2_ERR_PUAT_REQUIRED',      # A pinUvAuthToken is required for the selected operation. See also the pinUvAuthToken option ID.
  0x37: 'CTAP2_ERR_PIN_POLICY_VIOLATION',       # PIN policy violation. Minimum PIN length or PIN complexity may trigger this error. The platform should check the minimum PIN length in authenticatorGetInfo to discriminate between the causes of this error.
  0x38: 'Reserved for Future Use',      # Reserved for Future Use
  0x39: 'CTAP2_ERR_REQUEST_TOO_LARGE',  # Authenticator cannot handle this request due to memory constraints.
  0x3A: 'CTAP2_ERR_ACTION_TIMEOUT',     # The current operation has timed out.
  0x3B: 'CTAP2_ERR_UP_REQUIRED',        # User presence is required for the requested operation.
  0x3C: 'CTAP2_ERR_UV_BLOCKED', # built-in user verification is disabled.
  0x3D: 'CTAP2_ERR_INTEGRITY_FAILURE',  # A checksum did not match.
  0x3E: 'CTAP2_ERR_INVALID_SUBCOMMAND', # The requested subcommand is either invalid or not implemented.
  0x3F: 'CTAP2_ERR_UV_INVALID', # built-in user verification unsuccessful. The platform SHOULD retry.
  0x40: 'CTAP2_ERR_UNAUTHORIZED_PERMISSION',    # The permissions parameter contains an unauthorized permission.
  0x7F: 'CTAP1_ERR_OTHER',      # Other unspecified error.
  0xDF: 'CTAP2_ERR_SPEC_LAST',  # CTAP 2 spec last error.
  0xE0: 'CTAP2_ERR_EXTENSION_FIRST',    # Extension specific error.
  0xEF: 'CTAP2_ERR_EXTENSION_LAST',     # Extension specific error.
  0xF0: 'CTAP2_ERR_VENDOR_FIRST',       # Vendor specific error.
  0xFF: 'CTAP2_ERR_VENDOR_LAST',        # Vendor specific error.
}

makeCredentialKeys = {
  # required
  0x01: 'clientDataHash', # Hash of the ClientData contextual binding specified by host
  0x02: 'rp', # This PublicKeyCredentialRpEntity data structure describes a Relying Party with which the new public key credential will be associated
  0x03: 'user', # This PublicKeyCredentialUserEntity data structure describes the user account to which the new public key credential will be associated at the RP.
  0x04: 'pubKeyCredParams', # List of supported algorithms for credential generation, as specified in [WebAuthn]
  # optional
  0x05: 'excludeList', # An array of PublicKeyCredentialDescriptor structures, as specified in [WebAuthn]
  0x06: 'extensions', # Parameters to influence authenticator operation, as specified in [WebAuthn]
  0x07: 'options', # Parameters to influence authenticator operation, as specified in in the table below.
  0x08: 'pinUvAuthParam', # Result of calling authenticate(pinUvAuthToken, clientDataHash)
  0x09: 'pinUvAuthProtocol', # PIN/UV protocol version chosen by the platform
  0x0a: 'enterpriseAttestation', # An authenticator supporting this enterprise attestation feature is enterprise attestation capable and signals its support via the ep Option ID in the authenticatorGetInfo command response.
  0x0b: 'attestationFormatsPreference', # A prioritized list of attestation statement format identifiers that the client and/or RP prefers
}

makeCredentialResponseKeys = {
  # required
  0x01: 'fmt', # The attestation statement format identifier.
  0x02: 'authData', # The authenticator data object.
  # optional
  0x03: 'attStmt', # The attestation statement
  0x04: 'epAtt', # Indicates whether an enterprise attestation was returned for this credential
  0x05: 'largeBlobKey', # the largeBlobKey for the credential
  0x06: 'unsignedExtensionOutputs', # unsigned outputs of extensions
}

getAssertionKeys = {
  # required
  0x01: 'rpId (0x01)',	# relying party identifier
  0x02: 'clientDataHash (0x02)',	# Hash of the serialized client data collected by the host
  # optional
  0x03: 'allowList (0x03)',	# 	An array of PublicKeyCredentialDescriptor structures
  0x04: 'extensions (0x04)',	# 	Parameters to influence authenticator operation
  0x05: 'options (0x05)',	# 	Parameters to influence authenticator operation
  0x06: 'pinUvAuthParam (0x06)',	# 	Result of calling authenticate(pinUvAuthToken, clientDataHash)
  0x07: 'pinUvAuthProtocol (0x07)',	# 	PIN/UV protocol version selected by platform
}

getAssertionResponseKeys = {
  # required
  0x01: 'credential (0x01)',	# PublicKeyCredentialDescriptor structure containing the credential identifier whose private key was used to generate the assertion
  0x02: 'authData (0x02)',	# The signed-over contextual bindings made by the authenticator
  0x03: 'signature (0x03)',	# The assertion signature produced by the authenticator
  # optional
  0x04: 'user (0x04)',	# PublicKeyCredentialUserEntity structure containing the user account information
  0x05: 'numberOfCredentials (0x05)',	# Total number of account credentials for the RP
  0x06: 'userSelected (0x06)',	# Indicates that a credential was selected by the user via interaction directly with the authenticator
  0x07: 'largeBlobKey (0x07)',	# The contents of the associated largeBlobKey if present for the asserted credential, and if largeBlobKey was true in the extensions input
  0x08: 'unsignedExtensionOutputs (0x08)',	# unsigned outputs of extensions
}

# https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#authenticatorGetInfo
info = {
  0x01: 'versions',
  0x02: 'extensions',
  0x03: 'aaguid', 
  0x04: 'options',
  0x05: 'maxMsgSize',
  0x06: 'pinUvAuthProtocols',
  0x07: 'maxCredentialCountInList',
  0x08: 'maxCredentialIdLength',
  0x09: 'transports',
  0x0A: 'algorithms',
  0x0B: 'maxSerializedLargeBlobArray',
  0x0C: 'forcePINChange',
  0x0D: 'minPINLength',
  0x0E: 'firmwareVersion', 
  0x0F: 'maxCredBlobLength',
  0x10: 'maxRPIDsForSetMinPINLength',
  0x11: 'preferredPlatformUvAttempts',
  0x12: 'uvModality',
  0x13: 'certifications',
  0x14: 'remainingDiscoverableCredentials',
  0x15: 'vendorPrototypeConfigCommands',
  0x16: 'attestationFormats', 
  0x17: 'uvCountSinceLastPinEntry',
  0x18: 'longTouchForReset',
  0x19: 'encIdentifier',
  0x1A: 'transportsForReset',
  0x1B: 'pinComplexityPolicy',
  0x1C: 'pinComplexityPolicyURL',
  0x1D: 'maxPINLength',
}

clientPinKeys = {
  0x01: 'pinUvAuthProtocol', 	# PIN/UV protocol version chosen by the platform. This MUST be a value supported by the authenticator, as determined by the pinUvAuthProtocols field of the authenticatorGetInfo response.
  0x02: 'subCommand', 	# The specific action being requested.
  0x03: 'keyAgreement', 	# The platform key-agreement key. This COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
  0x04: 'pinUvAuthParam', 	# The output of calling authenticate on some context specific to the subcommand.
  0x05: 'newPinEnc', 	# An encrypted PIN.
  0x06: 'pinHashEnc', 	# An encrypted proof-of-knowledge of a PIN.
  0x09: 'permissions', 	# Bitfield of permissions. If present, MUST NOT be 0. See § 6.5.5.7 Operations to Obtain a pinUvAuthToken.
  0x0a: 'rpId', 	# The RP ID to assign as the permissions RP ID.
}

clientPinSubCommandoKeys = {
  0x01: 'getPINRetries',
  0x02: 'getKeyAgreement',
  0x03: 'setPIN',
  0x04: 'changePIN',
  0x05: 'getPinToken ',	# superseded by getPinUvAuthTokenUsingUvWithPermissions or getPinUvAuthTokenUsingPinWithPermissions, thus for backwards compatibility only
  0x06: 'getPinUvAuthTokenUsingUvWithPermissions',
  0x07: 'getUVRetries',
  0x09: 'getPinUvAuthTokenUsingPinWithPermissions',
}

clientPinResponseKeys = {
  0x01: 'KeyAgreement', # The result of the authenticator calling getPublicKey
  0x02: 'pinUvAuthToken', # The pinUvAuthToken, encrypted by calling encrypt with the shared secret as the key.
  0x03: 'pinRetries', # Number of PIN attempts remaining before lockout. This is optionally used to show in UI when collecting the PIN in setting a new PIN, changing existing PIN and obtaining a pinUvAuthToken flows.
  0x04: 'powerCycleState', # Present and true if the authenticator requires a power cycle before any future PIN operation
  0x05: 'uvRetries',	# Number of uv attempts remaining before lockout.
}

authenticatorBioEnrollmentKeys = {
  0x01: 'modality', 	# The user verification modality being requested
  0x02: 'subCommand', 	# The authenticator user verification sub command currently being requested
  0x03: 'subCommandParams', 	# Map of subCommands parameters. This parameter MAY be omitted when the subCommand does not take any arguments.
  0x04: 'pinUvAuthProtocol', 	# PIN/UV protocol version chosen by the platform.
  0x05: 'pinUvAuthParam', 	# The output of calling authenticate on some context specific to the subcommand.
  0x06: 'getModality', 	# Get the user verification type modality. This MUST be set to true.
}

authenticatorBioEnrollmentSubcommandKeys = {
  0x01: 'enrollBegin',
  0x02: 'enrollCaptureNextSample',
  0x03: 'cancelCurrentEnrollment',
  0x04: 'enumerateEnrollments',
  0x05: 'setFriendlyName',
  0x06: 'removeEnrollment',
  0x07: 'getFingerprintSensorInfo',
}

authenticatorBioEnrollmentResponseKeys = {
  0x01: 'modality',	# The user verification modality.
  0x02: 'fingerprintKind',	# Indicates the type of fingerprint sensor. For touch type sensor, its value is 1. For swipe type sensor its value is 2.
  0x03: 'maxCaptureSamplesRequiredForEnroll',	# Indicates the maximum good samples required for enrollment.
  0x04: 'templateId',	# Template Identifier.
  0x05: 'lastEnrollSampleStatus',	# Last enrollment sample status.
  0x06: 'remainingSamples',	# Number of more sample required for enrollment to complete
  0x07: 'templateInfos',	# Array of templateInfo’s
  0x08: 'maxTemplateFriendlyName',	# Indicates the maximum number of bytes the authenticator will accept as a templateFriendlyName.
}


# maintain some state
current_transaction = 0	# transaction
current_cbor_cmd = 0 # cbor cmd
# TODO: also maintain channel IDs to support concurrent transactions

### U2FHID protocol messages
# https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-hid-protocol-ps-20141009.html#u2fhid-protocol-implementation
# https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-u2f_hid.h-v1.0-ps-20141009.txt

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            return obj.hex()
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

def map_keys(d, m):
    for k, v in d.copy().items():
        d.pop(k)
        mk = m[k]
        d[mk] = v
    return d

def map_hex(d):
	for k, v in d.copy().items():
		match v:
			case bytes():
				d[k] = '0x' + v.hex()
			case dict():
				d[k] = map_hex(v)
			case _:	
				d[k] = v
	return d


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
			print("CTAPHID_CBOR[0x%02x]" % ctap_cmd)
			cbor(ctap_cmd,msg)
		case CTAPHID.CANCEL:
			print("CTAPHID_CANCEL[%i]" % cmd)
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
			(ctap_status_code,), msg = struct.unpack("B", msg[:1]), msg[1:]
			print("U2FHID_ERROR[0x%02x]" % ctap_status_code)
			if ctap_status_code != CTAP2_OK:
				print("\t\tERROR:", status_codes[ctap_status_code])
		case U2FHID.WINK:
			print("U2FHID_WINK[TODO]")
		case U2FHID.SYNC:
			print("U2FHID_SYNC")
		case U2FHID.LOCK:
			print("U2FHID_LOCK[TODO]")
		case CTAPHID.CBOR:
			(ctap_status_code,), msg = struct.unpack("B", msg[:1]), msg[1:]
			print("CTAPHID_CBOR[0x%02x]" % ctap_status_code)
			if ctap_status_code != CTAP2_OK:
				print("\t\tERROR:", status_codes[ctap_status_code])
				return
			cbor(0,msg)
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
			print("unknown command response=%i" % cmd)

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
	print("CMD: %x : %s" % (cmd, binascii.hexlify(data)))
	match cmd:
		case 0:
			cbor_response(current_cbor_cmd, data)
		case Authenticator.MakeCredential:
			print("\tMakeCredential:")
			cbormap = cbor2.loads(data)
			# required
			clientDataHash = cbormap[1]
			rp = cbormap[2]
			user = cbormap[3]
			pubKeyCredParams = cbormap[4]
			print("\t\tclientDataHash: %s" % binascii.hexlify(clientDataHash))
			print("\t\trp: %s" % rp)
			print("\t\tuser: %s" % user)
			print("\t\tpubKeyCredParams: %s" % pubKeyCredParams)
			del cbormap[1]; del cbormap[2]; del cbormap[3]; del cbormap[4]
			# TODO: what else is there?
			# optional
			for k,v in cbormap.items():
				print("\t\t%s(%x): %s" % (makeCredentialKeys[k], k, v) )
		case Authenticator.GetAssertion:
			print("\tGetAssertion:")
			cbormap = cbor2.loads(data)
			# required
			rpId = cbormap[1]
			print("\t\t%s: %s" % ("rpId",rpId) )
			del(cbormap[1])
			clientDataHash = cbormap[2]
			print("\t\t%s: %s" % ("clientDataHash",binascii.hexlify(clientDataHash)) )
			del(cbormap[2])
			# optional
			for k,v in cbormap.items():
				print("\t\t%s(%x): %s" % (getAssertionKeys[k], k, v) )
		case Authenticator.GetInfo:
			print("\tGetInfo")
		case Authenticator.ClientPIN:
			cbormap = cbor2.loads(data)
			print("\tClientPIN", cbormap)
			# required
			subCommand = cbormap[2]
			print("\t\t%s: %s" % (clientPinKeys[2], clientPinSubCommandoKeys[subCommand]) )
			del(cbormap[2])
			# rest
			for k,v in cbormap.items():
				print("\t\t%s: %s" % (clientPinKeys[k], v) )
		case Authenticator.GetNextAssertion:
			print("\tGetNextAssertion:")
			cbormap = cbor2.loads(data)
			for k,v in cbormap.items():
				print("\t\t%i: %s" % (k, v) )
		case Authenticator.AuthenticatorBioEnrollment:
			cbormap = cbor2.loads(data)
			print("\tAuthenticatorBioEnrollment", cbormap)
			if 2 in cbormap:
				subCommand = cbormap[2]
				print("\t\t%s: %s" % (authenticatorBioEnrollmentKeys[2], authenticatorBioEnrollmentSubcommandKeys[subCommand]) )
				del(cbormap[2])
			for k,v in cbormap.items():
				print("\t\t%s: %s" % (authenticatorBioEnrollmentKeys[k], v) )
		case Authenticator.PrototypeAuthenticatorBioEnrollment:
			cbormap = cbor2.loads(data)
			print("\tAuthenticatorBioEnrollment (FIDO_2_1_PRE)", cbormap)
			if 2 in cbormap:
				subCommand = cbormap[2]
				print("\t\t%s: %s" % (authenticatorBioEnrollmentKeys[2], authenticatorBioEnrollmentSubcommandKeys[subCommand]) )
				del(cbormap[2])
			for k,v in cbormap.items():
				print("\t\t%s: %s" % (authenticatorBioEnrollmentKeys[k], v) )
		case Authenticator.AuthenticatorCredentialManagement:
			cbormap = cbor2.loads(data)
			print("\tAuthenticatorCredentialManagement (FIDO_2_1_PRE)", cbormap)
			authenticatorCredentialManagement(cbormap)
		case _:
			print("\t\tTODO", cmd)
			print("\t\t: %s" % binascii.hexlify(data))
	current_cbor_cmd = cmd	# remember cmd to be able to interpret response

def cbor_response(cmd, data):
	match cmd:
		case Authenticator.MakeCredential:
			print("\tMakeCredential (response):")
			#print("\t\t: %s" % binascii.hexlify(data))
			cbormap = cbor2.loads(data)
			# required
			fmt = cbormap[1]
			del(cbormap[1])
			print("\t\t%s: %s" % ("fmt",fmt) )
			authData = cbormap[2]
			del(cbormap[2])
			print("\t\t%s: %s" % ("authData", binascii.hexlify(authData)) )
			attStmt = cbormap[3]
			del(cbormap[3])
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
			# optional
			for k,v in cbormap.items():
				print("\t\t%s(%x): %s" % (makeCredentialResponseKeys[k], k, v) )

		case Authenticator.GetAssertion:
			print("\tGetAssertion (response):")
			#print("\t\t: %s" % binascii.hexlify(data))
			cbormap = cbor2.loads(data)
			# required
			#jsonified = json.dumps( cbormap, indent=4, cls=MyEncoder )
			#print(jsonified)
			#jsonified = json.dumps( map_keys(cbormap,getAssertionResponseKeys), indent=4, cls=MyEncoder )
			#print(jsonified)
			credential = cbormap[1]
			print("\t\t%s:" % ("credential") )
			print("\t\t\t%s: %s" % ("id",binascii.hexlify(credential["id"])) )
			print("\t\t\t%s: %s" % ("type",credential["type"]) )
			###
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
			for k,v in cbormap.items():
				print("\t\t%s(%x): %s" % (getAssertionResponseKeys[k], k, v) )
		case Authenticator.GetInfo:
			cbormap = cbor2.loads(data)
			print("\tGetInfo (response):", cbormap)
			# required
			versions = cbormap[1]
			print("\t\t%s: %s" % ("versions",versions) )
			del(cbormap[1])
			aaguid = cbormap[3]
			print("\t\t%s: %s" % ("aaguid",binascii.hexlify(aaguid)) )
			del(cbormap[3])
			# optional
			for k,v in cbormap.items():
				print("\t\t%s: %s" % (info[k], v) )
		case Authenticator.ClientPIN:
			cbormap = cbor2.loads(data)
			print("\tClientPIN", cbormap)
			# optional
			for k,v in cbormap.items():
				print("\t\t%s: %s" % (clientPinResponseKeys[k], v) )
		case Authenticator.AuthenticatorBioEnrollment:
			cbormap = cbor2.loads(data)
			print("\tAuthenticatorBioEnrollment", cbormap)
			# optional
			for k,v in cbormap.items():
				print("\t\t%s: %s" % (authenticatorBioEnrollmentResponseKeys[k], v) )
		case Authenticator.PrototypeAuthenticatorBioEnrollment:
			cbormap = cbor2.loads(data)
			print("\tAuthenticatorBioEnrollment (FIDO_2_1_PRE)", cbormap)
			# optional
			for k,v in cbormap.items():
				print("\t\t%s: %s" % (authenticatorBioEnrollmentResponseKeys[k], v) )
		case Authenticator.AuthenticatorCredentialManagement:
			cbormap = cbor2.loads(data)
			print("\tAuthenticatorCredentialManagement (FIDO_2_1_PRE)", cbormap)
			authenticatorCredentialManagementResponse(cbormap)
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

# manage discoverable credentials
authenticatorCredentialManagementKeys = {
  0x01: 'subCommand',
  0x02: 'subCommandParams',
  0x03: 'pinUvAuthProtocol',
  0x04: 'pinUvAuthParam', 	# First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken
}

authenticatorCredentialManagementSubcommandKeys = {
  0x01: 'getCredsMetadata',
  0x02: 'enumerateRPsBegin',
  0x03: 'enumerateRPsGetNextRP',
  0x04: 'enumerateCredentialsBegin',
  0x05: 'enumerateCredentialsGetNextCredential',
  0x06: 'deleteCredential',
  0x07: 'updateUserInformation',
}

authenticatorCredentialManagementSubcommandParamKeys = {
  0x01: 'rpIDHash',
  0x02: 'credentialID',
  0x03: 'user',
}

authenticatorCredentialManagementResponseKeys = {
	0x01: 'existingResidentCredentialsCount',
	0x02: 'maxPossibleRemainingResidentCredentialsCount',
	0x03: 'rp',
	0x04: 'rpIDHash',
	0x05: 'totalRPs',
	0x06: 'user',
	0x07: 'credentialID',
	0x08: 'publicKey',
	0x09: 'totalCredentials',
	0x0a: 'credProtect',
	0x0b: 'largeBlobKey',
	0x0c: 'thirdPartyPayment',
}

import pprint

def authenticatorCredentialManagementSubcommandParam(cbormap):
	map_hex(cbormap)
	for k,v in cbormap.items():
		name = authenticatorCredentialManagementSubcommandParamKeys[k]
		match k:
			case 0x01: # rpIDHash
				value = binascii.hexlify(v)
			case 0x02: # credentialID
				value = binascii.hexlify(v)
			case _:
				value = v
		print("\t\t%s (%i): %s" % (name, k, value) )

def authenticatorCredentialManagement(cbormap):
	map_hex(cbormap)
	for k,v in cbormap.items():
		name = authenticatorCredentialManagementKeys[k]
		match k:
			case 0x01: # subCommand
				value = "%s (%i)" % (authenticatorCredentialManagementSubcommandKeys[v],v)
			case 0x02: # subCommandParams
				# value = authenticatorCredentialManagementSubcommandParam(v)
				value = (v)
			case _:
				value = v
		print("\t\t%s (%i): %s" % (name, k, value) )


def authenticatorCredentialManagementResponse_(cbormap):
	map_hex(cbormap)
	for k,v in cbormap.items():
		name = authenticatorCredentialManagementResponseKeys[k]
		value = v
		print("\t\t%s (%i): %s" % (name, k, value) )

def authenticatorCredentialManagementResponse(cbormap):
	map_hex(cbormap)
	map_keys(cbormap)
	for k,v in cbormap.items():
		name = authenticatorCredentialManagementResponseKeys[k]
		value = v
		print("\t\t%s (%i): %s" % (name, k, value) )


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


#context = zmq.Context()
#socket = context.socket(zmq.SUB)
#socket.connect('tcp://127.0.0.1:5678')
# subscribe to all messages (empty prefix filter)
#socket.setsockopt_string(zmq.SUBSCRIBE, '')

ctap_devices = []

with open(file, mode='r', newline='') as file:
	reader = csv.DictReader(filter_csv_comments(file))
	headers = reader.fieldnames
	command = 0

	print(headers)

	msg = bytearray()
	for row in reader:
		#print (row['Len'])
		if (re.search("txn", row["Record"]) and (row['Len'] == "64 B")):
			#and (row['Dev'] == "01")  and (row['Ep'] != "00")
			
			if (re.match("OUT",row["Record"])):
				msg_type = "request"
			else:
				msg_type = "response"

			report = bytearray.fromhex( row['Data'])

			
			#(prefix,size,), report = struct.unpack("IB", report[:5]), report[5:]
			#report, postfix = report[:size], report[size:]

			(channelID,cmd,), report = struct.unpack(">IB", report[:5]), report[5:]
			#print("%s" % format(channelID, '08x'))
			if format(channelID, '08x') == 'ffffffff': #look for CTAP channel requests
				ctap_devices.append((row["Dev"],row["Ep"]))
				print("Detected CTAP channel request.  Device %s endpoint %s added to CTAP devices list" % (row["Dev"],row["Ep"]))
			
			if (row["Dev"],row["Ep"]) in ctap_devices:
				#print("Device OK")

				#print(channelID)
				#print(cmd)
				if( cmd&0x80 ):
					command = cmd&0x7f
					(msg_size,), report = struct.unpack(">H", report[:2]), report[2:]
					print("Index %s Channel [%s] Command %s [%i bytes]" % (row['Index'], format(channelID, '08x'), format(cmd&0x7f, '02x'), msg_size))
					msg = report
					if( len(msg) > msg_size):
						msg = msg[:msg_size] # strip 0s
						u2fhid(command, msg, msg_type) # msg complete
				else:
					print("Index %s Channel [%s] Cont %s" % (row['Index'], format(channelID, '08x'), format(cmd&0x7f, '02x')))
					if msg:
						msg += report
						if( len(msg) > msg_size):
							msg = msg[:msg_size] # strip 0s
							u2fhid(command, msg, msg_type) # msg complete
					else:
						print("Index %s Channel [%s] Cont %s without corresponding command packet" % (row['Index'], format(channelID, '08x'), format(cmd&0x7f, '02x')))
			else:
				print("Device %s endpoint %s not on CTAP devices list" % (row["Dev"],row["Ep"]))
