# ctap-protocol-sniffer

Simple CTAP protocol sniffer on a Raspberry Pi

! WORK IN PROGRESS !

# Introduction

This is a quick and dirty implementation of a CTAP protocol sniffer using a Raspberry Pi 4.

## Install Raspbian

Download and install Raspberry Pi OS Lite (64 bit) on your Raspberry Pi 4, as documented
[here](https://www.raspberrypi.com/software/).

You can use an SD card or a USB flash drive.
If you install on a USB flash drive, you may need to
[enable this](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#usb-mass-storage-boot)
first.

## Install USBProxy

On your Raspberry Pi, install the latest release:

    bash -c "$(curl -fsSL https://raw.githubusercontent.com/nesto-software/USBProxy/master/scripts/install-from-release.sh)"

# Running your proxy

## Connecting your Pi

Your Pi 4's USB-C port will be configured in Device Mode, while the USB-A ports will be configured in Host Mode.
USB traffic will be relayed from and to these ports, such that the Pi 4 connected to your laptop or other device will appear as the FIDO security key connected to a USB-A port.

You may need a USB-A-to-C converter or a USB-C-to-A converter if you have a USB-C security key, or a client device with only USB-A ports.

Note that the PI will draw power from your USB-C port, so I doubt if that will work over USB-A with a converter. 
You may need a powererd USB hub for this but I haven't tried such scenario's.

## Sniffing CTAP

Insert your FIDO security key into one of the Pi's USB ports, and list all USB devices to discover the vendor and product IDs.

For instance, when a Google Titan U2F key is inserted:
```
$ ssh pi@raspberrypi.local lsusb
Bus 003 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 001 Device 003: ID 096e:0858 Feitian Technologies, Inc. U2F
Bus 001 Device 002: ID 2109:3431 VIA Labs, Inc. Hub
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
```
Here, the vendor ID is 096e, and the product ID is 0858.

Start USBProxy on your Pi, relaying all USB packets to and from the USB device with the specified vendor and product IDs, and tunneling zeroMQ traffic to your local system.

```
$ ssh pi@raspberrypi.local -L 5678:localhost:5678 sudo usb-mitm -v 096e -p 0858 -z
channel 3: open failed: connect failed: Connection refused
channel 4: open failed: connect failed: Connection refused
channel 3: open failed: connect failed: Connection refused
channel 3: open failed: connect failed: Connection refused
Loading plugins from /usr/lib/USBProxy/
Using the Nesto-specific ZeroMQ filter...
vendorId = 096e
productId = 0858
DeviceProxy::nice = 50
cleaning up /tmp
removing 0
Made directory /tmp/gadget-nzebkA for gadget
Printing Config data
	Strings: 5
		DeviceProxy: DeviceProxy_LibUSB
		DeviceProxy::nice: 50.
		HostProxy: HostProxy_GadgetFS
		productId: 0858
		vendorId: 096e
	Vectors: 1
		Plugins:
			PacketFilter_ZeroMQ
	Pointer: 0
Starting libusbEventLoop thread (2446) 
searching in [/tmp/gadget-nzebkA]
Starting setup writer thread (2450) for EP00.
Starting setup reader thread (2448) for EP00.
Device: 12 01 10 01 00 00 00 40 6e 09 58 08 00 44 01 02 00 01
  Manufacturer: FT
  Product:      U2F
	*Config(1): 09 02 29 00 01 01 00 80 0f
		Interface(0):
			*Alt(0): 09 04 00 00 02 03 00 00 05
			   Name: U2F
				HID: 09 21 00 01 00 01 22 22 00
				EP(84): 07 05 84 03 40 00 02
				EP(04): 07 05 04 03 40 00 02
============== Host Connect
Opened EP84
Opened EP04
Starting reader thread (2464) for EP84.
Starting writer thread (2465) for EP84.
Starting reader thread (2466) for EP04.
Starting writer thread (2467) for EP04.

```

Your PI is now proxying all USB traffic to and from your security key.

# Display USB traffic

The USBProxy repository contains an example application to view raw USB packets, published on a zeromq channel.

To run this application, you first need to install git, node, and npm. For instance on the Pi using:

    apt install -y git nodejs npm

To install and run, simply use the following commands from a terminal:

```
git clone https://github.com/nesto-software/USBProxy.git
cd USBProxy
npm install
node index.js
```

# Display CTAP traffic


To view CTAP protocol messages instead of raw USB packets, use the included python script.

First install its requirements:

    pip install cbor2 zmq

You can run one on the Pi itself, but as that traffic is also tunneled over SSH you can run it on your local system as well.

For example, the following output is generated when a U2F key is processing an authentication request:

```
$ python ctap.py 
--------------------------------------------------------------------------------
U2FHID_INIT[nonce=38a45af9aac8f81e]
U2FHID_INIT[nonce=38a45af9aac8f81e][channelID=00000009][version=2][major=1][minor=0][build=0][caps=3]
--------------------------------------------------------------------------------
U2FHID_MSG request:
	CLA=0 INS=2 Pn=0700 LCn=000081
	AUTHENTICATE (check-only)
	[challenge=b'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'][application=b'aeb0388497c8c3d375c157ee720698ac7878be870ad8f1aa99372fac5db45b54']
	[handle=b'e8aa5076468b7d088712c2a1629f77710141506f94c8b4977cef22cc78266a712de32600f06b73816e8f96c8f409ee9d550c2358b387c78ce03599b2402f4847']
U2FHID_MSG response:
	SW=6985 (response to 2)
	Conditions not satisfied
--------------------------------------------------------------------------------
U2FHID_MSG request:
	CLA=0 INS=2 Pn=0300 LCn=000081
	AUTHENTICATE (enforce-user-presence-and-sign)
	lc=000081
	[challenge=b'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'][application=b'aeb0388497c8c3d375c157ee720698ac7878be870ad8f1aa99372fac5db45b54']
	[handle=b'e8aa5076468b7d088712c2a1629f77710141506f94c8b4977cef22cc78266a712de32600f06b73816e8f96c8f409ee9d550c2358b387c78ce03599b2402f4847']
U2FHID_MSG response:
	SW=6985 (response to 2)
	Conditions not satisfied
--------------------------------------------------------------------------------
U2FHID_MSG request:
	CLA=0 INS=2 Pn=0300 LCn=000081
	AUTHENTICATE (enforce-user-presence-and-sign)
	lc=000081
	[challenge=b'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'][application=b'aeb0388497c8c3d375c157ee720698ac7878be870ad8f1aa99372fac5db45b54']
	[handle=b'e8aa5076468b7d088712c2a1629f77710141506f94c8b4977cef22cc78266a712de32600f06b73816e8f96c8f409ee9d550c2358b387c78ce03599b2402f4847']
U2FHID_MSG response:
	SW=9000 (response to 2)
	AUTHENTICATE=2
	[up=1][counter=2][signature=b'304402203fc73580f7066e79d709e40a97b1ccdc56ee4c11ce4239fa59855aab6096d6f0022079fa00709e219d342feb45f5ad7cafb4ba02a2b55465801c3b62b705770d0470']

```


# Acknowledgements

Credit is due to all the contributers to 
[https://github.com/nesto-software/USBProxy](https://github.com/nesto-software/USBProxy)
and
[https://github.com/usb-tools/USBProxy-legacy](https://github.com/usb-tools/USBProxy-legacy)
for developing USBProxy.

