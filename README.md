# ctap-protocol-analyzer

Decodes Universal Two Factor (U2F) and Client To Authenticator Protocol (CTAP) messages to make inspecting FIDO2 Security Keys easier.

This module is designed to take inputs (raw bytes) from various logging facilities, and based on those inputs to  produce a description of the CTAP messages on stdout.

# examples

## ctap-totalphasecsv.py

Takes the path to a CSV Export by the TotalPhase DataCenter application from a Beagle USB Analyzer.

## ctap-winevent.py 

Scans the local computer's Microsoft-Windows-WebAuthN Operational log and decodes all of the instances of event 2225, which contains CTAP messages. 

# Acknowledgements

Almost all of the `ctap.py` code here has been written by   
[Joost van Dijk](https://github.com/joostd), I'm just trying to make it easier for to use.
