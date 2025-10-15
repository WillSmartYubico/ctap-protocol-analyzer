# Grabs specific events from the Windows WebAuthN event log and runs them through the CTAP parser.
# TODO: provide a way to filter events based on a time range
# TODO: remove hard-coded limit to the number of processed events

from ctap_protocol_analyzer.ctap import u2fhid
import win32evtlog
import xml.etree.ElementTree as ET


hand = win32evtlog.EvtQuery(
    'C:\Windows\System32\winevt\Logs\Microsoft-Windows-WebAuthN%4Operational.evtx',
    win32evtlog.EvtQueryFilePath)



#hand = win32evtlog.OpenEventLog(None,"Microsoft-Windows-WebAuthN/Operational")
#print (win32evtlog.GetNumberOfEventLogRecords(hand))
read_count = 0
while True:
    # read 100 records
    events = win32evtlog.EvtNext(hand, 100)
    read_count += len(events)
    # if there is no record break the loop
    if len(events) == 0:
        break
    for event in events:
        xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
        

        # parse xml content
        xml = ET.fromstring(xml_content)
        # xml namespace, root element has a xmlns definition, so we have to use the namespace
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

        event_id = xml.find(f'.//{ns}EventID').text
        level = xml.find(f'.//{ns}Level').text
        #channel = xml.find(f'.//{ns}Channel').text
        #execution = xml.find(f'.//{ns}Execution')
        #process_id = execution.get('ProcessID')
        #thread_id = execution.get('ThreadID')
        time_created = xml.find(f'.//{ns}TimeCreated').get('SystemTime')
        
        
        
        eventdata = xml.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
        if (event_id == "2225") & (len(eventdata) > 0):
            print("================================================================================")
            #print(f'Time: {time_created}, Level: {level} Event Id: {event_id}, Channel: {channel}, Process Id: {process_id}, Thread Id: {thread_id}')
            print(f'Time: {time_created}, Level: {level} Event Id: {event_id}')
            
            #Dumping the XML may be nice?
            #print(xml_content)
            

            eventdatadict = {}
            fields = ("RequestCommand","Request", "ResponseCommand", "Response")

            for data in eventdata.findall("{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                #print ("Found Data")
                #print (data.attrib)
                
                if (data.get("Name") in fields):
                    eventdatadict[data.get("Name")] = data.text
                #print(f'{data.get("Name")} : {data.text}')


                #if (data.get("Name") =="Request"):
                    #cbor(Authenticator.MakeCredential,bytearray.fromhex(data.text))

            for command in ("RequestCommand", "ResponseCommand"):
                eventdatadict[command] = int (eventdatadict[command])
                eventdatadict[command] = eventdatadict[command] & 0x7f
            
            #eventdatadict["RequestCommand"] = int(eventdatadict["RequestCommand"])
            #if eventdatadict["RequestCommand"] > 128:
            #     eventdatadict["RequestCommand"] = eventdatadict["RequestCommand"] -128

            #eventdatadict["ResponseCommand"] = int(eventdatadict["ResponseCommand"])
            #if eventdatadict["ResponseCommand"] > 128:
            #     eventdatadict["ResponseCommand"] = eventdatadict["ResponseCommand"] -128

            #print (eventdatadict)

            
            #try:
                #cbor(eventdatadict["RequestCommand"],bytearray.fromhex(eventdatadict["Request"]))
                #cbor(eventdatadict["ResponseCommand"],bytearray.fromhex(eventdatadict["Response"]))
            #except:
                #print()
            

            if (eventdatadict["Request"]):
                try:
                    print("")
                    print ("Request:")
                    print('--------------------------------------------------------------------------------')
                    u2fhid(eventdatadict["RequestCommand"], bytearray.fromhex(eventdatadict["Request"]), "request")
                except:
                    print("Unable to parse request")
            else:
                print("Empty request")

            try:
                print("")
                print ("Response:")
                print('--------------------------------------------------------------------------------')
                u2fhid(eventdatadict["ResponseCommand"], bytearray.fromhex(eventdatadict["Response"]), "response")
            except:
                print("Unable to parse response")
            
            print("")
            
        # user_data has possible any data
    #if read_count > 10: 
    #    break    
print(f'Read {read_count} records')