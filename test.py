from netzob.all import *
filename="/home/wxw/modbus-new.pcap"
print filename.__class__
messages_session1 = PCAPImporter.readFile(filename).values()
print messages_session1

