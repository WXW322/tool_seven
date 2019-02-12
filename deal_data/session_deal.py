
from netzob.all import *
from pyshark import *
import scapy.all as scapy
from scapy.utils import PcapReader,PcapWriter
import sys
import os
sys.path.append('../classify_6/frequent_find')
import series_find
import find_one
class session_deal:
    def __init__(self,filename):
        if filename != "":
            self.messages = PCAPImporter.readFile(filename).values()
            self.filename = filename
        else:
            self.messages = []
            self.filename = ""

    def get_ip(self,t_str):
        t_lo = t_str.find(':')
        return t_str[0:t_lo]


    def noise_remove(self,filename,protocolname,t_lo):
        package_two = FileCapture(filename)
        package_pr = scapy.PcapReader(filename)
        package_one = []
        i = 1
        while(True):
            package = package_pr.read_packet()
            if package is None:
                break
            package_one.append(package)
        package_pr.close()
        package_three = []
        length = len(package_one)
        i = 0
        while(i < length):
            if package_two[i].layers[t_lo].layer_name == protocolname:
                package_three.append(package_one[i])
            i = i + 1
        t_writer = PcapWriter('/home/wxw/data/' + 'modbus_pure' + '.pcap', append=True)
        for p in package_three:
            t_writer.write(p)
        t_writer.flush()
        t_writer.close()

    def get_104sessions(self):
        src = self.get_ip(self.messages[0].source)
        des = self.get_ip(self.messages[0].destination)
        self.final_sessions = []
        t_lo = 0
        length = len(self.messages)
        i = 0
        while(i < length):
            t_session = []
            j = i
            while(j < length):
                if self.get_ip(self.messages[j].source) == src:
                    t_session.append(self.messages[j])
                    j = j + 1
                    t_length = len(t_session)
                    if len(t_session) <= 2:
                        continue
                    elif self.get_ip(t_session[-2].source) == src and self.get_ip(t_session[-3].source) == src:
                        t_lo = 1
                elif t_lo == 0:
                    t_session.append(self.messages[j])
                    j = j + 1
                else:
                    t_session.append(self.messages[j])
                    t_session.append(self.messages[j+1])
                    j = j + 1
                    self.final_sessions.append(t_session)
                    break
            i = j + 1
            t_lo = 0
        return self.final_sessions

    def get_sessionsbytime(self):
        print ('aa')


    def clus_sesionbydi(self,messages):
        src = self.get_ip(messages[0].source)
        des = self.get_ip(messages[0].destination)
        srcs = []
        dess = []
        for message in messages:
            if(self.get_ip(message.source) == src):
                srcs.append(message)
            else:
                dess.append(message)
        return srcs,dess

    def get_evisession(self,t_lo, gap):
        t_result = {}
        for data in self.messages:
            t_key = data.data[t_lo:t_lo + gap]
            if t_key not in t_result:
                t_result[t_key] = []
                t_result[t_key].append(data)
            else:
                t_result[t_key].append(data)
        return t_result

    def split_pcap(self,filename,rate):
        package_pr = scapy.PcapReader(filename)
        package_one = []
        i = 1
        while(True):
            package = package_pr.read_packet()
            if package is None:
                break
            package_one.append(package)
        package_pr.close()
        length = len(package_one)
        i = 0
        final_len = int(length * length)
        t_writer = PcapWriter('/home/wxw/data/Ethernetip/' + 'modbus_pure' + '.pcap', append=True)
        for p in package_one[0:final_len]:
            t_writer.write(p)
        t_writer.flush()
        t_writer.close()

    def get_changes(self):
        """
        change the raw datas to session show
        :return:
        """
        src = self.messages[0].source
        des = self.messages[0].destination
        i = 0
        changes = []
        while(i < len(self.messages)):
            if (self.messages[i].source == src):
                j = i + 1
                while(j < len(self.messages) and self.messages[j].source == src):
                    j = j + 1
                if(j - i >= 2):
                    t_message = []
                    for lo in range(i,j):
                        t_message.append(self.messages[lo])
                    changes.append((3,t_message))
                else:
                    t_message = []
                    for lo in range(i,j):
                        t_message.append(self.messages[lo])
                    changes.append((1,t_message))
                i = j
            else:
                j = i + 1
                while (j < len(self.messages) and self.messages[j].source == des):
                    j = j + 1
                if (j - i >= 2):
                    t_message = []
                    for lo in range(i, j):
                        t_message.append(self.messages[lo])
                    changes.append((4,t_message))
                else:
                    t_message = []
                    for lo in range(i, j):
                        t_message.append(self.messages[lo])
                    changes.append((2,t_message))
                i = j
        return changes















#data_deal.split_pcap('/home/wxw/data/Ethernetip/cip.pcap',0.1)
#data_deal.noise_remove('/home/wxw/data/modbus/test_new.pcap','mbtcp',-2)


#ss = session_deal('/home/wxw/data/modbus/test_new.pcap')
#datas = PCAPImporter.readFile('/home/wxw/data/iec104/10.55.37.310.55.218.2.pcap').values()
#t_s,t_d = ss.clus_sesionbydi(datas)
#messages = []
#for me in t_s:
#    s_s = str(me.data)
#    messages.append(s_s)


#ss = session_deal('/home/wxw/data/iec104/10.55.37.13110.55.218.2.pcap')
#cn = ss.get_changes()
#print (cn)
#test_it = find_one.frequents_find(messages)
#test_it.get_detaillo(messages,100)
#lo_one = test_it.voteforlen(0.88)
#lo_two = test_it.voteforvalues# (6)
#lo_three = test_it.voteforviation(0.01)
#result = test_it.getlobyabs(0.88,6,0.01,1)
#print result














#ss = session_deal('/home/wxw/data/iec104/10.55.37.310.55.218.2.pcap')
#t_result = ss.get_104sessions()
#tt = series_find.series_num(t_result)
#tt.get_multisession()
#result = tt.get_location(0.5,0.5)


#ss.noise_remove('/home/wxw/data/modbus/' + 'firefac.pcap','DATA',-1)
#data = PCAPImporter.readFile('/home/wxw/data/modbus/141.81.0.10141.81.0.24.pcap').values()
#t_num = 0
#length = len(data)
#i = 1
#while(i < length):
#    t_num = t_num + (data[i].date - data[i - 1].date)
#    i = i + 1
#print t_num/(length - 1)

