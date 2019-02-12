#-*- coding: utf-8 -*-

from netzob.all import *
from find_one import frequents_find

def do_it():
    MessageList = PCAPImporter.readFile('/home/wxw/data/iec104_pure.pcap').values()
    messages = []
    for me in MessageList:
        s_s = str(me.data)
        messages.append(s_s)
    t_fy = frequents_find(MessageList)
    t_result = t_fy.get_frequentbyte(messages,100,len(messages)/10)
    print (t_result)



do_it()
