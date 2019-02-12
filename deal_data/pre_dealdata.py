# -*- coding:utf-8 -*-
import scapy.all as scapy
from scapy.utils import PcapReader,PcapWriter
import sys

def get_srcip(single_pack):
    return single_pack['IP'].fields['src']

def get_dstip(single_pack):
    return single_pack['IP'].fields['dst']


def classify_bysrc(file_name):
    packages = scapy.rdpcap(file_name)
    t_results = {}
    for p in packages:
        if (get_srcip(p) + get_dstip(p) in t_results):
            t_results[get_srcip(p) + get_dstip(p)].append(p)
        elif(get_dstip(p) + get_srcip(p) in t_results):
            t_results[get_dstip(p) + get_srcip(p)].append(p)
        else:
            t_results[get_srcip(p) + get_dstip(p)] = []
            t_results[get_srcip(p) + get_dstip(p)].append(p)
    for key in t_results:
        t_temp = t_results[key]
        t_writer = PcapWriter('/home/wxw/data/cip_datanew/' + key + '.pcap',append=True)
        for p in t_results[key]:
            t_writer.write(p)
        t_writer.flush()
        t_writer.close()


#package = scapy.rdpcap('/home/wxw/data/modbusdata.pcap')
classify_bysrc('/home/wxw/data/cip_test/cip_perf.pcap')



