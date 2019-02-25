from scapy.all import *
import re
import sys
sys.path.append("../Config/")
import iec104
import modbus
import httpwe
import cip
import ftp
import os
import time

class p_dealer:
    def __init__(self):
        self.datas = None

    def read_packets(self, path):
        paths = []
        if os.path.isdir(path):
            t_paths = os.listdir(path)
            for t_path in t_paths:
                paths.append(os.path.join(path, t_path))
        else:
            paths.append(path)
        t_f = []
        for path in paths:
            data = rdpcap(path)
            t_f.extend(data)
        self.datas = t_f
        return t_f

    def data2sen(self, s):
        """
        transform data to string
        eg: 000908
        0_9_8_
        """
        t_f = ""
        t_len = len(s)
        i = 0
        while(i < t_len):
            t_f = t_f + str(s[i])
            t_f = t_f + '_'
            i = i + 1
        return t_f

    def transform(self, datas):
        """
        transform datas to string list
        """
        t_r = []
        for data in datas:
            t_r.append(self.data2sen(data))
        return t_r

    def data2str(self, datas):
        t_r = []
        for data in datas:
            t_r.append(str(data))
        return t_r

    def write_packet(self, path, datas = None):
        #fileone = open(path)
        #writer = PcapWriter(fileone, append = True)
        if datas == None:
            for data in self.datas:
                writer.write(data)
        else:
            for data in datas:
                writer.write(data)

    def convert(self, t_keys):
        t_f = []
        for t_key in t_keys:
            t_c = []
            for key in t_key:
                t_c.append(self.datas[key])
            t_f.append(t_c)
        return t_f

    def get_clsbyre(self, datas, re_ses):
        """
        get datas accoding to rex
        """
        t_fr = []
        t_fc = []
        i = 0
        for re_s in re_ses:
            t_r = []
            t_c = []
            i = 0
            for data in datas:
                if(re.search(re_s, data)):
                    t_r.append(data)
                    t_c.append(i)
                i = i + 1
            t_fr.append(t_r)
            if len(t_c) > 0:
                t_fc.append(t_c) 
        t_fdata = self.convert(t_fc)
        return t_fr, t_fc, t_fdata

    def get_clsbylos(self, datas, lo):
        t_r = {}
        t_c = {}
        i = 0
        for data in datas:
            if isinstance(lo, tuple):
                key = int.from_bytes(data[lo[0]:lo[1]], byteorder = 'big', signed = False)
            else:    
                key = data[lo]
            if key not in t_r:
                t_r[key] = []
                t_c[key] = []
                t_r[key].append(data)
                t_c[key].append(i)
            else:
                t_r[key].append(data)
                t_c[key].append(i)
            i = i + 1
        t_cdata = []
        for key in t_c:
            t_cdata.append(t_c[key])
        t_fdata = self.convert(t_cdata)
        return t_r, t_c, t_fdata

    def sample(self, datas, count):
        t_lo = {}
        t_len = len(datas)
        for i in range(t_len):
            t_lo[i] = 0
        sam_datas = []
        cnt = 0
        while(cnt <= count):
            for i in range(t_len):
                if t_lo[i] < len(datas[i]):
                    sam_datas.append(datas[i][t_lo[i]])
                    t_lo[i] = t_lo[i] + 1
                    cnt = cnt + 1
        return sam_datas


    def generate(self, pathf, patht, pro):
        datas = self.read_packets(pathf)
        # transform raw datas to bytes
        raw_datas = []
        samp_data = None
        for data in datas:
            if 'Raw' in data:
                raw_datas.append(data['Raw'].__bytes__())
        if pro == 'modbus':
            modbusone = modbus.modbus()
            _,_,T_datas = self.get_clsbylos(raw_datas, modbusone.lo)
            #samp_data = self.sample(T_datas, 20)
        elif pro == 'iec104':
            iecone = iec104.iec104()
            s_datas = self.transform(raw_datas)
            _,_,T_datas = self.get_clsbyre(s_datas, iecone.res)
        elif pro == 'cip':
            cipone = cip.cip() 
            _,_,T_datas = self.get_clsbylos(raw_datas, cipone.lo)
        elif pro == 'http':
            httpone = httpwe.http()
            s_datas = self.transform(raw_datas)
            _,_,T_datas = self.get_clsbyre(s_datas, httpone.res)
        elif pro == 'ftp':
            ftpone = ftp.ftp()
            s_datas = self.transform(raw_datas)
            _,_,T_datas = self.get_clsbyre(s_datas, ftpone.res)
        samp_data = self.sample(T_datas, 20)
        wrpcap(patht, samp_data)
        #self.write_packet(samp_data, patht)    
            
            


        
         



def test():
    dealer = p_dealer()
    dealer.read_packet("/home/wxw/data/iec104/10.55.41.12910.55.218.1.pcap")
    datas = dealer.datas
    t_datas = []
    for data in datas:
        print(type(data))
        if 'Raw' in data:
            t_datas.append(data['Raw'].__bytes__())
    P_iec = iec104.iec104()
    s_datas = dealer.transform(t_datas)
    f_datas = dealer.get_clsbyre(s_datas, P_iec.res[0])
    print(f_datas)
    
def test_one():
    start = time.time()
    dealer = p_dealer()
    #dealer.generate('/home/wxw/data/modbusdata', '/home/wxw/one_shot/modbus/one.pcap', 'modbus')
    #dealer.generate('/home/wxw/data/iec104', '/home/wxw/one_shot/iec104/one.pcap', 'iec104')
    #dealer.generate('/home/wxw/data/cip_datanew', '/home/wxw/one_shot/cip/one.pcap', 'cip')
    #dealer.generate('/home/wxw/data/http', '/home/wxw/one_shot/HTTP/one.pcap', 'http')
    dealer.generate('/home/wxw/data/ftp/', '/home/wxw/one_shot/ftp/one.pcap', 'ftp')
    end = time.time()
    print(end - start)
test_one()



                

