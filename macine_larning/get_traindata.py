
import pandas as pd
import numpy as np
from netzob.all import *
import struct
import sys
import os
sys.path.append('../classify_6/frequent_find')
import series_find
import find_one

class produce_medata:
    def __init__(self,datas):
        self.onelable = {}
        self.datas = datas

    def get_rate(self,sublist,t_num):
        return t_num[sublist['lo']][sublist['value']]


    def get_lable(self,datas,lo_s,dir,count):
        t_r = {}
        t_lable = []
        t_value = []
        t_lo = []
        t_num = {}
        t_count = {}
        i = 0
        while(i < count):
            t_num[i] = {}
            t_count[i] = 0
            i = i + 1
        for data in datas:
            t_length = len(data.data)
            i = 0
            while(i < t_length):
                t_lo.append(i)
                t_node = str(data.data[i:i+1])
                t_node = struct.unpack('>B',data.data[i:i+1])
                t_value.append(t_node[0])
                t_count[i] = t_count[i] + 1
                if t_node[0] not in t_num[i]:
                    t_num[i][t_node[0]] = 0
                else:
                    t_num[i][t_node[0]] = t_num[i][t_node[0]] + 1
                if i in lo_s:
                    t_lable.append(1)
                else:
                    t_lable.append(0)
                i = i + 1
        for key_one in t_num:
            for key_two in t_num[key_one]:
                t_num[key_one][key_two] = t_num[key_one][key_two] / t_count[key_one]

        t_r['value'] = t_value
        t_r['lo'] = t_lo
        t_r['lable'] = t_lable
        self.onelable = t_r
        g_r = pd.DataFrame(t_r)
        t_rate = g_r.apply(self.get_rate,axis = 1,args = (t_num,))
        g_r['cov'] = t_rate
        g_r.to_csv(os.path.join(dir,'lable_total.csv'),index=None)

    def get_loinfo(self):
        l_feature = find_one.frequents_find(self.datas)
        t_f = l_feature.get_detaillo(10000)
        t_info = {}
        t_tran = np.array(t_f).T
        t_info['lo'] = t_tran[0]
        t_info['num'] = t_tran[1]
        t_info['total_rate'] = t_tran[2]
        t_info['num_max'] = t_tran[3]
        t_info['num_min'] = t_tran[4]
        t_info['mean'] = t_tran[5]
        t_info['gap'] = t_tran[6]
        t_info['middle'] = t_tran[7]
        t_info['var'] = t_tran[8]
        lo_info = pd.DataFrame(t_info)
        return lo_info

    def data_combine(self,data_one,data_two,key,dir):
        data_new = data_one.merge(data_two,on = 'lo')
        data_new.to_csv(os.path.join(dir,'lable_finalone.csv'),index=None)

    def get_singledata(self,data,lo_file,dir_data):
        data_one = pd.read_csv(lo_file)
        data_two = pd.read_csv(dir_data)

    def drop_multi(self,filename,newfile):
        data = pd.read_csv(filename)
        data_one = data.drop_duplicates()
        data_one.to_csv(newfile)
    def transonelable(self,data,filename):
        t_datas = pd.read_csv(filename)
        features = t_datas.columns.values.tolist()
        t_single = pd.DataFrame()
        t_length = len(data)
        i = 0
        while(i < t_length):
            t_dataitom = data[i]
            t_item = t_datas[(t_datas['lo'] == i) & (t_datas['value'] == t_dataitom)]
            t_single = t_single.append(t_item)
            i = i + 1
        return t_single







def get_train(dir,locs):
    data = PCAPImporter.readFile('/home/wxw/data/modbus_pure.pcap').values()
    dd = produce_medata(data)
    t_R = dd.get_loinfo()
    t_R.to_csv(os.path.join(dir,'lo.csv'),index = None)
    dd.get_lable(data,locs,dir,10000)
    tt = pd.read_csv(os.path.join(dir,'lable_total.csv'))
    t_f = dd.data_combine(t_R,tt,'lo',dir)




#keys = []
#for i in range(0,30):
#    keys.append(i)
#keys.remove(2)
#keys.remove(3)

#get_train('/home/wxw/data/modbus_train',[0,2,3,6,7])
#data = pd.read_csv('/home/wxw/data/modbus_train/lable_finalone.csv')
#data = data[data['lable'] == 1]
#print (data['lo'].unique())
#data = PCAPImporter.readFile('/home/wxw/data/iec104_pure.pcap').values()
#dd = produce_medata([1,1,1])
#t_r = dd.transonelable(data[0].data,'/home/wxw/data/iec104_train/lable_finaltwo.csv')
#dd.drop_multi('/home/wxw/data/modbus_train/lable_finalone.csv','/home/wxw/data/modbus_train/lable_finaltwo.csv')
#dd.drop_multi('/home/wxw/data/iec104_train/lable_finalone.csv','/home/wxw/data/iec104_train/lable_finaltwo.csv')
