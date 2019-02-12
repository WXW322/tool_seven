import matplotlib.pyplot as plt
import numpy as np
from netzob.all import *
import struct
import os
import time
import sys

# plt.plot([1, 2, 3, 4], [1, 4, 9, 16], 'ro')
# plt.axis([0, 6, 0, 20])
# plt.show()

# t = np.arange(0., 5., 0.2)
# plt.plot(t, t, 'r--', t, t ** 2, 'bs', t, t ** 3, 'g^')


class protocol_dis:
    def __init__(self,filename,rootdir):
        if rootdir == '':
            self.datas = PCAPImporter.readFile(filename).values()

        else:
            t_paths = os.listdir(rootdir)
            t_length = len(t_paths)
            i = 0
            t_fpath = []
            while (i < t_length):
                t_path = os.path.join(rootdir, t_paths[i])
                t_fpath.append(t_path)
                i = i + 1
            self.datas = PCAPImporter.readFiles(t_fpath).values()
        self.loinfo = {}
        self.constant = []

    def get_lodata(self,t_lo):
        details = {}
        for i in range(0,256):
            details[i] = 0
        for data in self.datas:
            #num = struct.unpack('>h',data.data[t_lo:t_lo+1])
            if(len(data.data) < t_lo + 1):
                continue
            num = data.data[t_lo]
            details[num] = details[num] + 1
        temp_x = []
        temp_y = []   
        for key in details:
            temp_x.append(key)
            temp_y.append(details[key])
        result = {}
        result['x'] = temp_x
        result['y'] = temp_y
        return result

    def get_singlepic(self,datas,path,protocol,lo):
        plt.title(protocol + str(lo))
        plt.plot(datas['x'],datas['y'])
        plt.savefig(os.path.join(path,str(time.time()) + '.png'))
        plt.show()

    def get_twolepic(self,data_one,data_two,path):
        plt.subplot(211)
        plt.title(data_one['prolo'])
        plt.plot(data_one['x'],data_one['y'],'r--')
        plt.subplot(212)
        plt.title(data_two['prolo'])
        plt.plot(data_two['x'],data_two['y'],'b--')
        plt.savefig(os.path.join(path,str(time.time()) + '.png'))
        plt.show()

    def show_lonum(self,lo_s):
        t_length = len(self.datas)
        result = {}
        temp_x = []
        temp_y = []
        i = 0
        for data in self.datas:
            if(len(data.data) < lo_s + 1):
                continue
            t_idom = data.data[lo_s]
            print (t_idom)
            if t_idom not in result:
                result[t_idom] = 0
            else:
                result[t_idom] = result[t_idom] + 1
            i = i + 1
            if(i % 1000 == 0):
                temp_x.append(i)
                temp_y.append(len(result))
            t_f = {}
            t_f['x'] = temp_x
            t_f['y'] = temp_y
        self.get_singlepic(t_f,'/home/wxw/data/protocol_pic/ethernet/num','ethernet',lo_s)
    def get_loinfo(self):
        self.t_loinfo = {}
        for data in self.datas:
            t_length = len(data.data)
            i = 0
            while(i < t_length):
                if i not in self.t_loinfo:
                    self.t_loinfo[i] = {}
                t_node = data.data[i]
                if t_node not in self.t_loinfo[i]:
                    self.t_loinfo[i][t_node] = 1
                else:
                    self.t_loinfo[i][t_node] = self.t_loinfo[i][t_node] + 1
                i = i + 1
    def get_constant(self):
        for key in self.t_loinfo:
            if(len(self.t_loinfo[key]) == 1):
                self.constant.append(key)



#pp = protocol_dis('','/home/wxw/data/Ethernetip/keys')
#pp.get_loinfo()
#pp.get_constant()
#print (pp.constant)
#pp.show_lonum(0)








