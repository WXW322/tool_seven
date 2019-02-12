#-*- coding: utf-8 -*-
from netzob.all import *
import sys
sys.path.append("../")
#import t_node
import numpy as np
import random
import math
from common.readdata import *
from matplotlib import pyplot as plt

class words_base:
    def __init__(self):
        self.tt = None


    def get_loinfo(self,series_list,head_count):
        t_result = {}
        t_length = {}
        i = 0
        while (i < head_count):
            t_result[i] = {}
            t_length[i] = 0
            i = i + 1
        for series in series_list:
            length = len(series)
            i = 0
            while (i < length and i < head_count):
                t_length[i] = t_length[i] + 1
                t_fre = t_result[i]
                t_num = series[i]
                if t_num not in t_fre:
                    t_fre[t_num] = 1
                else:
                    t_fre[t_num] = t_fre[t_num] + 1
                i = i + 1
        i = 0
        while (i < head_count):
            t_pre = t_result[i]
            t_result[i] = sorted(t_pre.items(), key=lambda d: d[1], reverse=True)
            i = i + 1
        return t_result,t_length

    def get_entry(self,w_dic):
        t_ent = 0
        for key in w_dic:
            t_ent  = t_ent - key[1] * math.log(key[1],2)
        return t_ent

    def get_fre(self,series,T = 0.001):
        cnt = 0
        for se in series:
            if se[1] >= T:
                cnt = cnt + 1
        return cnt


    def huxinxi(self,vectorone,vectortwo):
        vectorthree = []
        for i in range(len(vectorone)):
            vectorthree.append(vectorone[i]+vectortwo[i])
        t_probone = self.caculate_prob(vectorone)
        t_probtwo = self.caculate_prob(vectortwo)
        t_probsum = self.caculate_prob(vectorthree)
        t_info = 0
        for key_one in t_probone:
            for key_two in t_probtwo:
                if key_one + key_two not in t_probsum:
                    continue
                t_info = t_info + t_probsum[key_one+key_two]*np.log(t_probsum[key_one + key_two]/(t_probone[key_one]*t_probtwo[key_two]))
        return -t_info


                
    def caculate_prob(self,vector):
        t_r = {}
        for v in vector:
            if v not in t_r:
                t_r[v] = 1
            else:
                t_r[v] = t_r[v] + 1
        for key in t_r:
            t_r[key] = t_r[key]/len(vector)
        return t_r

    def get_logapinfo(self,series_list,lo_s,lo_e):
        """

        :param series_list:series data
        :param lo_s: start location
        :param lo_e:end location
        :return:prob info
        """
        t_result = {}
        t_prob = {}
        i = 0
        t_len = 0
        t_datas = []
        for series in series_list:
            if len(series) < lo_e:
                continue
            i = lo_s
            t_str = ''
            while (i < lo_e):
                if t_str == "":
                    t_str = t_str + str(series[i])
                else:
                    t_str = t_str + '_' + str(series[i])
                i = i + 1

            if t_str not in t_result:
                t_result[t_str] = 1
            else:
                t_result[t_str] = t_result[t_str] + 1
            t_len = t_len + 1
            t_datas.append(series[lo_s:lo_e])
        i = 0
        for key in t_result:
            t_prob[key] = t_result[key] / t_len
        t_result = sorted(t_result.items(), key=lambda d: d[1], reverse=True)
        #t_result = dict((x,y) for x,y in t_result)
        t_prob = sorted(t_prob.items(),key = lambda d:d[1],reverse=True)
        t_entry = self.get_entry(t_prob)
        t_fre = self.get_fre(t_prob)
        
        return t_result,t_prob,t_datas,t_fre,t_entry

    def get_pureproinfo(self,series_list,lo_s,lo_e):
        """
        get location prob
        :param series_list:
        :param lo_s:
        :param lo_e:
        :return:
        """
        t_result = {}
        t_prob = {}
        i = 0
        t_len = 0
        t_datas = []
        for series in series_list:
            if len(series) < lo_e:
                continue
            i = lo_s
            t_key = series[lo_s:lo_e]

            if t_key not in t_result:
                t_result[t_key] = 1
            else:
                t_result[t_key] = t_result[t_key] + 1
            t_len = t_len + 1
            t_datas.append(series[lo_s:lo_e])
        i = 0
        for key in t_result:
            t_prob[key] = t_result[key] / t_len
        t_result = sorted(t_result.items(), key=lambda d: d[1], reverse=True)
        #t_result = dict((x,y) for x,y in t_result)
        t_prob = sorted(t_prob.items(),key = lambda d:d[1],reverse=True)

        return t_result,t_prob,t_datas

    def get_lengthinfo(self,series_list,lo_s,lo_e):
        t_lengths = []
        t_datasone = []
        t_datastwo = []
        for series in series_list:
            t_temp = series[lo_s:lo_e]
            t_lengths.append(len(series) - lo_e)
            t_datasone.append(int.from_bytes(t_temp,byteorder='little',signed=False))
            t_datastwo.append(int.from_bytes(t_temp,byteorder='big',signed=False))
        return t_datasone,t_datastwo,t_lengths

    def get_seidinfo(self,series_list,lo_s,lo_e):
        t_serienums = []
        t_datasone = []
        t_datastwo = []
        i = 0
        for series in series_list:
            t_temp = series[lo_s:lo_e]
            t_serienums.append(i)
            t_datasone.append(int.from_bytes(t_temp,byteorder='little',signed=False))
            t_datastwo.append(int.from_bytes(t_temp,byteorder='big',signed=False))
            i = i + 1
        return t_datasone,t_datastwo,t_serienums

    def get_info(self,dir_path,lo_end):
        t_data = read_datas(dir_path)
        t_messages = get_puredatas(t_data)
        for los in lo_end:
            lo_b = los[0]
            lo_e = los[1]
            t_aa,t_bb,_,t_e,t_f = self.get_logapinfo(t_messages,lo_b,lo_e)
            print(lo_b,lo_e,len(t_aa),t_e,t_f)
 
#wd = words_base()
#wd.get_info("/home/wxw/data/modbusdata",[(15,16)])
            
"""
wd = words_base()
cc,dd = wd.get_logapinfo([[1,2,3,4,5],[2,2,4,5,6],[3,1,2,3,4],[2,3,1],[3,3,3,1,2]],4,5)
print(cc)
print(dd)
"""
