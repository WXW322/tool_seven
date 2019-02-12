#-*- coding: utf-8 -*-
from netzob.all import *
import sys
sys.path.append("../../")
#import t_node
import numpy as np
import random
import math
from matplotlib import pyplot as plt

class words_base:
    def __init__(self):
        print("mm")
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

    def get_logapinfo(self,series_list,lo_s,lo_e):
        """

        :param series_list:series data
        :param lo_s: start location
        :param lo_e:end location
        :return:prob info
        """
        print("enter")
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
        print("aa")
        print(t_result)
        print(t_prob)
        #print(t_datas)
        sys.exit()
        return t_result,t_prob,t_datas

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





"""
wd = words_base()
cc,dd = wd.get_logapinfo([[1,2,3,4,5],[2,2,4,5,6],[3,1,2,3,4],[2,3,1],[3,3,3,1,2]],4,5)
print(cc)
print(dd)
"""
