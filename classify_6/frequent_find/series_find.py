#coding=utf-8
from netzob.all import *
import struct
import math
import os
import sys

class series_num:
    def __init__(self,sessions):
        self.sessions = sessions
        self.consession = []
        self.locate = []
        self.group = None

    def group_byoff(data_L):
        i = 0
        t_result = {}
        t_count = {}
        while (i < 100):
            t_result[i] = []
            t_count[i] = 0
            i = i + 1
        for data_l in data_L:
            for key, value in data_l.iteritems():
                t_result[key].append(value)
                t_count[key] = t_count[key] + 1
        return t_result, t_count

    def r_length(da_str, gap, leixing, encoding):
        """
        :param gap:
        :param leixing:
        :param encoding:
        :return:
        """
        length = len(da_str)
        i = 0
        t_co = {}
        while (i < length - gap):
            t_str = da_str[i:i + gap + 1]
            t_len = struct.unpack(encoding + leixing, t_str)
            offset = i
            left = length - i
            if (t_len[0] <= left):
                t_co[i] = [i, t_len[0]]
                # if i in t_co.keys():
                #    t_co[i].append([i,t_len[0],left])
                # else:
                #    t_co[i] = []
                #    t_co[i].append([i, t_len[0], left])
            i = i + gap + 1
        return t_co

    def get_multisession(self):
        """
        split mix sessions by ip and port
        :return:
        """
        src = self.sessions[0].source
        des = self.sessions[0].destination
        s_lo = 0
        t_lo = 0
        t_src = []
        t_des = []
        for session in self.sessions:
            if session.source == src:
                t_src.append(session)
            else:
                t_des.append(session)

        return t_src,t_des

    def r_length(self,da_str,gap,leixing,encoding):
        """
        :param da_str:original data
        :param gap:bytes num
        :param leixing:big edian or little indian
        :param encoding:number type
        :return:t_co location info
        """
        length = len(da_str)
        i = 0
        t_co = {}
        while (i < length - gap):
            t_str = da_str[i:i + gap + 1]
            t_len = struct.unpack(encoding + leixing, t_str)
            offset = i
            left = length - i
            t_co[i] = [i, t_len[0]]
            i = i + gap + 1
        return t_co

    def group_byoff(self,data_L):
        i = 0
        t_result = {}
        t_count = {}
        while (i < 100):
            t_result[i] = []
            t_count[i] = 0
            i = i + 1
        for data_l in data_L:
            for key, value in data_l.iteritems():
                if key >= 100:
                    continue
                t_result[key].append(value)
                t_count[key] = t_count[key] + 1
        return t_result, t_count

    def vote_lo(self,T_result,t_vote):
        t_lo = []
        t_selo = []
        for key in T_result:
            t_value = T_result[key]
            t_length = len(t_value)
            i = 0
            t_num = 0
            t_tans = {}
            while(i < t_length -1):
                t_temp = t_value[i+1][1] - t_value[i][1]
                if t_temp not in t_tans:
                    t_tans[t_temp] = 1
                else:
                    t_tans[t_temp] = t_tans[t_temp] + 1
                i = i + 1
            t_most = max(zip(t_tans.values(),t_tans.keys()))[0]
            t_value = max(zip(t_tans.values(),t_tans.keys()))[1]
            if(float(t_most)/float(t_length) > t_vote):
                t_lo.append(key)
                if(t_value != 0):
                    t_selo.append(key)
        return t_lo,t_selo






    def get_location(self,t_rate,t_vote):
        series_lo = []
        for t_session in self.consession:
            T_con = []
            data_T = t_session
            T_length = len(t_session)
            for data_s in data_T:
                t_con = self.r_length(data_s.data, 0, 'B', '>')
                T_con.append(t_con)
            T_group, T_count = self.group_byoff(T_con)
            T_group_two = {}
            T_count_two = {}
            for t_key in T_count:
                if (T_count[t_key] / T_length > t_rate):
                    T_group_two[t_key] = T_group[t_key]
                    T_count_two[t_key] = T_count[t_key]

            t_r,t_s = self.vote_lo(T_group_two,t_vote)
            series_lo.append(t_s)
        self.locate = series_lo
        return  series_lo


"""
MessageList = PCAPImporter.readFile('/home/wxw/data/iec104/10.55.37.310.55.218.2.pcap').values()
pp = series_num(MessageList)
src,des = pp.get_multisession()
print(src)
"""














