#coding=utf-8
from netzob.all import *
import struct
import math
import os
import sys
import words_basic
import numpy as np

class message_dealer:
    def __init__(self,messages):
        self.messages = messages
        self.const = []

    def find_const(self):
        #develop absolute or relative
        conster = words_basic.words_base()
        t_messages = []
        for message in self.messages:
            t_messages.append(message.data)
        t_r,t_l = conster.get_loinfo(t_messages,20)
        t_tol = len(self.messages)
        i = 0
        t_len = len(t_r)
        while(i < t_len):
            t_idom = t_r[i]
            t_max = t_idom[0][1]
            if(t_max / t_tol >= 0.95):
                self.const.append(i)
            i = i + 1



    def find_constone(self,lo_b,lo_e):
        #develop absolute or relative
        conster = words_basic.words_base()
        t_messages = []
        for message in self.messages:
            t_messages.append(message.data)
        t_r,t_l,_ = conster.get_logapinfo(t_messages,lo_b,lo_e)
        if(t_l[0][1] > 0.98):
            return 1
        else:
            return 0

    def pearson(self,vector1, vector2):
        n = len(vector1)
        # simple sums
        sum1 = sum(float(vector1[i]) for i in range(n))
        sum2 = sum(float(vector2[i]) for i in range(n))
        # sum up the squares
        sum1_pow = sum([pow(v, 2.0) for v in vector1])
        sum2_pow = sum([pow(v, 2.0) for v in vector2])
        # sum up the products
        p_sum = sum([vector1[i] * vector2[i] for i in range(n)])
        # 分子num，分母den
        num = p_sum - (sum1 * sum2 / n)
        den = math.sqrt((sum1_pow - pow(sum1, 2) / n) * (sum2_pow - pow(sum2, 2) / n))
        if den == 0:
            return 0.0
        return num / den

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



    def find_len(self,datas,lo_s,lo_e):
        t_lener = words_basic.words_base()
        t_messages = []
        for message in self.messages:
            t_messages.append(message.data)
        t_dataone,t_datatwo,t_lens = t_lener.get_lengthinfo(t_messages,lo_s,lo_e)
        print(t_datatwo)
        print(t_lens)
        p_one = self.pearson(t_dataone,t_lens)
        p_two = self.pearson(t_datatwo,t_lens)
        print(p_one)
        print(p_two)
        if(p_one > 0.9 or p_two > 0.9):
            return 1
        else:
            return 0

    def find_lenbyaccu(self,datas,lo_s,lo_e):
        t_lener = words_basic.words_base()
        t_messages = []
        for message in self.messages:
            t_messages.append(message.data)
        t_dataone, t_datatwo, t_lens = t_lener.get_lengthinfo(t_messages, lo_s, lo_e)
        print(t_datatwo)
        print(t_lens)
        acc_big = 0
        for i in range(len(t_dataone)):
            if(abs((t_dataone[i] - t_lens[i])) <= 1):
                acc_big = acc_big + 1
        acc_small = 0
        for i in range(len(t_datatwo)):
            if(abs((t_datatwo[i] - t_lens[i])) <= 1):
                acc_small = acc_small + 1
        print (acc_big)
        print (acc_small)
        print (len(t_dataone))
        if((acc_small/len(t_dataone)) > 0.8 or (acc_big / len(t_dataone)) > 0.8):
            return 1
        else:
            return 0

    def resplit(self):
        print('111')

    def ressemb(self,datas,lo):
        t_puredata = []
        for data in datas:
            t_puredata.append(data.data)
        t_listone = []
        t_listtwo = []
        for t_data in t_puredata:
            if(len(t_data) > lo):
                t_listone.append(t_data[lo-1:lo])
                t_listtwo.append(t_data[lo:lo+1])
        print (self.huxinxi(t_listone,t_listtwo))







    def find_senum(self,Mone,Mtwo,gap,leixing,encoding):
        # delevepe effective add direction
        length_one = len(Mone.data)
        length_two = len(Mtwo.data)
        #print (Mone)
        #print (Mtwo)
        #sys.exit()
        t_length = min(length_one,length_two)
        i = 0
        t_condilo = []
        while(i < t_length - gap):
            if(i in self.const):
                i = i + 1
                continue
            j = 0
            while(j < t_length - gap):
                if(j in self.const):
                    j = j + 1
                    continue
                t_strone = struct.unpack(encoding + leixing,Mone.data[i:i+gap+1])[0]
                t_strtwo = struct.unpack(encoding + leixing,Mtwo.data[j:j+gap+1])[0]
                #print(i,j)
                #print(Mone.data[i:i+gap+1])
                #print(Mtwo.data[j:j+gap+1])
                #print(t_strone)
                #print(t_strtwo)
                if(t_strone == t_strtwo):
                    t_condilo.append((i,j))
                j = j + 1
            i = i + 1

        return t_condilo

    def find_senumsub(self,Mone,Mtwo,gap,leixing,encoding):
        # delevepe effective add direction
        length_one = len(Mone.data)
        length_two = len(Mtwo.data)
        #print (Mone)
        #print (Mtwo)
        #sys.exit()
        t_length = min(length_one,length_two)
        i = 0
        t_condilo = []
        while(i < t_length - gap):
            if(i in self.const):
                i = i + 1
                continue
            j = 0
            while(j < t_length - gap):
                if(j in self.const):
                    j = j + 1
                    continue
                t_strone = struct.unpack(encoding + leixing,Mone.data[i:i+gap+1])[0]
                t_strtwo = struct.unpack(encoding + leixing,Mtwo.data[j:j+gap+1])[0]
                print(i,j)
                print(Mone.data[i:i+gap+1])
                print(Mtwo.data[j:j+gap+1])
                print(t_strone)
                print(t_strtwo)
                if(t_strtwo - t_strone == 2):
                    t_condilo.append((i,j))
                j = j + 1
            i = i + 1

        return t_condilo

    def find_seriesid(self,sessions):
        t_total = 0.0
        t_selo = {}
        for session in sessions:
            t_len = len(session)
            if(t_len <= 1):
                continue
            else:
                j = 0
                while(j < t_len -1):
                    pre = session[j][1][-1]
                    last = session[j + 1][1][0]
                    t_total = t_total + 1
                    #los = self.find_senum(pre,last,0,'B','<')
                    los = self.find_senumsub(pre, last, 0, 'B', '>')
                    for lo in los:
                        t_key = str(lo[0]) + ',' + str(lo[1])
                        if lo not in t_selo:
                            t_selo[lo] = 1
                        else:
                            t_selo[lo] = t_selo[lo] + 1
                    j = j + 1
        for key in t_selo:
            if(t_selo[key] / t_total > 0.8):
                print (key)

            def find_seriesid(self, sessions):
                t_total = 0.0
                t_selo = {}
                for session in sessions:
                    t_len = len(session)
                    if (t_len <= 1):
                        continue
                    else:
                        j = 0
                        while (j < t_len - 1):
                            pre = session[j][1][-1]
                            last = session[j + 1][1][0]
                            t_total = t_total + 1
                            los = self.find_senum(pre, last, 0, 'B', '<')
                            for lo in los:
                                t_key = str(lo[0]) + ',' + str(lo[1])
                                if lo not in t_selo:
                                    t_selo[lo] = 1
                                else:
                                    t_selo[lo] = t_selo[lo] + 1
                            j = j + 1
                for key in t_selo:
                    if (t_selo[key] / t_total > 0.8):
                        print(key)


    def findserienum(self,data,lo_s,lo_e):
        t_lener = words_basic.words_base()
        t_messages = []
        for message in self.messages:
            t_messages.append(message.data)
        t_dataone, t_datatwo, t_series = t_lener.get_seidinfo(t_messages, lo_s, lo_e)
        #print(t_dataone)
        #print(t_datatwo)
        #print(t_series)
        j_one = self.pearson(t_dataone,t_series)
        j_two = self.pearson(t_datatwo,t_series)
        j_final = max(j_one,j_two)



    def find_constfunc(self,lo_b,lo_e,L):
        #develop absolute or relative
        conster = words_basic.words_base()
        t_messages = []
        for message in self.messages:
            t_messages.append(message.data)
        t_r,t_l,_ = conster.get_logapinfo(t_messages,lo_b,lo_e)
        t_lo = 1 - lo_b / L
        t_num = 1 - len(t_r) / 255
        t_en = 0
        for t_pro in t_l:
            t_en = t_en + t_pro[1] * np.log(t_pro[1])
        t_en = -t_en
        return t_lo * t_num * t_en

    def find_head(self):
        min_len = 10000
        for message in self.messages:
            t_len = len(message.data)
            if t_len < min_len:
                min_len = t_len
        return min_len




















