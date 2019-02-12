#-*- coding: utf-8 -*-
from netzob.all import *
import sys
sys.path.append("../../")
#import t_node
import numpy as np
import random
import math
from matplotlib import pyplot as plt




class frequent_seties:
    def __init__(self,data):
        self.data = data
        self.local = -1
        self.range = [0,0]

#频繁序列挖掘类
class frequents_find:

    def __init__(self,MessageList):
        """

        :param MessageList:protocol messages
         clusters:locations info
         single:
         loinfo:protocol packages location info
        """

        messages = []
        for me in MessageList:
            messages.append(me.data)
        self.datas = messages
        self.single = []
        self.cluster = {}
        self.loinfo = []

    def get_frequentbyte(self,series_list,head_count,line):
        """

        :param series_list:messages list
        :param head_count:the num to caculate
        :param line:the therehold of the frequent byte
        :return:location info
        example:
         MessageList = PCAPImporter.readFile('/home/wxw/data/iec104_pure.pcap').values()
         messages = []
        for me in MessageList:
           s_s = str(me.data)
           messages.append(s_s)
        t_fy = frequents_find(MessageList)
        t_result = t_fy.get_frequentbyte(messages,100,len(messages)/10)
        print (t_result)
        """
        t_result = {}
        t_length = {}
        i = 0
        while(i < head_count):
            t_result[i] = {}
            t_length[i] = 0
            i = i + 1
        for series in series_list:
            length = len(series)
            i = 0
            while(i < length and i < head_count):
                t_length[i] = t_length[i] + 1
                t_fre = t_result[i]
                t_num = series[i]
                if not t_fre.has_key(t_num):
                    t_fre[t_num] = 1
                else:
                    t_fre[t_num] = t_fre[t_num] + 1
                i = i + 1
        i = 0
        t_final = {}
        t_final_two = {}
        while(i < head_count):
            t_pre = t_result[i]
            t_final[i] = sorted(t_pre.iteritems(), key=lambda d:d[1], reverse = True)
            t_final_two[i] = []
            for single in t_final[i]:
                if(single[1] >= line):
                    t_final_two[i].append(single)
                else:
                    break;
            i = i + 1
        self.cluster = t_final_two
        return t_final_two

    def show_str(self,series,head,rate):
        """
        get frequent series
        :param series:
        :param head:
        :param rate:
        :return:
        """
        result = self.get_frequentbyte(series,head,len(series)/rate)
        str_one = ''
        i = 0
        while (i < head):
            t_dict = result[i]
            t_s = []
            for t in t_dict:
                t_s.append(repr(t[0]))
            str_s = ' '.join(t_s)
            str_one = str_one + str(i) + ':' + ' ' + str_s + '\r\n'
            i = i + 1
        return str_one

    def decode_series(self,t_series):
        """

        :param t_series:a single message
        :return: a decoded message s
        """
        t_length = len(self.cluster)
        print(t_length)
        i = 0
        t_code = []
        while(i < t_length):
            t_clu = self.cluster[i]
            j = 0
            while(j < len(t_clu)):
                if(t_clu[j][0] == t_series[i]):
                    t_code.append((i,j,t_clu[j][0]))
                    break;
                j = j + 1
            i = i + 1
        return t_code

    def caculate_num(self,single,sequences,t_len):
        """
        get a serie show times in messages
        :param single:
        :param sequences:
        :param t_len:
        :return:
        """
        t_time = 0
        for se in sequences:
            i = 0
            se_len = len(se)
            while(i <= se_len - t_len):
                if se[i:i+t_len] == single:
                    t_time = t_time + 1
                i = i + 1
        return t_time




    def unlo_find(self,sequences,therehold):
        """
        use aprior to find frequent series
        :param sequences:protocol packages
        :param therehold:frequent therehold
        :return:frequent series
        :youhua tree
        """

        g_r = {}
        g_r[1] = []
        for i in range(0,256):
            t_num = chr(i)
            g_r[1].append(t_num)
        i = 1
        t_sum = 0
        for se in sequences:
            t_sum = t_sum + len(se)
        print (t_sum)
        while(len(g_r[i]) != 0):
            p = 0
            for single in g_r[i]:
                t_time = self.caculate_num(single,sequences,i)
                #print (t_time)
                #print(single)
                if(float(t_time)/float(t_sum) < therehold):
                    p = p + 1
                    g_r[i].remove(single)
            print ('outone')
            print (len(g_r[i]))
            print (i)
            if(len(g_r[i]) == 0):
                break
            g_r[i + 1] = []
            if i == 1:
                for se_one in g_r[i]:
                    for se_two in g_r[i]:
                        g_r[i + 1].append(se_one + se_two)
            else:
                for se_one in g_r[i]:
                    for se_two in g_r[i]:
                        se_lone = list(se_one)
                        se_ltwo = list(se_two)
                        if(se_lone[0:i-1] == se_ltwo[1:i]):
                            se_new = se_ltwo
                            se_new.append(se_lone[i-1])
                            g_r[i + 1].append(str(se_new))
            i = i + 1
            #print(g_r[i])
            #print(i)
        print('out')
        i = 1
        while(len(g_r[i+1]) > 0):
            t_con = []
            for s_one in g_r[i]:
                for se_two in g_r[i+1]:
                    if s_one not in se_two:
                        t_con.append(s_one)
            g_r[i] = s_one
            i = i + 1
        return t_con


    def get_detaillo(self,head_count):
        """

        :param head_count:the head_num to caculate
        :return: every location infomation
        example:

        """
        t_result = {}
        t_length = {}
        for series in self.datas:
            length = len(series)
            i = 0
            while(i < length and i < head_count):
                s_temp = series[i]
                if i not in t_result:
                    t_result[i] = {}
                    t_result[i][s_temp] = 1
                else:
                    if s_temp not in t_result[i]:
                        t_result[i][s_temp] = 1
                    else:
                        t_result[i][s_temp] = t_result[i][s_temp] + 1
                if i not in t_length:
                    t_length[i] = 1
                else:
                    t_length[i] = t_length[i] + 1
                i = i + 1
        for key in t_result:
            t_result[key] = sorted(t_result[key].items(), key=lambda d:d[1], reverse = True)
            #print (key)
            #print (t_result[key]

        t_final = {}
        length = len(t_result)
        i = 0
        while(i < length and i < head_count):
            t_final[i] = []
            for key in t_result[i]:
                t_final[i].append((i,key[0],key[1],t_length[i],float(key[1])/float(t_length[i])))
            i = i + 1
        t_loinfo = []
        for key in t_final:

            t_temp = t_final[key]
            t_rate = float(t_temp[0][3])/float(len(self.datas))
            t_srate = []
            for node in t_temp:
                t_srate.append(node[4])
            t_nodes = np.array(t_srate)
            t_loinfo.append((key,len(t_temp),t_rate,t_nodes.max(),t_nodes.min(),t_nodes.mean(),t_nodes.max() - t_nodes.min(),np.median(t_nodes),t_nodes.var()))
        self.loinfo = t_loinfo
        return t_loinfo

    def voteforlen(self,rate):
        condidate = []
        for info in self.loinfo:
            if(info[2] > rate):
                condidate.append(info)
        return condidate

    def voteforvalues(self,rate):
        condidate = []
        for info in self.loinfo:
            if(info[1] < rate):
                condidate.append(info)
        return condidate

    def voteforviation(self,rate):
        condidate = []
        for info in self.loinfo:
            if(info[-1] > rate or info[-1] == 0):
                condidate.append(info)
        return condidate

    def getlobyabs(self,rate_one,rate_two,rate_three,rate_f):
        """
        vote for the condidate location
        :param rate_one:
        :param rate_two:
        :param rate_three:
        :param rate_f:
        :return:condidate location
        example:
        """

        vote_r = []
        vote_one = self.voteforlen(rate_one)
        vote_two = self.voteforvalues(rate_two)
        vote_three = self.voteforviation(rate_three)
        vote_r.append(vote_one)
        vote_r.append(vote_two)
        vote_r.append(vote_three)
        t_result = {}
        for vote_node in vote_r:
            for one in vote_node:
                if one[0] not in t_result:
                    t_result[one[0]] = 1
                else:
                    t_result[one[0]] = t_result[one[0]] + 1
        condidate = []
        for node in t_result:
            if(float(t_result[node])/3.0 >= rate_f):
                condidate.append(node)
        return condidate














#MessageList = PCAPImporter.readFile('/home/wxw/data/iec104/10.55.37.310.55.218.2.pcap').values()
#tt = frequents_find(MessageList)
#print (tt.get_detaillo(5))

#messages = []
#mesages_one = []
#for me in MessageList:
#    s_s = str(me.data)
#    messages.append(s_s)



#test_it = frequents_find(messages)
#lo = test_it.get_detaillo(messages,100)




    























