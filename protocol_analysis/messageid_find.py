from netzob.all import *
import struct
import math
import os
import sys
import fre_words
from scipy import stats
import numpy as np

class messaid_finder:
    def __init__(self,otherpos,length):
        self.otherp = otherpos
        self.condidate = []
        self.length = length

    def get_lo(self,t_sess,encoding,leixing,gap):
        t_location = []
        t_temp = {}
        t_sub = {}
        for t_s in t_sess:
            t_data = t_s.data
            i = 0
            while(i < len(t_data) and i < (self.length - gap) and i not in self.otherp):
                if (i not in t_temp):
                    t_temp[i] = []
                    t_temp[i].append(struct.unpack(encoding + leixing,t_data[i:i+gap]))
                    t_sub[i] = {}
                else:
                    t_idom = struct.unpack(encoding + leixing,t_data[i:i+gap])
                    t_temp[i].append(t_idom)
                    t_sub[i].append(t_idom - t_temp[i][-1])
                i = i + 1
        for key in t_sub:
            t_num = stats.mode(np.array(t_sub[key]))
            if(t_num[0][0] != 0 and t_num[0][1] / len(t_sess) > 0.5):
                t_location.append(key)
        return t_location








    def filter(self,t_sessions,t_total):
        i = 0
        t_selo = {}
        t_backlo = []
        for t_sess in t_sessions:
            t_len = len(t_sess)
            i = 0
            while(i < t_len):
                if(t_sess[i][0] == 3 or t_sess[i][0] ==4):
                    t_temp = t_sess[i][1]







    def get_lo(self,t_sessions):
        print ('aaa')


