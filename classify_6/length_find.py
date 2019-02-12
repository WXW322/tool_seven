#coding=utf-8
from netzob.all import *
import struct
import math
import os


def get_primedata(dir_path):
    t_dirs = os.listdir(dir_path)
    T_data = []
    for file_n in t_dirs:
        t_path = os.path.join(dir_path,file_n)
        t_data = PCAPImporter.readFile(t_path).values()
        T_data.extend(t_data)
    return T_data


def pearson(vector1, vector2):
    n = len(vector1)
    #simple sums
    sum1 = sum(float(vector1[i]) for i in range(n))
    sum2 = sum(float(vector2[i]) for i in range(n))
    #sum up the squares
    sum1_pow = sum([pow(v, 2.0) for v in vector1])
    sum2_pow = sum([pow(v, 2.0) for v in vector2])
    #sum up the products
    p_sum = sum([vector1[i]*vector2[i] for i in range(n)])
    #分子num，分母den
    num = p_sum - (sum1*sum2/n)
    den = math.sqrt((sum1_pow-pow(sum1, 2)/n)*(sum2_pow-pow(sum2, 2)/n))
    if den == 0:
        return 0.0
    return num/den

def r_length(da_str,gap,leixing,encoding):
    length = len(da_str)
    i = 0
    t_co = {}
    while(i < length - gap):
        t_str = da_str[i:i+gap+1]
        t_len = struct.unpack(encoding + leixing, t_str)
        offset = i
        left = length - i
        if(t_len[0] <= left):
            t_co[i] = [i,t_len[0],left]
            #if i in t_co.keys():
            #    t_co[i].append([i,t_len[0],left])
            #else:
            #    t_co[i] = []
            #    t_co[i].append([i, t_len[0], left])
        i = i + gap + 1
    return t_co

def check_list(L):
    print (L)

def group_byoff(data_L):
    i = 0
    t_result = {}
    t_count = {}
    while(i < 100):
        t_result[i] = []
        t_count[i] = 0
        i = i + 1
    for data_l in data_L:
        for key,value in data_l.iteritems():
            t_result[key].append(value)
            t_count[key] = t_count[key] + 1
    return t_result,t_count



def t_get_r(t_rate,data):
    data_T = data
    #t_co = r_length(data[0].data,0,'B','>')
    T_con = []
    for data_s in data_T:
        t_con = r_length(data_s.data,0,'B','>')
        T_con.append(t_con)
    T_group,T_count = group_byoff(T_con)
    T_length = len(T_con)
    T_group_two = {}
    T_count_two = {}
    for t_key in T_count:
        if(T_count[t_key]/T_length > t_rate):
            T_group_two[t_key] = T_group[t_key]
            T_count_two[t_key] = T_count[t_key]
    T_group_three = {}
    T_count_three = {}
    for key in T_count_two:
        t_X = []
        t_Y = []
        t_da = T_group_two[key]
        for t_s in t_da:
            t_X.append(t_s[1])
            t_Y.append(t_s[2])
        rate = pearson(t_X,t_Y)
        if(rate > 0.3):
            T_group_three[key] = T_group_two[key]
            T_count_three[key] = T_count_two[key]
    for key in T_count_three:
        print (key)

#data_T = PCAPImporter.readFile('/home/wxw/data/modbus-new.pcap').values()
data = get_primedata('/home/wxw/data/dnp3.0')
r_length(data[0].data,1,'h','>')
#t_get_r(0.5,data)

