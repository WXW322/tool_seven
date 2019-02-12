from netzob.all import *
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.decomposition import LatentDirichletAllocation
import numpy as np
import sys
import time
import os
import sys
import json
sys.path.append('../protocol_analysis')
import word_deal
def get_single_messge(message,winsize):
    t_list = []
    t_len = len(message)
    i = 0
    t_flist = ''
    while(i < t_len - winsize):
        t_idom = message[i]
        t_temp = str(t_idom)
        j = 1
        while(j < winsize):
            t_idom = message[i + j]
            t_temp = t_temp + '_' + str(t_idom)
            j = j + 1
        if i == 0:
            t_flist = t_temp
        else:
            t_flist = t_flist + ' ' + t_temp
        i = i + 1
    t_flist = t_flist + '.'
    return t_flist
def get_messages(messages,winsize,K,L):
    t_messages = []
    for message in messages:
        t_messages.append(get_single_messge(message,winsize))
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(t_messages)
    lda = LatentDirichletAllocation(n_topics=K,learning_method='batch',random_state=0)
    docres = lda.fit_transform(X)
    words = lda.components_
    names = vectorizer.get_feature_names()
    result = np.argsort(-words,axis = 1)
    t_finals = []
    for i in range(K):
        t_datas = result[i]
        t_temp = [names[j] for j in t_datas]
        t_finals.append(t_temp[0:L])
    t_set = {}
    for t_f in t_finals:
        for idom in t_f:
            t_set[idom] = 1
    return t_finals,t_set
 
def read_datas(dirs):
    paths = os.listdir(dirs)
    t_datas = []
    for path in paths:
        t_path = os.path.join(dirs,path)
        t_data = PCAPImporter.readFile(t_path).values()
        t_datas.extend(t_data)
    messages = []
    for data in t_datas:
        messages.append(data.data)
    return messages

def get_votes(messages,winsize,words):
    t_votes = {}
    for message in messages:
        t_len = len(message)
        i = 0
        t_temp = ''
        while(i < t_len - winsize):
            t_temp = str(message[i])
            j = 1
            while(j < winsize):
                t_temp = t_temp + '_' + str(message[j + i])
                j = j + 1 
            print(t_temp)
            if(t_temp in words):
                t_lo = i + winsize
                if t_lo in t_votes:
                    t_votes[t_lo] = t_votes[t_lo] + 1
                else:
                    t_votes[t_lo] = 1
            i = i + 1
    return t_votes

def get_los(times):
    t_keys  = []
    for key in times:
        prekey = key - 1
        lastkey = key + 1
        nownum = times[key]
        if prekey not in times:
            prenum = 0
        else:
            prenum = times[prekey]
        if lastkey not in times:
            lastnum = 0
        else:
            lastnum = times[lastkey]
        if nownum > prenum and nownum > lastnum:
            t_keys.append(key)
    return t_keys



def get_idoms(t_los):
    t_idoms = []
    t_len = len(t_los)
    i = 0
    while(i < t_len):
        if i == 0:
            t_idoms.append((0,t_los[i]))
        else:
            t_idoms.append((t_los[i-1],t_los[i]))
        i = i + 1
    t_idoms.append((t_los[i-1],-1))
    print(t_idoms)
    return t_idoms
def get_f(dirs,winsize,K,L,outdirs,r_los):
    f_out = open(outdirs,'w+')
    tempout = sys.stdout
    sys.stdout = f_out
    messages = read_datas(dirs)
    t_f,t_s = get_messages(messages,winsize,K,L)
    t_votes = get_votes(messages,winsize,t_s)
    t_votes = get_los(t_votes)
    print(t_votes)
    t_idoms =get_idoms(t_votes)
    t_messages = word_deal.message_dealer()
    t_messages.set_conlo(t_idoms)
    t_messages.set_rlo(r_los)
    f_num = t_messages.get_f1()
    sys.stdout = tempout
    return f_num


    



start_time = time.time()
inputdirs = ['/home/wxw/data/modbusdata','/home/wxw/data/iec104','/home/wxw/data/cip_datanew']
#inputdirs = ['/home/wxw/data/modbustest','/home/wxw/data/iec104_test','/home/wxw/data/cip_test']
outdirs = ['/home/wxw/paper/researchresult/modbus/lda/','/home/wxw/paper/researchresult/iec104/lda/','/home/wxw/paper/researchresult/cip/lda/']

#outdirs = ['/home/wxw/paper/researchresult/modbus/lda/test','/home/wxw/paper/researchresult/iec104/lda/test','/home/wxw/paper/researchresult/cip/lda/test']
r_loses = [[(0,2),(2,4),(4,6),(6,7),(7,8)],[(0,1),(1,2),(2,4),(4,6),(6,7),(7,8),(8,9),(9,10),(10,12)],[(0, 2), (2, 4), (4, 8), (8, 12), (12, 20), (20, 23),(23, 30),(30, 33),(33, 34),(34,35)]]
i = 0
t_finals= {}
t_args = {}
while(i < len(inputdirs)):
    t_input = inputdirs[i]
    t_output = outdirs[i]
    t_rlo = r_loses[i]
    for wsize in [2,3,4]: 
        if i == 0:
            if i not in t_finals:
                t_finals[i] = {}
            t_finals[i][wsize] = get_f(t_input,wsize,5,20,t_output+str(wsize)+'out',t_rlo)
        elif i == 1:
            if i not in t_finals:
                t_finals[i] = {}
            t_finals[i][wsize] = get_f(t_input,wsize,5,30,t_output+str(wsize) + 'out',t_rlo)
        else:
            if i not in t_finals:
                t_finals[i] = {}
            t_finals[i][wsize] = get_f(t_input,wsize,20,5,t_output+str(wsize) + 'out',t_rlo)
    i = i + 1
"""
while(i < len(inputdirs)):
    t_input = inputdirs[i]
    t_output = outdirs[i]
    t_rlo = r_loses[i]
    for wsize in range(2,5,1):
        t_finals[i] = {}
        t_finals[i][wsize] = -100
        t_args[i] = {}
        t_args[i][wsize] = []
        for k in [5,10,20]:
            for L in [5,10,20,30]:
                t_stime = time.time()
                t_line = str(wsize) + '_' +str(k) + '_' + str(L)
                t_fvalue = get_f(t_input,wsize,k,L,t_output + t_line,t_rlo)
                if t_fvalue > t_finals[i][wsize]:
                    t_finals[i][wsize] = t_fvalue
                    t_args[i][wsize].clear()
                    t_args[i][wsize].append((i,wsize,k,L))
                t_etime = time.time()
                print(t_etime - t_stime)
    i = i + 1
"""
"""
f_out = open('/home/wxw/paper/researchresult/lad/result_totalleft','w+')
tempout = sys.stdout
sys.stdout = f_out
print(t_finals)
print(t_args)
sys.stdout = tempout
with open('/home/wxw/paper/researchresult/lad/vjsonttleft.json','w',encoding = 'utf-8') as outfile:
    json.dump(t_finals,outfile)
with open('/home/wxw/paper/researchresult/lad/arjsonttleft.json','w',encoding = 'utf-8') as outfile:
    json.dump(t_args,outfile)


#get_f('/home/wxw/data/modbusdata',i,j,k,'/home/wxw/paper/researchresult/modbus/lda/'+str(i)+'_'+str(j)+'_' + str(k))
#end_time = time.time()
#print(end_time - start_time)

"""


