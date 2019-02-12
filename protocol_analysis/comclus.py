from netzob.all import *
import os
import time
import sys
import random

def read_data(dir):
    paths = os.listdir(dir)
    t_datas = []
    t_sedatas = []
    for path in paths:
        t_path = os.path.join(dir, path)
        t_data = PCAPImporter.readFile(t_path).values()
        t_datas.extend(t_data)
    for t_data in t_datas:
        t_sedatas.append(t_data.data)
    return t_sedatas

def clus_bynw(datas,value):
    pre_messages = []
    for data in datas:
        t_data = RawMessage(data)
        pre_messages.append(t_data)
    f_clus = Format()
    t_r = f_clus.clusterByAlignment(messages = pre_messages,minEquivalence = value)
    return t_r



def get_tcount(clus,lo):
    t_s = lo[0]
    t_e = lo[1]
    t_n = {}
    #print_clus(clus,'fun')
    for clu in clus:
        if(len(clu) < t_e + 1):
            t_id = clu[2]
            t_temp = 3&t_id
            if t_temp == 3:
                t_n['uu'] = 1
            else:
                t_n['ss'] = 1
            continue
        t_key = clu[t_s:t_e]
        if t_key not in t_n:
            t_n[t_key] = 1
    return len(t_n)

def split_byfc(messages,t_lo):
    t_s = t_lo[0]
    t_e = t_lo[1]
    t_fme = {}
    
    for message in messages:
        if len(message) < t_e + 1:
            t_id = int.from_bytes(message[2:3],byteorder="big")
            t_temp = t_id&3
            if t_temp == 3:
                if 'uu' not in t_fme:
                    t_fme['uu'] = []
                t_fme['uu'].append(message)
            else:
                if 's' not in t_fme:
                    t_fme['ss'] = []
                t_fme['ss'].append(message)
            continue
        t_key = message[t_s:t_e]
        if t_key not in t_fme:
            t_fme[t_key] = []
        t_fme[t_key].append(message)
    return t_fme

def sample_data(messages,T):
    t_count = len(messages)
    t_avg = T/t_count
    i = 0
    t_f = []
    t_sum = 0
    t_ps = {}
    for key in messages:
        if(len(messages[key]) < t_avg):
            t_f.extend(messages[key])
            t_sum = t_sum + len(messages[key])
            t_ps[key] = 0
    left_c = t_count - len(t_ps)
    if left_c == 0:
        return t_f
    left_l = T - t_sum
    left_avn = left_l / left_c
    for key in messages:
        if(key not in t_ps):
            t_f.extend(messages[key][0:int(left_avn)])
        i = i + 1
    return t_f

def get_keyclus(clus,key,r_lo):
    t_c = 0
    for clu in clus:
        t_lo = 0
        if key == 'uu':
            for idom in clu:

                t_id = int.from_bytes(idom[2:3],byteorder="big")
                t_temp = 3&t_id
                if(t_temp == 3):
                    t_lo = 1
                    break
        elif key == 'ss':
            for idom in clu:
                t_id = int.from_bytes(idom[2:3],byteorder="big")
                t_temp = 3&t_id
                if(t_temp == 1):
                    t_lo = 1
                    break
        else:
            for idom in clu:
                if(len(idom) > r_lo[1] + 1 and idom[r_lo[0]:r_lo[1]] == key):
                    t_lo = 1
                    break
        if(t_lo == 1):
            t_c = t_c + 1
    #print(key,t_c)
    return t_c

def get_precess(clus,r_lo,keys):
    t_r = 0
    t_pre = 0
    for clu in clus:
        t_cu = get_tcount(clu,r_lo)
        if t_cu == 1:
            t_r = t_r + 1
    for key in keys:
        if(key == 'ss'):
            t_cu = get_keyclus(clus,key,(2,3))
        elif(key == 'uu'):
            t_cu = get_keyclus(clus,key,(2,3))
        else:
            t_cu = get_keyclus(clus,key,r_lo)
        if t_cu == 1:
            t_pre = t_pre + 1
    print(t_r,t_pre,t_r/len(clus),t_pre/len(keys),(t_r/len(clus)) * (t_pre/len(keys)))
    return(t_r,t_pre,t_r/len(clus),t_cu/len(keys),(t_r/len(clus)) * (t_pre/len(keys)))

def print_binary(datas):
    for data in datas:
        print(data,end=' ')
    print()

def print_clus(datas,args):
    print(args + 'start:')
    if(len(datas) < 1):
        return
    else:
        for data in datas:
            print_binary(data)
    print(args + 'end:')
    print()

def get_lengths(datas):
    t_sum = 0
    for data in datas:
        print (len(data))
        t_sum = t_sum + len(data)
    print(t_sum/len(datas))

def short_messages(datas,T):
    i = 0
    while(i < len(datas)):
        if(len(datas[i]) > T):
            datas[i] = datas[i][0:T]
        i = i + 1
    return datas


def get_results(s_path,des_path,los,para):
    t_output = sys.stdout
    file = open(des_path,'w+')
    sys.stdout = file
    datas = read_data(s_path)
    t_funclus = split_byfc(datas,los)
    #print('split_start')
    #for t_key in t_funclus:
    #    print_clus(t_funclus[t_key],'p')
    #print('split_end')

    t_fdatas = sample_data(t_funclus,2000)
    #t_fdatas = short_messages(t_fdatas,100)
    #get_lengths(t_fdatas)
    #print_clus(t_fdatas,'sample')
    #sys.exit()
    t_clus = clus_bynw(t_fdatas,para)
    t_fmes = []
    for t_clu in t_clus:
        t_messages = t_clu.messages
        t_M = []
        for t_me in t_messages:
            t_M.append(t_me.data)
        t_fmes.append(t_M)

        #print_clus(t_M,'nw')
    #print('start')
    get_precess(t_fmes,los,t_funclus.keys())
    #print('end')

    #t_tmes = clus_byfun(t_fdatas,los)
    #get_precess(t_tmes,los,t_funclus.keys())

def get_basespes(s_path,des_path,los,para,lo):
    t_output = sys.stdout
    file = open(des_path,'w+')
    sys.stdout = file
    datas = read_data(s_path)
    t_funclus = split_byfc(datas,los)
    #print('split_start')
    #for t_key in t_funclus:
    #    print_clus(t_funclus[t_key],'p')
    #print('split_end')

    t_fdatas = sample_data(t_funclus,2000)
    if lo == 1:
        t_fdatas = short_messages(t_fdatas,100)
    #get_lengths(t_fdatas)
    #print_clus(t_fdatas,'sample')
    #sys.exit()
    t_clus = clus_bynw(t_fdatas,para)
    t_fmes = []
    print(len(t_funclus.keys()))
    for t_clu in t_clus:
        print(t_clu._str_debug())
        #print(t_clu.getCells())
        print("")

        #print_clus(t_M,'nw')
    #print('start')
    #get_precess(t_fmes,los,t_funclus.keys())

def get_iecmk(data):
    if(len(data) < 7):
        tv = int.from_bytes(data[2:3],byteorder="big")
        t_lo = 3&tv
        if (t_lo == 3):
            return "u"
        else:
            return "s"
    else:
         tv = int.from_bytes(data[7:8],byteorder="little")
         t_lo = 1&tv
         if (t_lo == 1):
             return "single"
         else:
             return "mul"

def get_keys(messages):
    t_keys = {}
    for message in messages:
        t_key = get_iecmk(message)
        if t_key not in t_keys:
            t_keys[t_key] = 0
    return t_keys

def get_keysT(messages):
    keys = {}
    for message in messages:
        t_keys = get_keys(message)
        for t_key in t_keys:
            if t_key not in t_keys:
                t_keys[t_key] = 1
    return t_keys 

def get_keyc(clus,key):
    t_lo = 0
    for clu in clus:
        keys = get_keys(clu)
        if key in keys:
            t_lo = t_lo + 1
    return t_lo
    

def caculate(clus,keys):
    t_r = 0
    t_pre = 0
    for clu in clus:
        if(len(get_keys(clu)) == 1):
            t_r = t_r + 1
    for key in keys:
        if get_keyc(clus,key) == 1:
            t_pre = t_pre + 1
    t_r = t_r / len(clus)
    t_pre = t_pre / len(keys)
    return t_r,t_pre,t_r*t_pre


def get_iec104(s_path,des_path,los,para):

    t_output = sys.stdout
    file = open(des_path,'w+')
    #sys.stdout = file
    datas = read_data(s_path)
    t_fdatas = [random.choice(datas) for _ in range(100)]
    t_tmes = clus_byfun(t_fdatas,los)
    T_keys = get_keys(t_fdatas)
    t_or,t_op,t_oc = caculate(t_tmes,T_keys)
    print(T_keys)
    t_clus = clus_bynw(t_fdatas,para)
    t_nmes = []
    for t_clu in t_clus:
        t_messages = t_clu.messages
        t_M = []
        for t_me in t_messages:
            t_M.append(t_me.data)
        t_nmes.append(t_M)
    t_or,t_op,t_oc = caculate(t_tmes,T_keys)
    t_nr,t_np,t_nc = caculate(t_nmes,T_keys)
    print(t_or,t_op,t_oc)
    print(t_nr,t_np,t_nc)


    
    

def get_funcr(s_path,des_path,los,para):
    t_output = sys.stdout
    file = open(des_path,'w+')
    sys.stdout = file
    datas = read_data(s_path)
    t_funclus = split_byfc(datas,los)
    #print('split_start')
    #for t_key in t_funclus:
    #    print_clus(t_funclus[t_key],'p')
    #print('split_end')

    t_fdatas = sample_data(t_funclus,100)
    #t_fdatas = short_messages(t_fdatas,100)
    #get_lengths(t_fdatas)
    #print_clus(t_fdatas,'sample')
    #sys.exit()
    #t_clus = clus_bynw(t_fdatas,para)
    t_fmes = []
    t_tmes = clus_byfun(t_fdatas,los)
    get_precess(t_tmes,los,t_funclus.keys())

def getourspe(s_path,des_path,los,para):
    t_output = sys.stdout
    file = open(des_path,'w+')
    sys.stdout = file
    datas = read_data(s_path)
    t_funclus = split_byfc(datas,los)
    #print('split_start')
    #for t_key in t_funclus:
    #    print_clus(t_funclus[t_key],'p')
    #print('split_end')

    t_fdatas = sample_data(t_funclus,100)
    t_fmes = []
    t_tmes = clus_byfun(t_fdatas,los)
    print(t_funclus.keys())
    for datas in t_tmes:
        pre_messages = []
        for data in datas:
            t_data = RawMessage(data)
            pre_messages.append(t_data)
        t_sympol = Symbol(messages = pre_messages)
        f_clus = Format()
        f_clus.splitAligned(t_sympol, doInternalSlick=True)
        print(t_sympol._str_debug())
        print(t_sympol.getCells()[0:2])
        print("")



def clus_byfun(t_fdatas,lo):
    t_final = {}
    for data in t_fdatas:
        if len(data) < lo[1]:
            if "ss" not in t_final:
                t_final["ss"] = []
            t_final["ss"].append(data)
            continue
        t_idom = data[lo[0]:lo[1]]
        if t_idom not in t_final:
            t_final[t_idom] = []
        t_final[t_idom].append(data)
    t_ff = []
    for key in t_final:
        t_ff.append(t_final[key])
    return t_ff
    










starttime = time.time()
"""
value = sys.argv[1]
file_from = sys.argv[2]
file_to = sys.argv[3]
lo = sys.argv[4]
start = sys.argv[5]
end = sys.argv[6]
"""

#data = read_data('/home/wxw/data/modbustest')
#clus_bynw(data)
#for i in [80,70,60,50,40,30,20,10]:
#get_results('/home/wxw/data/modbustest','/home/wxw/paper/researchresult/classify/modbus/netzob/out'+str(value),(7,8),int(value))
#get_basespes(file_from,file_to,(int(start),int(end)),int(value),int(lo))
#getourspe(file_from,file_to,(int(start),int(end)),int(value))
#get_results('/home/wxw/data/cip_datanew','/home/wxw/paper/researchresult/classify/cip/netzob_new/out'+str(value),(0,2),int(value))
#get_results('/home/wxw/data/iec104','/home/wxw/paper/researchresult/classify/iec104/netzob_two/'+str(value),(6,7),int(value))
#get_funcr('/home/wxw/data/modbustest','/home/wxw/paper/researchresult/classify/modbus/ours/out'+str(value),(7,8),int(value))
#get_funcr('/home/wxw/data/iec104','/home/wxw/paper/researchresult/classify/iec104/ours/'+str(value),(6,7),50)

get_iec104('/home/wxw/data/iec104','/home/wxw/paper/researchresult/classify/iec104/combine/'+str(50),(6,7),50)
#get_funcr('/home/wxw/data/cip_datanew','/home/wxw/paper/researchresult/classify/cip/ours/out'+str(value),(0,2),int(value))

endtime = time.time()
print(endtime - starttime)
