import os
from netzob.all import *


def read_datas(dirs,ways = "single"):
    paths = os.listdir(dirs)
    t_datas = []
    t_sedatas = []
    if ways == "single":
        for path in paths:
            t_path = os.path.join(dirs,path)
            t_data = PCAPImporter.readFile(t_path).values()
            t_datas.extend(t_data)
    else:
                
        for path in paths:
            t_path = os.path.join(dirs,path)
            t_data = PCAPImporter.readFile(t_path).values()
            t_datas.append(t_data)
    return t_datas
 


def get_puredatas(datas):
    t_fdata = []
    for data in datas:
        t_fdata.append(data.data)
    return t_fdata

def get_itoms(string,delimiter):
    return string.split(delimiter)

def add_stail(message,h):
    message_b = bytearray(message)
    for i in range(h):
        message_b.append(250)
    return bytes(message_b)
    
def add_tail(messages,h):
    for i in range(len(messages)):
        messages[i] = add_stail(messages[i],h)
    return messages

def cutmessage(messages,lo_c):
    for i in range(len(messages)):
        messages[i] = messages[i][lo_c:]
    return messages

def get_part(messages, lo):
    t_f = []
    for message in messages:
        t_f.append(message[:lo])
    return t_f

def get_ip(t_str):
    t_lo = t_str.find(':')
    return t_str[0:t_lo]

def clusbydes(messages):
     src = get_ip(messages[0].source)
     des = get_ip(messages[0].destination)
     srcs = []
     dess = []
     for message in messages:
        if(get_ip(message.source) == src):
            srcs.append(message)
        else:
            dess.append(message)
     return srcs,dess
def clusbydesT(Melist):
    src_Me = []
    des_Me = []
    for me in Melist:
        src_t,des_t = clusbydes(me)
        src_Me.extend(src_t)
        des_Me.extend(des_t)
    return src_Me,des_Me
