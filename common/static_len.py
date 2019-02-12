import sys
#sys.path.append("../common/")
import f_cg
from readdata import *

def sta_lengths(messages,h_r):
    transer = f_cg.transer()
    lengths = transer.sort_length(messages)
    r_ac = {}
    len_T = len(lengths)
    for a in range(1,11,1):
        t_line = int(len_T * a * 0.1)
        len_now = lengths[t_line - 1]
        if h_r < len_now:
            r_ac[a] = 1
        else:
            r_ac[a] = float(len_now) / float(h_r)
    return r_ac

def get_lengths(path,h):
    datas = read_datas(path)
    messages = get_puredatas(datas)
    r_ac = sta_lengths(messages,h)
    print(r_ac)
 
get_lengths("/home/wxw/data/modbusdata/",8)
get_lengths("/home/wxw/data/iec104/",12)
get_lengths("/home/wxw/data/cip_datanew/",24)

    
