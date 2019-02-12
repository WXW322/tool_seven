from netzob.all import *
from treelib import *
import numpy as np
import sys
sys.path.append("../ngrambuild/")
sys.path.append("../common/")
sys.path.append("../class/")
import pyngram 
import f_cg
import parse
from readdata import *
import word_deal
import output
import time
class gformat:
    def __init__(self):
        self.vote_fs = None
        self.vote_es = None
        self.lo_f = None
        self.lo_e = None
        self.f_los = None

    def get_format(self,messages,h,ways,combine,model,v_way,T=0,r=0):
        """
        get single format
        """
        voter = pyngram.voters()
        key_locations = voter.get_info(messages,h,ways,combine,model,v_way,T,r)
        #keys_info = voter.query_keys(["1","0 0","1 0","0","1 0 0"])
        #for key in keys_info:
        #    print(key,keys_info[key])
        #sys.exit()
        return key_locations

    def get_formats(self,messages,rules,clus,h,ways,combine,model,v_way,T=0,r=0):
        t_data = None
        paser = parse.parse()
        transe = f_cg.transer()
        messager = word_deal.message_dealer()
        t_formats = {}
        if rules == "lo":
            t_data,_ = paser.cls_fun(messages,clus[0],clus[1])
        for key in t_data:
            #if key != "1":
            #    continue
            t_formats[key] = cutmessage(t_data[key],clus[1])
            l_num = 0
            #for item in t_formats[key]:
                #print(item)
            #sys.exit()
            if len(t_formats[key]) < 100:
                continue
            t_formats[key] = add_tail(t_formats[key],h)
            #print(key)
            t_formats[key] = self.get_format(t_formats[key],h,ways,combine,model,v_way,len(t_formats[key])*T,r = r)
            #messager.set_dataM(t_data[key])
            #t_formats[key] = transe.border2item(t_formats[key])
            #t_formats[key] = messager.extract_Dwords(t_formats[key],20,T=0.7)a
        return t_formats

   

def get_f(T_path,data_path,r_way,rules,clus,h,ways,combine,model,v_way,T,r):
    #T_path = "/home/wxw/paper/researchresult/modbus/format"
    #datas = read_datas("/home/wxw/data/modbusdata/","multiple") 
    datas = read_datas(data_path,r_way)
    datas_src,datas_des = clusbydesT(datas)
    datas_src = get_puredatas(datas_src)
    datas_des = get_puredatas(datas_des)
    f_name = "tempone" + str(h) + ways + combine + model + v_way + str(T) + str(r) + ".txt" 
    out_f = output.R_out()
    out_f.set_path(T_path,f_name)
    out_f.trans_out()
    g_f = gformat()
    t_f = g_f.get_formats(datas_des,rules,clus,h,ways,combine,model,v_way,T,r)
    print("des")
    out_f.print_dic(t_f)
    print("src")
    t_f = g_f.get_formats(datas_src,rules,clus,h,ways,combine,model,v_way,T,r)
    out_f.print_dic(t_f)
    out_f.back_out()
 
    
def get_common(T_path,data_path,r_way,h,ways,combine,model,v_way,T,r,R_los):
    #T_path = "/home/wxw/paper/researchresult/modbus/format"
    #datas = read_datas("/home/wxw/data/modbusdata/","multiple") 
    datas = read_datas(data_path,r_way)
    datas = get_puredatas(datas)
    messages = add_tail(datas,h)
    f_name = str(h) + ways + combine + model + v_way + str(T) + str(r) +str(time.time()) + ".txt" 
    out_f = output.R_out()
    out_f.set_path(T_path,f_name)
    out_f.trans_out()
    print(h,ways,combine,model,v_way,T,r)
    g_f = gformat()
    t_f = g_f.get_format(datas,h,ways,combine,model,v_way,T,r)
    f_trans = f_cg.transer()
    borders_pre = f_trans.border2item(t_f)
    M_dealer = word_deal.message_dealer()
    M_dealer.set_conlo(borders_pre)
    M_dealer.set_rlo(R_los)
    M_dealer.get_f1()
    M_dealer.set_dataM(messages)
    print("after")
    M_dealer.resplit("yes")
    M_dealer.reclus("yes")
    M_dealer.get_f1()
    out_f.back_out()
#for key in t_f:
#    print(key,t_f[key])
#parameters = [i*0.1 for i in range(1,11)]

for h in [2,4]:
#get_common("/home/wxw/paper/researchresult/modbus/bordertwo","/home/wxw/data/modbusdata/","single",h,"g","no","re","normal",0.1,0.1,[(0,2),(2,5),(5,6),(6,7),(7,8)])

#   get_common("/home/wxw/paper/researchresult/iec104/bordertwo/","/home/wxw/data/iec104/","single",h,"g","no","re","loose",0.1,0.1,[(0,1),(1,2),(2,4),(4,6),(6,7),(7,8),(8,9),(9,10),(10,12)])
    
    get_common("/home/wxw/paper/researchresult/cip/borderfour","/home/wxw/data/cip_datanew/","single",h,"g","no","re","loose",0.1,0.9,[(0, 2), (2, 4), (4, 8), (8, 12), (12, 20), (20, 24)])

"""
get_common("/home/wxw/paper/researchresult/modbus/bordertwo","/home/wxw/data/modbusdata/","single",4,"g","no","re","normal",0.1,0.1,[(0,2),(2,5),(5,6),(6,7),(7,8)])

get_common("/home/wxw/paper/researchresult/modbus/bordertwo","/home/wxw/data/modbusdata/","single",4,"g","no","re","loose",0.1,0.1,[(0,2),(2,5),(5,6),(6,7),(7,8)])

get_common("/home/wxw/paper/researchresult/modbus/bordertwo","/home/wxw/data/modbusdata/","single",3,"g","no","re","normal",0.1,0.1,[(0,2),(2,5),(5,6),(6,7),(7,8)])

get_common("/home/wxw/paper/researchresult/modbus/bordertwo","/home/wxw/data/modbusdata/","single",3,"g","no","re","loose",0.1,0.1,[(0,2),(2,5),(5,6),(6,7),(7,8)])
start = time.time()
    
get_common("/home/wxw/paper/researchresult/iec104/bordertwo","/home/wxw/data/iec104/","single",4,"g","no","re","normal",0.1,0.1,[(0,1),(1,2),(2,4),(4,6),(6,7),(7,8),(8,9),(9,10),(10,12)])

get_common("/home/wxw/paper/researchresult/iec104/bordertwo/","/home/wxw/data/iec104/","single",4,"g","no","re","loose",0.1,0.1,[(0,1),(1,2),(2,4),(4,6),(6,7),(7,8),(8,9),(9,10),(10,12)])

get_common("/home/wxw/paper/researchresult/iec104/bordertwo","/home/wxw/data/iec104/","single",3,"g","no","re","normal",0.1,0.1,[(0,1),(1,2),(2,4),(4,6),(6,7),(7,8),(8,9),(9,10),(10,12)])


get_common("/home/wxw/paper/researchresult/iec104/bordertwo","/home/wxw/data/iec104/","single",3,"g","no","re","loose",0.1,0.1,[(0,1),(1,2),(2,4),(4,6),(6,7),(7,8),(8,9),(9,10),(10,12)])
end = time.time()
print(end - start)
"""
#get_common("/home/wxw/paper/researchresult/cip/borderthree","/home/wxw/data/cip_datanew/","single",4,"g","no","re","normal",0.1,0.1,[(0, 2), (2, 4), (4, 8), (8, 12), (12, 20), (20, 24)])

#get_common("/home/wxw/paper/researchresult/cip/borderthree","/home/wxw/data/cip_datanew/","single",4,"g","no","re","loose",0.1,0.1,[(0, 2), (2, 4), (4, 8), (8, 12), (12, 20), (20, 24)])

#get_common("/home/wxw/paper/researchresult/cip/borderthree","/home/wxw/data/cip_datanew/","single",3,"g","no","re","normal",0.1,0.1,[(0, 2), (2, 4), (4, 8), (8, 12), (12, 20), (20, 24)])

#get_common("/home/wxw/paper/researchresult/cip/borderfour","/home/wxw/data/cip_datanew/","single",3,"g","no","re","loose",0.1,0.9,[(0, 2), (2, 4), (4, 8), (8, 12), (12, 20), (20, 24)])
#last = time.time()
#print(last - end)

#get_f("/home/wxw/paper/researchresult/iec104/format","/home/wxw/data/iec104/","multiple","lo",(6,7),3,"g","no","re","normal",0.8,0.1)

#get_f("/home/wxw/paper/researchresult/modbus/format","/home/wxw/data/modbusdata/","multiple","lo",(7,8),3,"g","no","re","normal",0.8,0.1)


#get_f("/home/wxw/paper/researchresult/modbus/format","/home/wxw/data/modbusdata/","multiple","lo",(7,8),3,"g","no","abs","loose",0.1,0.1)

#get_f("/home/wxw/paper/researchresult/modbus/format","/home/wxw/data/modbusdata/","multiple","lo",(7,8),3,"g","no","re","loose",0.1,0.1)






