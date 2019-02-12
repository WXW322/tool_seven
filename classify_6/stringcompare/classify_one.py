from netzob.all import *
from node import *

from factor import *

from prepare import *

messages= PCAPImporter.readFile("modbus-new.pcap").values()
t_len=len(messages)
t_vis=[0 for i in range(t_len)]
result_message=[]
result_l=[]
for i in range(t_len-1):
    if(t_vis[i]==1):
        continue
    t_vis[i]=1
    t_temp=[]
    l_temp=[]
    t_temp.append(messages[i])
    l_temp.append(i)
    for j in range(i+1,t_len):
        if(t_vis[j]==1):
            continue
        else:
            start_one=str(messages[i].data)
            start_two=str(messages[j].data)
            pe=prepare(start_one,start_two)
            pe.get_lists()
            pe.get_data()
            fy=factor(start_one,start_two,pe.change)
            fy.spart_1()
            if(fy.get_same1()>=0.3):
                t_vis[j]=1
                t_temp.append(messages[j])
                l_temp.append(j)
    result_message.append(t_temp)
    result_l.append(l_temp)
    print result_l
    
