from scapy.all import *
from netzob.all import *
from classify import *
from t_node import *
from cluster import *
tftp_one=rdpcap("final_last.pcap")
start_str=[]
for t in tftp_one:
     ss=str(t)
     ss1=ss[54:]
     if(len(ss1)>0):
        start_str.append(ss1)
for s in start_str:
    print repr(s)
print "\r\n"
start_list=[]
for s in start_str:
    nn=t_node(0,s)
    start_list.append(nn)
jihe=cluster(start_list,5)
jihe.update_bytime(20)
print "kkk"
i=0
file_object = open('thefile_six.txt', 'w+')
while(i<5):
    print i
    file_object.write(repr(i))
    file_object.write("\r\n")
    print repr(jihe.cores[i].contain)
    file_object.write(repr(jihe.cores[i].contain))
    file_object.write("\r\n")
    print "clui"
    for r in jihe.clus[i]:
        file_object.write(repr(r.contain))
        file_object.write("\r\n")
        print repr(r.contain)
    i=i+1
    print ""
    file_object.write("\r\n")
file_object.close()
print ""

