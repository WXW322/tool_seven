from node import *
from factor import *
from prepare import *
from netzob.all import *
from classify import *



if __name__=="__main__":
    
    messages = PCAPImporter.readFile("tftp.pcap").values()
    start_cluster=[]
    for m_temp in messages:
        r_temp=Raw(m_temp.data)
        b_temp=r_temp.value.toBytes()
        start_cluster.append(b_temp)
    spart=classify(start_cluster)
    spart.do_classify()
    for r in spart.result:
        for j in r:
           print repr(j)
        print ""
        print ""
    
    
