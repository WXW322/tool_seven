from node import *

from factor import *

from prepare import *

#from netzob.all import *

class classify(object):

    def __init__(self,classify):
        self.start=classify
        self.result=[]
        self.link=[]


    def do_classify(self):
        file_object = open('thefile2.txt', 'w')
        t_len=len(self.start)
        t_vis=[0 for i in range(t_len)]
        for i in range(t_len-1):
            if(t_vis[i]==1):
                continue
            t_vis[i]=1
            t_temp=[]
            l_temp=[]
            t_temp.append(self.start[i])
            l_temp.append(i)
            for j in range(i+1,t_len):
                if(t_vis[j]==1):
                    continue
                else:
                    #file_object.write(repr(i+1))
                    #file_object.write(" ")
                    #file_object.write(repr(j+1))
                    #print ("%d %d"%(i,j))
                    #file_object.write('\r\n')
                    #file_object.write(repr(self.start[i]))
                    #file_object.write('\r\n')
                    #file_object.write(repr(self.start[j]))
                    #file_object.write('\r\n')
                    #file_object.flush()
                    #print repr(self.start[i])
                    #print repr(self.start[j])
                    pe=prepare(self.start[i],self.start[j])
                    pe.get_lists()
                    pe.get_data()
                    fy=factor(self.start[i],self.start[j],pe.change)
                    fy.spart_1()
                    #fy.cluster()
                    #fy.get_similar()
                    print (i+1," ",j+1," ",fy.get_sim())
                    if(fy.get_same1()>=0.25):
                        t_vis[j]=1
                        t_temp.append(self.start[j])
                        l_temp.append(j)
            self.result.append(t_temp)
            self.link.append(l_temp)
        file_object.close()
