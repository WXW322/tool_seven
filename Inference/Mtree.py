from netzob.all import *
from queue import queue
from Node import *

class Mtree(Field):
    def __init__(self,messages,ids,threshold,start,end = -1,t_type = "const"):
        super(Mtree,self).__init__()
        self.Nodes = ids
        self.state = "start"
        self.threshold = threshold
        self.type = t_type
        self.start = start
        self.end = end
    
        self.messages = messages

    def splitbylos(self):
        """
        F: class messages by locations
        ids: list of Node
        t_r: a dict of ids
        """
        t_los = {}
        for node  in Nodes:
            t_next = node.get_next()
            if t_next not in t_los:
                t_los[t_next] = []
                t_los[t_next].append(node)
            else:
                t_los[t_next].append(node)
        t_los["varible"] = []
        for key in t_los:
            if len(t_los[key] < threshold):
                t_los['varible'].extend(t_los[key])
                del t_los[key]
        for key in t_los:
            if key != "variable":
                t_mtree = Mtree(messages,t_los[key],threshold,self.end,key)
            else:
                t_mtree = Mtree(messages,t_los[key],threshold,self.end,key,"V")
            self.fields.append(t_mtree)
        #return t_los


    def judge_type(self,nodes):
        """
        F: judge field type 
        ids: ids whose location is same 
        t_type : value tupe od messages
        """
        t_values = []
        for node in nodes:
            print("qqq")
            
            
            
            


    def splitbyfunction(self):
        """
        F: split nodes by field type
        ids waiting to be split
        t_fields: a list of fields whose location is more backer
        """
        print("111")

    def get_tree(self):
        t_dep = 0
        t_m = self.getLeafFields(depth = t_dep)
        while(len(t_m) > 0):
            t_lo = 0
            for m in t_m:
                if m.type != "V":
                    m.splitbylos()
                    t_lo = 1
            if t_lo == 0:
                break
            t_dep = t_dep + 1


    def print_exptree(self):
        queue = Queue()
        # print(self.start,self.end)
        queue.put(self)
        while(not queue.empty()):
            t_f = queue.get()
            print(t_f.start,t_f.end)
            for f in t_f.fields:
                t_f.put(f)
                












M = Mtree()
