from netzob.all import *
from treelib import *
import numpy as np
import sys

class transer:
    def __init__(self):
        self.name = ""

    def byte2str(self,b_se):
        t_name = ""
        for i in range(len(b_se)):
            if i == 0:
                t_name = str(b_se[i])
            else:
                t_name = t_name + ' ' + str(b_se[i])
        return t_name
      
    def border2item(self,borders):
        itoms = []
        i = 0
        while(i < len(borders)):
            if i == 0:
                itoms.append((0,borders[i]))
            else:
                itoms.append((borders[i-1],borders[i]))
            i = i + 1
        return itoms
    
    def sort_length(self,messages):
        lengths = [len(message) for message in messages]
        lengths.sort(reverse=True)
        return lengths

    def get_range(self,ratio,messages):
        lengths = [len(message.data) for message in messages]
        lengths.sort()
        lo = int(len(messages) * ratio)
        return lengths[lo]




        

