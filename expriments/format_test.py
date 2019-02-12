from netzob.all import *
from treelib import *
import numpy as np
import sys 

def f_test:
    def __init__(self):
        print("enter_format")

    def get_bscore(self,los_one,los_two):
        t_H = self.rborders[-1]
        conpbors = set(self.conborders)
        rpborders = set(self.rborders)
        T_boders = set([i for i in range(t_H + 1)])
        rnborders = T_boders - rpborders
        connbors = T_boders - conpbors
        tpborders = rpborders&conpbors
        fnborders = rpborders&connbors
        fpborders = rnborders&conpbors
        tnborders = rnborders&connbors
        acc = (len(tpborders) + len(tnborders))/(len(tpborders) + len(tnborders) + len(fnborders) + len(fnborders))
        pre = len(tpborders)/(len(tpborders) + len(fpborders))
        recall = (len(tpborders)/(len(tpborders) + len(fnborders)))
        f1 = 2*pre*recall/(pre + recall)
        print("conb:",self.conborders)
        print("rb:",self.rborders)
        print("To;",T_boders)
        print("tp:",tpborders)
        print("fn:",tnborders)
        print("fp:",fpborders)
        print("tn:",tnborders)
        print("pre:",pre)
        print("recall:",recall)
        print("f1:",f1)
        return pre,recall,f1




