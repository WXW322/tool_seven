from netzob.all import *
from treelib import *
import numpy as np
import sys 
sys.path.append("../common/")
import f_cg


class parse:
    def __init__(self):
        self.format = None

    def cls_fun(self,messages,lo_s,lo_e):
        transpose = f_cg.transer()
        t_dic = {}
        others = []
        for message in messages:
            t_idom = transpose.byte2str(message[lo_s:lo_e])
            if t_idom == "":
                others.append(message)
                continue
            if t_idom not in t_dic:
                t_dic[t_idom] = []
            t_dic[t_idom].append(message)
        return t_dic,others
