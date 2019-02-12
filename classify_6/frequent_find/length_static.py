#-*- coding: utf-8 -*-
from netzob.all import *
import sys
sys.path.append("../../")
import t_node
import numpy as np
import random
import math
from matplotlib import pyplot as plt



class length_info:
    def __init__(self):
        self.min_length = 0
        self.max_length = 0

    def get_freq(self,data):
        t_data = []
        for da in data:
            t_data.append(da.length)
        print t_data
        self.get_lenggraph(t_data)

    def get_lenggraph(self,data):
        bins = np.linspace(math.ceil(min(data)),math.floor(max(data)),20)
        plt.xlim([min(data) - 5, max(data) + 5])
        plt.hist(data, bins=bins, alpha=0.5)
        plt.title('length static data (fixed number of bins)')
        plt.xlabel('variable X (20 evenly spaced bins)')
        plt.ylabel('count')
        plt.show()

    def get_cdf_graph(self,data):
        data_X = []
        data_Y = []
        start = min(data)
        end = max(data)
        sum_num = sum(data)
        length = float(end - start)
        step = length/100
        i = start
        while(i < end):
            temp = [j for j in data if j <= i]
            temp_num = float(sum(temp))
            temp_Y = temp_num/sum_num

            data_X.append(i)
            data_Y.append(temp_Y)
            i = i + step
        data_X.append(end)
        data_Y.append(1)
        plt.plot(data_X, data_Y, '-', linewidth=2)
        plt.show()

    def get_range(self,start,end,data):
        t_data = []
        for da in data:
            if(start <= da.length and end >= da.length):
                t_data.append(da)
        return t_data








