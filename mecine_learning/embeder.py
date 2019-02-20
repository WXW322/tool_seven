import numpy as np
import torch
import sys
sys.path.append('../common/')
import readdata
import os
import itertools

class base_process:
    def __init__(self, zerovalue = 0):
        self.voc = {}
        self.lo = 0
        self.cate = {}
        self.datas = []
        self.zerovalue = zerovalue

    def build_woc(self, words):
        for word in words:
            for w in word[0]:
                if w not in self.voc:
                    self.voc[w] = self.lo
                    self.lo = self.lo + 1
        self.voc[self.zerovalue] = self.lo + 1

    def read_data(self, path):
        raw_datas = readdata.read_datas(path, 'single')
        pure_datas = readdata.get_puredatas(raw_datas)
        return pure_datas

    def init_data(self, p_dir):
        t_lo = 0
        for c_dir in os.listdir(p_dir):
            if c_dir not in self.cate:
                self.cate[c_dir] = t_lo
                t_lo = t_lo + 1
            t_path = os.path.join(p_dir, c_dir)
            pure_datas = self.read_data(t_path)
            for data in  pure_datas:
                self.datas.append((data, c_dir))
        self.build_woc(self.datas)


    def input2T(self, datas):
        inputs = [self.voc[data] for data in datas[0]]
        outputs = [self.cate[datas[1]]]
        input_t = torch.LongTensor(inputs)
        output_t = torch.LongTensor(outputs)
        return input_t, output_t

    def padding(self, l):
        return list(itertools.zip_longest(*l,fillvalue=self.zerovalue))

    def inputs2T(self, datas):
        datas.sort(key = lambda i:len(i[0]),reverse=True)
        lengths = [len(item[0]) for item in datas]
        #str_l = padding(str_l,0)
        inputs = []
        outputs = []
        for s in datas:
            inputs.append([self.voc[w] for w in s[0]])
            outputs.append(self.cate[s[1]])
        inputs = self.padding(inputs)
        out_tensor = torch.LongTensor(outputs)
        input_tensor = torch.LongTensor(inputs)
        input_tensor = input_tensor.transpose(0,1)
        lengths = torch.LongTensor(lengths)
        return input_tensor,out_tensor,lengths
def test_one():
    base = base_process(zerovalue=256)
    base.init_data('/home/wxw/one_shot')
    print(len(base.inputs2T(base.datas)[0]))
#test_one()
