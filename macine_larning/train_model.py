import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn import metrics
import sys
from sklearn.metrics import accuracy_score
from netzob.all import *
from get_traindata import *

class train_data:
    def __init__(self,data_num,file_name):
        self.data_num = data_num
        self.models = []
        self.filename = file_name
        self.data_right = None
        self.data_wrong = None
        self.data_valid = None
        self.datas = None
        self.out_data = None

    def get_dataset(self):
        data = pd.read_csv(self.filename)
        data = data.sample(frac = 1).reset_index(drop = True)
        self.data_right = data[data['lable'] == 1]
        self.data_wrong = data[data['lable'] == 0]
        length_r = self.data_right.shape[0]
        length_w = self.data_wrong.shape[0]
        self.data_valid = self.data_right[0:int(length_r/10)]
        self.data_right = self.data_right[int(length_r/10):]
        self.data_valid = pd.concat([self.data_valid,self.data_wrong[0:int(length_r/10)]])
        self.data_wrong = self.data_wrong[int(length_r/10):]
        i = 0
        self.datas = []
        while(i < self.data_num):
            data_temp = self.data_wrong.sample(frac = 0.1)
            self.datas.append(data_temp)
            i = i + 1
        return self.data_right,self.datas

    def get_transdata(self,filename):
        self.out_data = pd.read_csv(filename)
    def crossvalidate(self,features,lable):
        i = 0
        while(i < self.data_num):
            model_temp = self.models[i]
            print (model_temp.score(self.data_valid[features],self.data_valid[lable]))
            i = i + 1


    def transvalidate(self,features,lable):
        i = 0
        while(i < self.data_num):
            model_temp = self.models[i]
            print (model_temp.score(self.outdata[features],self.outdata[lable]))
            i = i + 1





    def get_tempdata(self):
        data = pd.read_csv(self.filename)
        self.data_right = data[data['lable'] == 1]
        self.data_wrong = data[data['lable'] == 0]
        length_r = self.data_right.shape[0]
        length_w = self.data_wrong.shape[0]
        self.data_valid = self.data_right[0:length_r/10]
        self.data_right = self.data_right[length_r/10:]
        self.data_valid = pd.concat([self.data_valid,self.data_wrong[0:length_r/10]])
        self.data_wrong = self.data_wrong[length_r/10:]
        i = 0
        self.datas = []
        length_one = self.data_right.shape[0]
        length_two = self.data_wrong.shape[0]
        t_num = length_two/length_one
        pre = 0
        while(i < t_num):
            data_temp = self.data_wrong[pre:pre+length_one]
            self.datas.append(data_temp)
            pre = pre + length_one
            i = i + 1
        self.datas.append(self.data_wrong[pre:])
        return self.data_right,self.datas

    def get_models(self,features,lable):
        i = 0
        #data_right,data_wrong = self.get_dataset()
        #while(i < self.data_num):
        while (i < len(self.datas)):
            models_temp = MLPClassifier(hidden_layer_sizes=(40,40),activation='relu',solver='adam')
            data_new = pd.concat([self.data_right,self.datas[i]])
            i = i + 1
            models_temp.fit(data_new[features],data_new[lable])
            self.models.append(models_temp)

    def validate(self,features,lable):
        i = 0
        while(i < self.data_num):
            model_temp = self.models[i]
            print (model_temp.score(self.data_valid[features],self.data_valid[lable]))
            i = i + 1
    def validate_multy(self,features,lable):
        i = 0
        length = self.data_valid.shape[0]
        t_list = []
        for i in range(length):
            t_list.append(0)
        t_f = np.array(t_list)
        i = 0
        while (i < self.data_num):
            model_temp = self.models[i]
            # print (model_temp.score(self.out_data[features],self.out_data[lable]))
            t_r = model_temp.predict(self.data_valid[features])
            t_f = t_f + t_r
            i = i + 1
        f_l = []
        i = 0
        while (i < length):
            if (t_f[i] > int(self.data_num / 2)):
                f_l.append(1)
            else:
                f_l.append(0)
            i = i + 1
        f_f = np.array(f_l)
        print(accuracy_score(self.data_valid['lable'], f_f))


    def tran_learning(self,features,lable):
        i = 0
        while(i < self.data_num):
            model_temp = self.models[i]
            print (model_temp.score(self.out_data[features],self.out_data[lable]))
            i = i + 1

    def trans_multi(self,features,lable):
        i = 0
        length = self.out_data.shape[0]
        t_list = []
        for i in range(length):
            t_list.append(0)
        t_f = np.array(t_list)
        i = 0
        while(i < self.data_num):
            model_temp = self.models[i]
            print (model_temp.score(self.out_data[features],self.out_data[lable]))
            t_r = model_temp.predict(self.out_data[features])
            t_f = t_f + t_r
            i = i + 1
        f_l = []
        i = 0
        while(i < length):
            if(t_f[i] > int(self.data_num / 2)):
                f_l.append(1)
            else:
                f_l.append(0)
            i = i + 1
        f_f = np.array(f_l)

    def get_r(self,features,lable,datas):
        i = 0
        length = datas.shape[0]
        t_list = []
        for i in range(length):
            t_list.append(0)
        t_f = np.array(t_list)
        i = 0
        while(i < self.data_num):
            model_temp = self.models[i]
            #print (model_temp.score(self.out_data[features],self.out_data[lable]))
            t_r = model_temp.predict(datas[features])
            t_f = t_f + t_r
            i = i + 1
        f_l = []
        i = 0
        while(i < length):
            if(t_f[i] > int(self.data_num / 2)):
                f_l.append(1)
            else:
                f_l.append(0)
            i = i + 1
        f_f = np.array(f_l)
        print (f_f)
        sys.exit()
        datas['lable'] = f_f
        print (datas[datas['lable'] == 1]['lo'])
















data = pd.read_csv('/home/wxw/data/iec104_train/lable_finalone.csv')
feature = data.columns.values.tolist()
feature.remove('value')
feature.remove('lable')
tt = train_data(10,'/home/wxw/data/iec104_train/lable_finalone.csv')
tt.get_dataset()
tt.get_models(feature,'lable')
#tt.validate(feature,'lable')
#tt.validate_multy(feature,'lable')
tt.get_transdata('/home/wxw/data/modbus_train/lable_finalone.csv')
#tt.validate_multy(feature,'lable')
data = PCAPImporter.readFile('/home/wxw/data/modbus_pure.pcap').values()
dd = produce_medata([1,1,1])
t_r = dd.transonelable(data[0].data,'/home/wxw/data/modbus_train/lable_finaltwo.csv')
tt.get_r(feature,'lable',t_r)
