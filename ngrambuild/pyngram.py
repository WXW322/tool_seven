from netzob.all import *
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.decomposition import LatentDirichletAllocation
import numpy as np
import sys
import time
import os
import sys
import json
import time
sys.path.append('../common')
import readdata
 
class voters:
    def __init__(self):
        self.words_fre = None
        self.words_table = None
        self.words_entry = None
        self.glvotes = None
        self.svotes = None

    def query_key(self,key):
        return self.words_table[key],self.words_fre[key],self.words_entry[key]

    def query_keys(self,keys):
        f_r = {}
        for key in keys:
            f_r[key] = self.query_key(key)
        return f_r
    def get_single_messages(self,message):
        """
        converse a message to n-gram item
        message: a list o bytes
        return : str of n-gram items
        """
        t_list = []
        t_len = len(message)
        i = 0
        t_flist = ''
        while(i < t_len):
           if(len(t_flist) == 0):
               t_flist = t_flist + str(message[i])
           else:
               t_flist = t_flist + ' ' + str(message[i])
           i = i + 1
        return t_flist

    def printm(self,message):
        t_len = len(message)
        i = 0
        while(i < t_len):
            print(message[i])
            i = i + 1

    def get_messages(self,messages):
        """
        function: converse messages to n-gram items
        messages: a list of message
        t_lists: str sentence lists
        """
        t_lists = ''
        for message in messages:
            #printm(message)
            if(len(t_lists) == 0):
                t_lists = t_lists + self.get_single_messages(message)
            else:
                t_lists = t_lists + '. ' + self.get_single_messages(message)
        return t_lists

    def get_splitsmessages(self,messages):
        t_lists = []
        for message in messages:
            t_lists.append(self.get_single_messages(message))
        return t_lists

    def get_keywords(self,messages,valuen):
        """
        function : get frequent of each words
        messages: str multiple sentences
        t_dics: dict words and its frequent
        """
        t_inputs = [self.get_messages(messages)]
        #t_inputs = ["10 10 10 10 11"]
        vetorizer = CountVectorizer(ngram_range=(1,valuen),stop_words=[' ','.'],token_pattern='(?u)\\b\\w\\w*\\b')
        X = vetorizer.fit_transform(t_inputs)
        #t_arrays = np.sum(X.toarray(),axis = 0)
        t_arrays = np.squeeze(X.toarray())
        words = vetorizer.get_feature_names()
        t_len = len(words)
        t_dics = {}
        i = 0
        while(i < t_len):
            t_dics[words[i]] = t_arrays[i]
            i = i + 1
        self.words_table = t_dics
        return t_dics




    def get_frequent(self,t_dics,nrange):
        """
        function: caculate normalized frequence of words
        t_dics: dict words and its frequent
        nrange:the length of words
        t_frer: dict words and its frequence
        """
        t_fredic = {}
        t_biaozhun = {}
        t_mean = {}
        t_std = {}
        for i in range(1,nrange + 1):
            t_fredic[i] = []
            t_biaozhun[i] = []
        for key in t_dics:
            t_fredic[len(key.split(' '))].append(t_dics[key])

        for i in range(1,nrange + 1):
            t_fredic[i] = sum(t_fredic[i])
        t_frer = {}
        for key in t_dics:
            t_frer[key] = -np.log(t_dics[key] / t_fredic[len(key.split(' '))])
            t_biaozhun[len(key.split(' '))].append(t_frer[key])
        for i in range(1,nrange + 1):
            t_mean[i] = np.mean(np.array(t_biaozhun[i]))
            t_std[i] = np.std(np.array(t_biaozhun[i]),ddof = 1)
        for key in t_dics:
            if t_std[len(key.split(' '))] != 0:
                t_frer[key] = (t_frer[key] - t_mean[len(key.split(' '))]) / t_std[len(key.split(' '))]
            else:
                t_frer[key] = 0
        self.words_fre = t_frer
        return t_frer

    def get_childs(self,t_dics,key):
        """
        function: get childs of words key
        t_dics:dict words table
        key: str key:words
        return: float entry of children
        """
        t_entrys = []
        for i in range(0,256):
            t_idom = key + ' ' + str(i)
            if t_idom in t_dics:
                t_entrys.append(t_dics[t_idom])
        t_fentry = 0
        for entry in t_entrys:
            t_fentry = t_fentry + (entry / t_dics[key]) * np.log(entry / t_dics[key])
        return -t_fentry 
        

    def get_backentry(self,t_dics,nrange):
        """
        function: get entry of ngrams
        t_dics: dict words vacabulary
        nrange: int length of words
        return:dict entry information of words
        """
        t_entrys = {}
        for key in t_dics:
            if(len(key.split(' ')) < nrange + 1):
                t_entrys[key] = self.get_childs(t_dics,key)
            else:
                t_entrys[key] = 0
        t_entrylist = {}
        for i in range(1,nrange + 1):
            t_entrylist[i] = []
        for key in t_entrys:
            t_entrylist[len(key.split(' '))].append(t_entrys[key])
        t_entrymean = {}
        t_entrystd = {}
        for i in range(1,nrange + 1):
            t_entrymean[i] = np.mean(np.array(t_entrylist[i]))
            t_entrystd[i] = np.std(np.array(t_entrylist[i]),ddof = 1)
        for key in t_entrys:
            if t_entrystd[len(key.split(' '))] == 0:
                t_entrys[key] = 0
            else:
                t_entrys[key] = (t_entrys[key] - t_entrymean[len(key.split(' '))]) / (t_entrystd[len(key.split(' '))])
        return t_entrys

    def s2key(self,ses):
        """
        function:converse a data sequence to words
        ses: bytes sequences
        return: str words
        """
        s_f = ""
        for s in ses:
            if len(s_f) == 0:
                s_f = s_f + str(s)
            else:
                s_f = s_f + ' ' + str(s)
        return s_f

    def vote_item(self,itom_s,t_frer,t_entrys):
        """
        function: get vote location of single item
        itom_s: bytes sequence
        t_frer: dict frequent table
        t_entrys:dict entry table

        """
        t_lo = 0
        t_len = len(itom_s)
        i = 1
        t_min_fre = 100
        t_max_entry = -100
        t_fre_lo = -1
        t_entry_lo = -1
        while(i <= t_len):
            t_pre = self.s2key(itom_s[0:i])
            if i < t_len:
                t_last = self.s2key(itom_s[i:t_len])
            else:
                t_last = "300"
            t_fre = t_frer[t_pre] + t_frer[t_last]
            t_entry = t_entrys[t_pre]
            if t_fre < t_min_fre:
                t_min_fre = t_fre
                t_fre_lo = i
            if t_entry > t_max_entry:
                t_max_entry = t_entry
                t_entry_lo = i
            i = i + 1
        return t_fre_lo,t_entry_lo

    def vote_sequence(self,sequence,win_L,t_frer,t_entrys):
        """
        get voting result of a sequence
        sequnce:a message
        t_frer:frequent dict
        t_entrys:entry dict
        t_los: a location list
        win_L:size of ngram
        """
        t_len = len(sequence)
        i = 0
        f_fres = {}
        f_entrys = {}
        while(i < t_len):
            if i < t_len - win_L:
                t_fre,t_entry = self.vote_item(sequence[i:i+win_L],t_frer,t_entrys)
            else:
                t_fre,t_entry = self.vote_item(sequence[i:t_len],t_frer,t_entrys)
            t_f_item = i + t_fre
            t_e_item = i + t_entry
            if t_f_item not in f_fres:
                f_fres[t_f_item] = 1
            else:
                f_fres[t_f_item] = f_fres[t_f_item] + 1
            if t_e_item not in f_entrys:
                f_entrys[t_e_item] = 1
            else:
                f_entrys[t_e_item] = f_entrys[t_e_item] + 1
            #f_fres.append(i + t_fre)
            #f_entrys.append(i + t_entry)
            i = i + 1
        i = 0
        while(i < win_L):
            if i in f_fres:
                f_fres[i] = f_fres[i] * (win_L / i)
            if i in f_entrys:
                f_entrys[i] = f_entrys[i] * (win_L / i)
            i = i + 1
        return f_fres,f_entrys

    def vote_singlese(self,t_los, model, way,T = 0,r = 0):
        """
        funtion: get final los for one messages
        t_los:vote locations(dict)
        way:vote strategy:str
        T:vote threshold:int
        return: final locations(set)
        """
        t_flos = []
        for key in t_los:
            t_now = t_los[key]
            pre_key = key - 1
            last_key = key + 1
            t_pre = 0 if pre_key not in t_los else t_los[pre_key]
            t_last = 0 if last_key not in t_los else t_los[last_key]
            if model == "abs" and way == "normal":
                if t_now > T and t_now > t_pre and t_now > t_last:
                    t_flos.append(key)
            elif model == "abs" and way == "loose":
                if key != 1:
                    if t_now > T and ((t_now > t_pre) or (t_now > t_last)):
                        t_flos.append(key)
                else:
                    if t_now > T and ((t_now > t_pre) and (t_now > t_last)):
                        t_flos.append(key)
            elif model == "re" and way == "normal":
                if key != 1:
                    if t_now > T and (((t_pre == 0) or (t_now/t_pre > 1 + r)) and ((t_last == 0) or (t_now/t_last > 1 + r))):
                    # print(key)
                        t_flos.append(key)
                else:
                    if t_now > T and ((t_last == 0) or (t_now/t_last > 1 + r)):
                    # print(key)                        
                        t_flos.append(key)
            elif model == "re" and way == "loose":
                if key != 1:
                    if t_now > T and (((t_pre == 0) or (t_now/t_pre > 1 + r)) or ((t_last == 0) or (t_now/t_last > 1 + r))):
                        t_flos.append(key)
                else:
                    if t_now > T and ((t_last == 0) or (t_now/t_last > 1 + r)):
                        t_flos.append(key)
            else:
                print("error")
        return t_flos
            

    def tulple2dic(self,tulple):
        t_dic = {}
        for item in tulple:
            t_dic[item[0]] = item[1]
        return t_dic

     
    def get_voter(self,sequences,way,T):
        """
        function: get result for a sequece
        sequence:list of messages:list
        way:vote stratagy:string
        T:threshold int
        return:a list of final locations
        """
        t_fsequence = []
        for t_setemp in sequences:
            t_temp_lo = sorted(t_setemp.items(),key = lambda x:x[0])
            print(t_temp_lo)
            t_temp_lo = self.tulple2dic(t_temp_lo)
            t_fsequence.append(self.vote_singlese(t_temp_lo,way,T))
        return t_fsequence

    def get_gvotes(self,sentences):
        """
        F: get global voting results
        sentences: list of bytes (messages set)
        way:caculate ways
        """
        t_flos = {}
        for sentence in sentences:
            for key in sentence:
                if key not in t_flos:
                    t_flos[key] = sentence[key]
                else:
                    t_flos[key] = t_flos[key] + sentence[key]
        return t_flos

    def merge_splits(self,seq1,seq2):
        s_los = set()
        for key in seq1:
            s_los.add(key)
        for key in seq2:
            s_los.add(key)
        l_los = list(s_los)
        l_los.sort()
        return l_los
 
    def filter_los(self,los,length):
        t_los = 0
        drop_keys = []
        for key in los:
            if key > length:
                drop_keys.append(key)
            if key == length:
                t_los = 1
        for key in drop_keys:
            los.pop(key)
        if t_los == 0:
            los[length] = 1
        return los


    def get_info(self,messages,h,ways = "g",combine = "no",model = "abs", v_way="normal",T=0,r=0,stren = "no"):
        t_dics = self.get_keywords(messages,h + 1)
        t_fres = self.get_frequent(t_dics,h + 1)
        t_fres["300"] = 0
        self.words_fre = t_fres
        t_entrys = self.get_backentry(t_dics,h + 1)
        self.words_entry = t_entrys
        self.words_table = t_dics
        t_mes_frelos = []
        t_me_entry_los = []
        for i in range(len(messages)):
            t_fre_r,t_entry_r = self.vote_sequence(messages[i],h,t_fres,t_entrys)
            t_fre_r = self.filter_los(t_fre_r,int(len(messages[i]) - h))
            t_entry_r = self.filter_los(t_entry_r,int(len(messages[i]) - h))
            t_mes_frelos.append(t_fre_r)
            t_me_entry_los.append(t_entry_r)
        if ways == "g" and combine == "no":
            lo_f = self.get_gvotes(t_mes_frelos)
            lo_e = self.get_gvotes(t_me_entry_los)
            t_lastone = lo_f[max(lo_f,key = lo_f.get)]
            t_lasttwo = lo_e[max(lo_e,key = lo_e.get)]
            last_f = max(t_lastone,t_lasttwo)
            #print(lo_f)
            #print(lo_e)
            lo_vf = self.vote_singlese(lo_f, model, v_way, T, r)
            lo_ve = self.vote_singlese(lo_e, model, v_way, T, r)
            #print(lo_vf)
            #print(lo_ve)
            t_results = self.merge_splits(lo_vf,lo_ve)
            if t_results[-1] < last_f:
                t_results.append(-1)
            print(t_results)
#print(t_results)

        elif ways == "g" and combine == "yes":
            sum_los = []
            sum_los.extend(t_mes_frelos)
            sum_los.extend(t_me_entry_los)
            sum_Tlos = self.get_gvotes(sum_los)
            t_lasts = sum_Tlos[-1]
            t_results = self.vote_singlese(sum_Tlos,way=v_way)
            if(t_results[-1] < t_lasts):
                t_results.append(-1)
        
        return t_results


        
                




            

"""        
        
datas = readdata.read_datas('/home/wxw/data/iec104/')
messages = readdata.get_puredatas(datas)
            
start = time.time()
voter = voters()
t_r = voter.get_info(messages,4,r=0.1)
print(t_r)
print(len(voter.words_table))
"""
"""
t_dics = voter.get_keywords(messages,5)
t_fres = voter.get_frequent(t_dics,6)
t_fres["300"] = 0
t_entrys = voter.get_backentry(t_dics,6)
t_mes_frelos = []
t_me_entry_los = []
for i in range(5):
    t_fre_r,t_entry_r = voter.vote_sequence(messages[i],5,t_fres,t_entrys)
    t_me_entry_los.append(t_entry_r)
#t_results = voter.get_voter(t_mes_frelos,'normal',0)
t_results = voter.get_voter(t_me_entry_los,'normal',0)    
print(t_results)
end = time.time()
print(end - start)
"""
           
