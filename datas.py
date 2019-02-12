#-*- coding: utf-8 -*-
from netzob.all import *
from pygraphviz import *

import sys

sys.path.append("/home/wxw/PycharmProjects/tools_six/classify_6/stringcompare")
from classify import *
from t_node import *
from cluster import *
sys.path.append("/home/wxw/PycharmProjects/tools_six/classify_6/frequent_find")
from length_static import length_info
from find_one import frequents_find

#主要数据结构类
class datas:
    
    def __init__(self):
       self.MessageList=[]
       self.symbol=None
       self.symbols={}
       self.abstractlist=[]
       self.pure_messages=[]
       self.pure_symbols=[]
       self.count=0
       self.protocol = ''
       self.key_lo = 0
       self.code_clu = {}
       self.code_list = []




    def readMessage(self,filename):
        self.MessageList=PCAPImporter.readFile(filename).values()
        self.symbol=Symbol(messages=self.MessageList)
        t_pro = self.MessageList[0].source
        t_proone = self.MessageList[0].destination
        if(t_pro.find('502')!= -1 or t_proone.find('502')!= -1):
            self.protocol = 'modbus'
        elif(t_pro.find('2404')!= -1 or t_proone.find('2404')!= -1):
            self.protocol = 'iec104'
        for me in self.MessageList:
            s_s=str(me.data)
            s_temp=t_node(0,s_s)
            self.pure_messages.append(s_temp)
        return self.MessageList

    def sealign(self):
        print "ttt"
        if(self.symbol is None):
            if(len(self.MessageList)==0):
                print "sss"
                return None
            else:
                print "kkk"
                self.symbol=Symbol(messages=self.MessageList)
                Format.splitAligned(self.symbol,doInternalSlick=True)
        else:
            Format.splitAligned(self.symbol,doInternalSlick=True)
        return self.symbol

    def splitdilimeter(self,delimeter,leixing):
        if (leixing==0):
            if(self.symbol is None):
                if(len(self.MessageList)==0):
                    return None
                else:
                    print "A"
                    self.symbol=Symbol(messages=self.MessageList)
                    Format.splitDelimiter(self.symbol, ASCII(delimeter))
            else:
                print "B"
                mt=delimeter.encode("ascii")
                zt=delimeter.decode("unicode_escape")
                print zt
                print type(mt)
                print type(delimeter)
                kt="\r\n"
                print type(kt)
                print repr(kt)
                print repr(mt)
                if "\r\n"==mt:
                     print "000"
                else:
                     print "111"
                Format.splitDelimiter(self.symbol, ASCII(zt))
                print "kkkzzz"
        else:
           if(self.symbol is None):
                if(len(self.MessageList)==0):
                    return None
                else:
                    print "C"
                    self.symbol=Symbol(messages=self.MessageList)
                    Format.splitDelimiter(self.symbol, Raw(delimeter))
           else:
                print "D"
                Format.splitDelimiter(self.symbol, Raw(delimeter))
        return self.symbol

    def remove_col(self,index):
        del self.symbol.messages[index]

    def get_symbol(self):
        return self.symbol

    def do_align(self,index):
        Format.splitAligned(self.symbol.fields[index],doInternalSlick=True)

    def cluster(self,lo):
        self.symbols = Format.clusterByKeyField(self.symbol, self.symbol.fields[lo])

    def get_symbolsl(self):
        l_r=[]
        for keyFieldName, s in self.symbols.items():
            l_r.append(keyFieldName)
        return l_r


    def get_ith(self,lo):
        return self.symbols.values()[lo]

    def set_symbol(self,lo):
        self.symbol=self.symbols.values()[lo]

    def get_state_mecine(self):
        session=Session(self.MessageList)
        sessionlist=session.getTrueSessions()
        for se in sessionlist:
            sse = se.abstract(self.symbols.values())
            self.abstractlist.append(sse)
        automata = Automata.generatePTAAutomata(self.abstractlist,self.symbols.values())
        dotcode = automata.generateDotCode()
        t_g=automata.get_graph()
        t_g.layout()
        t_g.draw("/home/wxw/tools_four/pic_ture/second.png")
        return str(dotcode)

    def do_classify(self,num,count):
        self.count=count
        self.jihe=cluster(self.pure_messages,self.count)
        self.jihe.update_bytime(num)
        i=0
        while(i<count):
            message_temp=[]
            for r in self.jihe.clus[i]:
                temp=RawMessage(r.contain)
                message_temp.append(temp)
            symbol=Symbol(messages=message_temp)
            Format.splitAligned(symbol,doInternalSlick=True)
            self.pure_symbols.append(symbol)
            i=i+1

    def get_top_left(self):
        messages=[]
        for y in self.jihe.cores:
            messages.append(repr(y.contain))
        return messages


    def get_top_right(self,num):
        messages=[]
        for r in self.jihe.clus[num]:
            messages.append(repr(r.contain))
            print repr(r.contain)
        return messages

    def get_down(self,num):
        sys=self.pure_symbols[num]
        #code = '协议:   '+ self.protocol + '功能码' + repr(self.code_list[num][0][self.key_lo]) + '\r\n'
        return sys._str_debug()

    def get_down_one(self,num):
        sys=self.pure_symbols[num]
        code = '协议:   '+ self.protocol + '功能码' + repr(self.code_list[num][0][self.key_lo]) + '\r\n'
        return code + sys._str_debug()

    def classify_bycode(self):
        for message in self.pure_messages:
            code = message.contain[self.key_lo]
            if(self.code_clu.has_key(code)):
                self.code_clu[code].append(message.contain)
            else:
                T_l = []
                T_l.append(message.contain)
                self.code_clu[code] = T_l
        for key,value in self.code_clu.items():
            self.code_list.append(value)
            t_temp = []
            for me in value:
                rawmessage = RawMessage(me)
                t_temp.append(rawmessage)
            symbol = Symbol(messages=t_temp)
            Format.splitAligned(symbol,doInternalSlick=True)
            self.pure_symbols.append(symbol)

    def get_t_L(self):
        messages = []
        for key,values in self.code_clu.items():
            messages.append(repr(values[0]))
        return messages

    def get_t_R(self,num):
        messages=[]
        for r in self.code_list[num]:
            messages.append(repr(r))
        return messages

    def get_graphlength(self):
        t_pure = []
        for me in self.MessageList:
            s_s = str(me.data)
            s_temp = t_node(0, s_s)
            s_temp.length = len(s_s)
            t_pure.append(s_temp.length)
        t_test = length_info()
        t_test.get_lenggraph(t_pure)

    def get_frequent(self,head,count):
        fy = frequents_find([1,1,1])
        t_str = []
        for message in self.MessageList:
            t_str.append(str(message.data))
        result = fy.show_str(t_str,head,count)
        return result









    
    
        
    
    
    
    
