from netzob.all import *
from treelib import *
import numpy as np
import sys



class ngramtree:
    def __init__(self):
        """
        self.tree :ngram tree
        self.conlosfre:frequent votes
        self.conlosentry:entry votes
        self.reconlosfre:reverse frequent votes
        self.Reconlosentry:reverse Reenrty votes
        self.idoms:vote result
        """
        self.tree = Tree()
        self.tree.create_node(tag = '0_0',identifier = '0_0',data = [0])
        self.conlosfre = None
        self.conlosentry = None
        self.Reconlosfre = None
        self.Reconlosentry = None
        self.idoms = None

    def tract(self,name):
        los = name.split('_')
        return los

    def addnode(self,p_name,n_num,depth):
        name = str(depth) + '_' + str(n_num) + '_' + self.tract(p_name)[1]
        if(self.tree.contains(name)):
            t_node = self.tree.get_node(name)
            t_node.data[0] = t_node.data[0] + 1
        else:
            self.tree.create_node(tag = name,identifier = name,data = [1],parent = p_name)
        return name

    def add_sequence(self,sequence):
        t_len = len(sequence)
        i = 0
        while(i < t_len):
            if i == 0:
                p_name = '0_0'
            t_num = sequence[i]
            p_name = self.addnode(p_name,t_num,i + 1)
            i = i + 1


    def build_tree(self,sequences,L):
        for sequence in sequences:
            t_len = len(sequence)
            i = 0
            while(i < t_len):
                if i <= t_len - L:
                    self.add_sequence(sequence[i:i+L])
                else:
                    self.add_sequence(sequence[i:])
                i = i + 1

    def print_tree(self):
        for node in self.tree.all_nodes():
            print (node.identifier + '  ' + str(node.data))

    def print_htree(self):
        t_H = self.tree.depth()
        t_h = 1
        while(t_h <= t_H):
            t_nodes = self.get_h(t_h)
            #print(t_h)
            for t_node in t_nodes:
                t_node = self.tree.get_node(t_node)
                print (t_node.identifier + ' ' + str(t_node.data))
            t_h = t_h + 1

    def get_hnodes(self,h):
        t_nodes = self.get_h(h)
        for t_node in t_nodes:
            self.check_childs(t_node)

    def get_h(self,h):
        t_nodes = []
        for node in self.tree.all_nodes():
            if int(self.tract(node.identifier)[0]) == h:
                t_nodes.append(node.identifier)
        return t_nodes


    def caculate_prob(self):
        """
        caculate prob of each node
        :return:
        """
        t_H = self.tree.depth()
        t_h = 1
        while(t_h <= t_H):
            t_hnodes = self.get_h(t_h)
            t_sum = 0
            t_hpro = []
            t_cpro = []
            for t_n in t_hnodes:
                t_sum = self.tree.get_node(t_n).data[0] + t_sum
                t_node = self.tree.get_node(t_n)
                if t_node.is_leaf():
                    t_node.data.append(0)
                    continue
                t_childrens = self.tree.children(t_n)
                t_shang = 0
                for child in t_childrens:
                    t_shang = t_shang + (child.data[0]/t_node.data[0])*np.log(child.data[0]/t_node.data[0])
                t_node.data.append(-t_shang)
            for t_n in t_hnodes:
                t_node = self.tree.get_node(t_n)
                t_parentnode = self.tree.parent(t_n)
                if t_h > 1:
                    t_node.data.append((t_node.data[0] / t_sum) * (t_node.data[0]/t_parentnode.data[0]))
                    t_hpro.append((t_node.data[0]/t_sum) * (t_node.data[0]/t_parentnode.data[0]))
                else:
                    t_node.data.append((t_node.data[0] / t_sum))
                    t_hpro.append((t_node.data[0] / t_sum))

                t_cpro.append(t_node.data[1])
            t_ndata = np.array(t_hpro)
            mean = np.mean(t_ndata)
            std = np.std(t_ndata,ddof=1)
            t_sdata = np.array(t_cpro)
            mean_s = np.mean(t_sdata)
            std_s = np.std(t_sdata,ddof=1)
            for t_n in t_hnodes:
                t_node = self.tree.get_node(t_n)
                if(std != 0):
                    t_node.data[2] = (t_node.data[2] - mean)/std
                else:
                    t_node.data[2] = (t_node.data[2] - mean)
                if(mean_s == 0 and std_s ==0):
                    t_node.data[1] = -100.0
                    continue
                t_node.data[1] = (t_node.data[1] - mean_s)/std_s
            t_h = t_h + 1

    def query_info(self,idom):
        t_len = len(idom)
        i = 0
        t_root = '0_0'
        while(i < t_len):
            t_temp = idom[i]
            t_childrens = self.tree.children(t_root)
            t_has = 0
            for children in t_childrens:
                #if (self.tract(children.identifier)[1] == t_temp):
                if(int(self.tract(children.identifier)[1]) == t_temp):
                    t_has = 1
                    t_root = children.identifier
                    break
            if(t_has == 0):
                break
            i = i + 1
        if(i != t_len or i == 0):
            return 0,0
        else:
            return self.tree.get_node(t_root).data[2],self.tree.get_node(t_root).data[1]

    def get_hnodes(self,h):
        """
        get all h nodes childern info
        :param h:
        :return:
        """
        t_nodes = self.get_h(h)
        for t_node in t_nodes:
            t_node = self.tree.get_node(t_node)
            self.check_childs(t_node.identifier)

    def check_se(self,element):
        t_len = len(element)
        i = 0
        while(i < t_len):
            print(element[i],end=",")
            i = i + 1
        print("")

    def check_childs(self,name):
        t_node = self.tree.get_node(name)
        print(t_node.identifier + ' ' + str(t_node.data), end='!')
        t_childrens = self.tree.children(name)
        for child in t_childrens:
            print(child.identifier + ' ' + str(child.data),end='!')
        print("")


    def find_slo(self,aa):
        tt_l = len(aa)
        j = 0
        #print('ss')
        #self.check_se(aa)
        t_len = len(aa)
        i = 1
        t_maxfre = -1000
        t_frelo = -1
        t_maxent = -1000
        t_loen = -1
        while(i <= t_len):
            #print (i)
            pre = aa[:i]
            if(i < t_len):
                last = aa[i:]
            else:
                last = ''
            #print ('zz')
            #self.check_se(pre)
            t_freone,t_entryone = self.query_info(pre)
            #print(t_frelo)
            #print(t_entryone)
            #print('zz')
            #print('mm')
            #self.check_se(last)
            t_frelast,t_enlast = self.query_info(last)
            #print(t_frelast,t_enlast)
            #print('mm')
            t_fre = t_freone + t_frelast
            t_entry = t_entryone
            #print(i)
            #print(t_fre)
            if(t_fre > t_maxfre):
                t_maxfre = t_fre
                t_frelo = i
            if(t_entry > t_maxent):
                t_maxent = t_entry
                t_loen = i
            i = i + 1
        #print (t_frelo,t_loen)
        return t_frelo,t_loen

    def find_sloentry(self, aa):
        tt_l = len(aa)
        j = 0
        self.check_se(aa)
        t_len = len(aa)
        i = 1
        t_maxfre = -1000
        t_frelo = -1
        t_maxent = -1000
        t_loen = -1
        while (i <= t_len):
            print (i)
            pre = aa[:i]
            if (i < t_len):
                last = aa[i:]
            else:
                last = ''
            print ('prestart')
            self.check_se(pre)
            t_freone, t_entryone = self.query_info(pre)
            # print(t_frelo)
            print(t_entryone)
            print('preend')
            # print('mm')
            self.check_se(last)
            t_frelast, t_enlast = self.query_info(last)
            t_fre = t_freone + t_frelast
            t_entry = t_entryone
            # print(i)
            # print(t_fre)
            if (t_fre > t_maxfre):
                t_maxfre = t_fre
                t_frelo = i
            if (t_entry > t_maxent):
                t_maxent = t_entry
                t_loen = i
            i = i + 1
        print (t_frelo,t_loen)
        return t_frelo, t_loen

    def vote_locas(self,sequence,L):
        t_len = len(sequence)
        i = L
        t_frelos = []
        t_entrylos = []
        while(i <= t_len):
            t_s = sequence[i-L:i]
            #self.check_se(t_s)
            t_frelo,t_entrylo = self.find_slo(t_s)
            #print(t_frelo)
            #sys.exit()
            if(t_frelo != -1):
                t_frelos.append(t_frelo + i - L)
            else:
                t_frelos.append(-1)
            if(t_entrylo != -1):
                t_entrylos.append(t_entrylo + i - L)
            else:
                t_entrylos.append(-1)
            i = i + 1
        j = t_len - L + 1
        while(j < t_len):
            t_s = sequence[j:t_len]
            t_frelo, t_entrylo = self.find_slo(t_s)
            if (t_frelo != -1):
                t_frelos.append(t_frelo + j)
            else:
                t_frelos.append(-1)
            if (t_entrylo != -1):
                t_entrylos.append(t_entrylo + j)
            else:
                t_entrylos.append(-1)
            j = j + 1

        return t_frelos,t_entrylos

    def vote_Relocations(self,sequence,L):
        t_len = len(sequence)
        i = L
        t_frelos = []
        t_entrylos = []
        while(i <= t_len):
            t_s = sequence[i-L:i]
            t_frelo,t_entrylo = self.find_slo(t_s)
            if(t_frelo != -1):
                t_frelos.append(t_len - (t_frelo + i - L))
            else:
                t_frelos.append(-1)
            if(t_entrylo != -1):
                t_entrylos.append(t_len - (t_entrylo + i - L))
            else:
                t_entrylos.append(-1)
            i = i + 1
        j = t_len - L + 1
        while(j < t_len):
            t_s = sequence[j:t_len]
            t_frelo, t_entrylo = self.find_slo(t_s)
            if (t_frelo != -1):
                t_frelos.append(t_len - (t_frelo + j))
            else:
                t_frelos.append(-1)
            if (t_entrylo != -1):
                t_entrylos.append(t_len - (t_entrylo + j))
            else:
                t_entrylos.append(-1)
            j = j + 1

        return t_frelos,t_entrylos



    def get_conlos(self,messages,L):
        """

        :param messages:messages data
        :return:vote locations ascent reverse
        """
        t_fref = {}
        t_entryf = {}
        for message in messages:
            temp_fre,temp_entry = self.vote_locas(message,L)
            t_flen = len(temp_fre)
            i = 0
            while(i < t_flen):
                if(temp_fre[i] not in t_fref):
                    t_fref[temp_fre[i]] = 1
                else:
                    t_fref[temp_fre[i]] = t_fref[temp_fre[i]] + 1
                i = i + 1
            t_entrylen = len(temp_entry)
            i = 0
            while(i < t_entrylen):
                if(temp_entry[i] not in t_entryf):
                    t_entryf[temp_entry[i]] = 1
                else:
                    t_entryf[temp_entry[i]] = t_entryf[temp_entry[i]] + 1
                i = i + 1
        t_fref[1] = t_fref[1]*2

        self.conlosfre = t_fref
        self.conlosentry = t_entryf


    def get_Reconlos(self,messages,L):
        """

        :param messages:messages data
        :return:vote locations ascent reverse
        """
        t_fref = {}
        t_entryf = {}
        for message in messages:
            temp_fre,temp_entry = self.vote_locas(message,L)
            t_flen = len(temp_fre)
            i = 0
            while(i < t_flen):
                if(temp_fre[i] not in t_fref):
                    t_fref[temp_fre[i]] = 1
                else:
                    t_fref[temp_fre[i]] = t_fref[temp_fre[i]] + 1
                i = i + 1
            t_entrylen = len(temp_entry)
            i = 0
            while(i < t_entrylen):
                if(temp_entry[i] not in t_entryf):
                    t_entryf[temp_entry[i]] = 1
                else:
                    t_entryf[temp_entry[i]] = t_entryf[temp_entry[i]] + 1
                i = i + 1


        self.Reconlosfre = t_fref
        self.Reconlosentry = t_entryf


        #print (sorted(t_fref.items(),key = lambda d:d[1],reverse = True))
    def get_locationbycondition(self,times):
        t_fresplits = []
        t_entrysplits = []
        for key in self.conlosfre:
            if self.conlosfre[key] > times:

                t_fresplits.append(key)
        for key in self.conlosentry:
            if self.conlosentry[key] > times:
                t_entrysplits.append(key)
        return t_fresplits,t_entrysplits

    def getlocationbyneibor(self,times):
        t_fresplits = []
        t_entrysplits = []
        for key in self.conlosfre:
            prekey = key - 1
            nexkey = key + 1
            nownum = self.conlosfre[key]
            if prekey not in self.conlosfre:
                prenum  = 0
            else:
                prenum = self.conlosfre[prekey]
            if nexkey not in self.conlosfre:
                nextnum = 0
            else:
                nextnum = self.conlosfre[nexkey]

            if(prenum ==0):
                if nownum > times:
                    t_fresplits.append(key)
                continue
            elif((nownum > prenum) and (nownum - prenum)/prenum > 0.1):
                t_fresplits.append(key)
                continue
            if(nextnum == 0):
                if(nextnum > times):
                    t_fresplits.append(key)
                continue
            elif((nownum > nextnum) and (nownum - nextnum)/nextnum > 0.1):
                t_fresplits.append(key)
                continue
        for key in self.conlosentry:
            if self.conlosentry[key] > times:
                t_entrysplits.append(key)
        return t_fresplits, t_entrysplits

    def get_locationbylocal(self,entrys):
        print ('aaa')


    def get_Relocationbycon(self,times):
        t_reentrys = []
        for key in self.Reconlosentry:
            if(self.Reconlosentry[key] > times):
                t_reentrys.append(key)
        return t_reentrys

    def get_idoms(self,t_los):
        t_idoms = []
        t_len = len(t_los)
        i = 0
        while(i < t_len):
            if(i == 0):
                t_idoms.append((0,t_los[i]))
            else:
                t_idoms.append((t_los[i-1],t_los[i]))
            i = i + 1
        t_idoms.append((t_los[i - 1],-1))
        #self.idoms = t_idoms
        return t_idoms







    def get_key(self,idom):
        return idom[1]


    def get_frequentse(self,therehold):
        t_H = self.tree.depth()
        t_h = 1
        t_hnodes = []
        while(t_h <= t_H):
            t_nodes = self.get_h(t_h)
            print(t_h)
            for t_node in t_nodes:
                t_node = self.tree.get_node(t_node)
                if(t_node.data[2] > therehold):
                    t_hnodes.append((t_node.identifier + ' ' + str(t_node.data),t_node.data[2]))
            t_h = t_h + 1
        t_hnodes.sort(key = self.get_key,reverse=True)
        return t_hnodes