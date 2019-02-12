from netzob.all import *
from treelib import *
import sys
sys.path.append('../deal_data')
import session_deal
import words_deal
#caculate the frequent sessions
class fre_tree:
    def __init__(self):
        self.trees = None
        self.modes = []
        self.idoms= []
        self.singles = []
        self.Ntrees = None
        self.final_sessions = None

    def get_right(self,nods,dep):
        """
        :param nods:condidate nodes
        :param dep: the depth of tree
        :return: i th depth of node
        """
        pn = []
        for nod in nods:
            if int(nod.identifier[1]) == dep:
                pn.append(nod.identifier)
        return pn
    def creat_session(self,depth):
        tt = Tree()
        tt.create_node(tag = 'n00', identifier = 'n00' ,data = 0)
        i = 1
        while(i <= depth):
            j = 1
            while( j <= 4):
                t_name = 'n' + str(i) + str(j)
                t_parents = self.get_right(tt.all_nodes(),i-1)
                m = 0
                for t_pa in t_parents:
                    tt.create_node(tag = t_name + str(m),identifier = t_name + str(m),data = 0,parent = t_pa)
                    m = m + 1
                j = j + 1
            i = i + 1
        self.trees = tt
    def update_num(self,t_series):
        """
        update the num of trees
        :param t_series: session info
        :return: updated trees
        """
        t_len = len(t_series)
        i = 0
        t_ctree = self.trees.subtree('n00')
        while(i < t_len):
            t_data = t_series[i]
            t_id = 'n' + str(i + 1) + str(t_data)
            t_condidates = t_ctree.children(t_ctree.root)
            for con in t_condidates:
                if(con.tag[0:3] == t_id):
                    self.trees[con.tag].data = self.trees[con.tag].data + 1
                    t_ctree = t_ctree.subtree(con.tag)
                    break
            i = i + 1

    def find_fre(self,rate,s_leng,t_len):
        """
        find fre patterns
        :param rate: therehold
        :param s_leng:total length session info
        :param t_len: select length
        :return: fre sessions info
        """
        while(t_len >= 1):
            t_bound = (s_leng / t_len) * rate
            t_nodes = self.get_right(self.trees.all_nodes(),t_len)
            for t_n in t_nodes:
                if (self.trees.get_node(t_n).data < t_bound):
                    t_lo = 0
                    for t_con in self.trees.children(t_n):
                        if t_con.tag == 'right':
                            t_lo = 1
                            break
                    if(t_lo == 0):
                        self.trees.remove_node(t_n)
                    else:
                        self.trees.get_node(t_n).tag = 'right'
                else:
                    self.trees.get_node(t_n).tag = 'right'
            t_len = t_len - 1
    def depth_traverse(self,identy,t_s):
        """
        find fre patterns
        :param identy: parent node
        :param t_s: parent series
        :return: fre series
        """
        t_node = self.trees.get_node(identy)
        if(t_node.is_leaf()):
            t_s = t_s + t_node.identifier[2]
            self.modes.append(t_s)
        else:
            t_lags = self.trees.children(identy)
            t_s = t_s + t_node.identifier[2]
            for tg in t_lags:
                self.depth_traverse(tg.identifier,t_s)



    def get_sessionmode(self):
        """
        get fre session info
        :return:
        """
        temp_nodes = self.trees.children('n00')
        for t_no in temp_nodes:
            self.depth_traverse(t_no.identifier,'')

    def get_idom(self):
        """
        delete session cylic
        :return:
        """

        for t_mode in self.modes:
            t_len = len(t_mode)
            while(t_len > 2 and t_len % 2 == 0):
                t_len = int(t_len / 2)
                if (t_mode[0:t_len] != t_mode[t_len:]):
                    break;
            self.idoms.append(t_mode[0:t_len])

    def is_same(self,l_one,l_two):
        """
        judge two pattern is same?
        :param l_one: pattern one
        :param l_two: pattern two
        :return: result
        """
        start = l_one[0]
        loc = l_two.index(start)
        while(loc != -1):
            pre = l_two[0:loc]
            last = l_two[loc:]
            t_temp = last + pre
            t_len = len(l_one)
            t_is = 0
            i = 0
            while(i < t_len):
                if(l_one[i] != t_temp[i]):
                    t_is = 1
                    break
                i = i + 1
            if(t_is == 0):
                break
            if(loc > t_len - 2):
                break
            print (loc)
            loc = l_two[loc + 1:].index(start)
            sys.exit()
        if t_is == 1:
            return 0
        elif ((int(l_one[0]) == 1 or int(l_one[0]) == 3) and (int(l_two[0]) != 1 and int(l_two[0]) != 3)):
            return 1
        elif((int(l_one[0]) != 1 and int(l_one[0]) != 3) and (int(l_two[0]) == 1 or int(l_two[0]) == 3)):
            return 2
        else:

            t_length = len(l_one)
            j = 0
            while(j < t_length):
                if(l_one[j] < l_two[j]):
                    return 1
                elif(l_one[j] > l_two[j]):
                    return 2
                j = j + 1
        return 1



    def out_same(self):
        """
        delete all same patterns
        :return: all unique frequent patterns
        """
        t_len = len(self.idoms)
        i = 0
        t_los = []
        while(i < t_len - 1):
            if i in t_los:
                i = i + 1
                continue
           #    self.singles.append(self.idoms[i])
            t_los.append(i)
            j = i + 1
            while(j < t_len):
                if(len(self.idoms[0]) != len(self.idoms[j])):
                    continue
                else:
                    result = self.is_same(self.idoms[i],self.idoms[j])
                    if(result == 1):
                        self.singles.append(self.idoms[i])
                    elif(result == 2):
                        self.singles.append(self.idoms[j])
                    
                    if result:
                        t_los.append(j)
                j = j + 1
            i = i + 1

    def regettree(self):
        """
        get tree according to itoms
        :return:
        """
        tt = Tree()
        tt.create_node(tag='n00', identifier='n00', data=0)
        root = tt.get_node('n00')
        for sig in self.singles:
            t_len = len(sig)
            i = 0
            while(i < t_len):
                t_con = tt.children(root.identifier)
                t_num = sig[i]
                t_is = 0
                for con in t_con:
                    if (int(con.identifier[2]) == t_num):
                        t_is = 1
                        root = tt.get_node(con)
                        break;
                if(t_is == 0):
                    t_temp = 'n' + str(i + 1) + str(t_num) +str(len(tt.all_nodes()))
                    tt.create_node(t_temp,t_temp,parent = root.identifier)
                    root = tt.get_node(t_temp)

                i = i + 1
        self.Ntrees = tt


    def get_itoms(self,lo,root):
        t_is = 0
        for t_con in self.Ntrees.children(root):
            if (int(t_con.identifier[2]) == lo):
                return t_con.identifier
        return None


    def split_session(self,t_session):
        """
        split session according to fre sessions
        args:t_session the total_session to be split
        :return: t_rr:the sessions be split
        """
        pre = 0
        t_tolen = len(t_session)
        t_root = self.Ntrees.get_node('n00').identifier
        t_rr = []
        while(pre < t_tolen):
            t_root = self.Ntrees.get_node('n00').identifier
            t_temp = t_session[pre][0]
            middle = pre
            while(middle < t_tolen and self.get_itoms(t_temp,t_root) == None):
                middle = middle + 1
                if (middle >= t_tolen):
                    break
                t_temp = t_session[middle][0]
            if(middle > pre):
                t_rr.append(t_session[pre:middle])
            end = middle
            if(end >= t_tolen):
                break
            t_temp = t_session[end][0]
            while (end < t_tolen and self.get_itoms(t_temp, t_root) != None):
                t_root = self.get_itoms(t_temp, t_root)
                end =  end + 1
                if(end >= t_tolen):
                    break
                t_temp = t_session[end][0]
            if(end > middle):
                t_rr.append(t_session[middle:end])
            pre = end
        self.final_sessions = t_rr
    def split_single(self,sess_len, path ,threhold):
        """

        :param sess_len:session idom length
        :param path:messages path
        :param threhold:frequent therehold
        :return:splited messages
        """
        self.creat_session(sess_len)
        ss = session_deal.session_deal(path)
        t_ss = []
        cn = ss.get_changes()
        for co in cn:
            t_ss.append(co[0])
        i = sess_len
        while (i < len(t_ss) - 1):
            self.update_num(t_ss[i - sess_len:i])
            i = i + 1
        self.find_fre(threhold, len(t_ss), sess_len)
        self.get_sessionmode()
        self.get_idom()
        self.out_same()
        self.regettree()
        self.Ntrees.show()
        self.split_session(cn)





























ff = fre_tree()
ff.split_single(4,'/home/wxw/data/iec104/10.55.41.210.55.218.1.pcap',0.5)
#for sess in ff.final_sessions:
#    for se in sess:
#        print (se[0])
#    print ('line')
MessageList = PCAPImporter.readFile('/home/wxw/data/iec104/10.55.37.13110.55.218.2.pcap').values()
series_find = words_deal.message_dealer(MessageList)
series_find.find_const()
series_find.find_seriesid(ff.final_sessions)

"""
ff = fre_tree()
ff.creat_session(4)
ss = session_deal.session_deal('/home/wxw/data/iec104/10.55.37.13110.55.218.2.pcap')
t_ss = []
cn = ss.get_changes()
for co in cn:
    t_ss.append(co[0])

#s_l = [1, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3]
s_l = t_ss
i = 4
while(i < len(s_l) - 1):
    ff.update_num(s_l[i-4:i])
    i = i + 1
ff.find_fre(0.5,len(s_l),4)
ff.get_sessionmode()

ff.get_idom()
ff.out_same()
ff.regettree()
ff.Ntrees.show()
ff.split_session(cn)
"""
















