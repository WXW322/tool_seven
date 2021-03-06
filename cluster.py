from scapy.all import *
import operator
from netzob.all import *
from t_node import *

from classify import *


class cluster(object):
    def __init__(self, str_list1, count):
        self.list1 = str_list1
        self.num = count
        i = 0
        self.clus = []
        self.cores = []
        while (i < self.num):
            temp = []
            self.clus.append(temp)
            i = i + 1
        i = 0
        while (i < self.num):
            self.cores.append(str_list1[i])
            i = i + 1
        self.file_object = open('thefile_six.txt', 'w+')
        self.biaozhi = 0
        # self.coreA=self.list1[0]
        # self.coreB=self.list1[1]

    def get_dis(self, S1, S2):
        pe = prepare(S1, S2)
        pe.get_lists()

        pe.get_data()
        fy = factor(S1, S2, pe.change)
        fy.spart_1()
        return fy.get_distance_one()

    def choice_core(self):
        i = 0
        while (i < self.num):
            self.clus[i].sort(key=operator.attrgetter('distance'))
            i = i + 1
        i = 0
        while (i < self.num):
            print("bb ", i, "cc ", len(self.clus[i]))
            self.cores[i] = self.clus[i][len(self.clus[i]) / 2]
            i = i + 1
            # self.clu_one.sort(key=operator.attrgetter('distance'))
            # self.clu_two.sort(key=operator.attrgetter('distance'))
            # self.coreA=self.clu_one[len(self.clu_one)/2]
            # self.coreB=self.clu_two[len(self.clu_two)/2]

    def update(self):
        i = 0
        while (i < self.num):
            del self.clus[i][:]
            i = i + 1

        # del self.clu_one[:]
        # del self.clu_two[:]
        print self.num
        for r in self.list1:
            # d_one=self.get_dis(r.contain,self.coreA.contain)
            # d_two=self.get_dis(r.contain,self.coreB.contain)
            d_d = -100
            lo = -1
            i = 0
            while (i < self.num):
                d_t = self.get_dis(r.contain, self.cores[i].contain)
                # self.file_object.write(repr(r.contain))
                # self.file_object.write("\r\n")
                # self.file_object.write(repr(self.cores[i].contain))
                # self.file_object.write(repr(repr(d_t)))
                # self.file_object.write("\r\n")
                # self.file_object.write("\r\n")
                # self.file_object.flush()
                # print("b ",repr(r.contain),"\r\n ",repr(self.cores[i].contain),"\r\n",repr(d_t))
                if (d_t > d_d):
                    d_d = d_t
                    lo = i
                i = i + 1
            t_one = t_node(d_d, r.contain)
            # print("t ",i)
            self.clus[lo].append(t_one)

    def show_core(self):
        print "cores"
        self.file_object.write("cores\r\n")
        for r in self.cores:
            self.file_object.write(repr(r.contain))
            print repr(r.contain)

    def show_clus(self):
        print "cls:"
        self.file_object.write("cls\r\n")
        for l in self.clus:
            print "clus:"
            self.file_object.write("clus:\r\n")
            for m in l:
                print repr(m.contain)
                self.file_object.write(repr(m.contain))
                self.file_object.write("\r\n")

    def get_min(self):
        t_min = -100
        t_lo = -1
        i = 0
        while (i < self.num):
            t_temp = self.clus_dis[i]
            t_t_d = t_temp[1]
            if (t_t_d > t_min):
                t_min = t_t_d
                t_lo = i
            i = i + 1
        return self.clus_dis[t_lo]

    def get_max(self):
        t_max = 0
        t_lo = -1
        i = 0
        while (i < self.num):
            t_temp = self.core_dis[i]
            if (t_temp[2] > t_max):
                t_max = t_temp[2]
                t_lo = i
            i = i + 1
        return self.core_dis[t_lo]

    def change_cores(self):
        i = 0
        self.core_dis = []
        while (i < self.num - 1):
            j = i + 1
            while (j < self.num):
                t_d = self.get_dis(self.cores[i].contain, self.cores[j].contain)
                t_t = (i, j, t_d)
                self.core_dis.append(t_t)
                j = j + 1
            i = i + 1
        i = 0
        self.clus_dis = []
        while (i < self.num):
            t_d = self.clus[i][len(self.clus[i]) / 2 - 1].distance - self.clus[i][0].distance
            t_t = (i, t_d)
            self.clus_dis.append(t_t)
            i = i + 1
        t_pre = self.get_min()
        t_last = self.get_max()
        print t_pre
        print t_last
        self.cores[t_last[1]] = self.clus[t_pre[0]][0]

    def update_bytime(self, time):
        print "enter"
        for i in range(time):
            print("time ",i)
            # if(i==31):
            # self.show_core()
            # self.biaozhi=1
            self.update()
            # self.show_clus()
            print('middle')
            self.choice_core()
            if (i == time / 2):
                self.change_cores()
            # self.show_clus()
            print " zanting"
        self.file_object.close()