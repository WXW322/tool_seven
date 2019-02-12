import matplotlib.pyplot as plt
import os
import sys
import matplotlib
import numpy as np

def plot_linefigure(file_to,x_lable,y_lable,datas_X,datas_Y,colors,labels,makers):
    
    plt.rcParams.update({'font.size': 13})
    plt.xlabel(x_lable)
    plt.ylabel(y_lable)
    t_len = len(datas_X)
    i = 0
#plt.rcParams.update({'font.size': 13})
    while(i < t_len):
        show_variable('y'+str(i),datas_Y[i],'w+')
        plt.plot(datas_X[i],datas_Y[i],colors[i],label = labels[i],marker = makers[i],fillstyle='none')
        i = i + 1
    #matplotlib.rc('xtick', labelsize=22) 
    #matplotlib.rc('ytick', labelsize=22)
    #plt.rcParams.update({'font.size': 18})
    plt.xlim([1,4.1])
    plt.ylim([0,1.03])
    plt.xticks(np.arange(1,5,step=1),('1','2','3','4'))
    plt.yticks(np.arange(0,1.2,step=0.2),['0.0','0.2','0.4','0.6','0.8','1.0'])
    #print(ys)
    #print(ylabels)
    #matplotlib.rcParams.update({'font.size': 22})
    #plt.xticks([1,2,3,4],['1','2','3','4'])
    #plt.yticks([1,2,3,4,5],[0.2,0.4,0.6,0.8,1.0])
    plt.legend()
    path = os.path.join('/home/wxw/test',file_to)
    #path = os.path.join(file_to,'linemodbustwo.jpg')
    plt.savefig(path)
    plt.close('all')



def process_data(file_from,file_to,x_lable,y_lable):
    t_correct = {}
    t_preci = {}
    t_coms = {}
    for filename in os.listdir(file_from):
        t_file = os.path.join(file_from,filename)
        #print(t_file)
        t_filein = open(t_file,'r')
        t_line = t_filein.readline()
        #print(t_line)
        t_line = t_line[0:-1]
        t_temp = t_line.split(' ')
        t_id = int(t_temp[-4])
        t_cor = float(t_temp[-3])
        t_pre = float(t_temp[-2])
        t_com  = float(t_temp[-1])
        t_cor = round(t_cor,4)
        t_pre = round(t_pre,4)
        t_com  = round(t_com,4)
        t_correct[t_id] = t_cor
        t_preci[t_id] = t_pre
        t_coms[t_id] = t_com
    #show_variable('yy',t_correct,'a+')
    #show_variable('yy',t_preci,'a+')
    #show_variable('yy',t_coms,'w+')
    t_correct = sorted(t_correct.items(),key = lambda x:x[0])
    datas_X = []
    datas_Y = []
    x_temp = []
    y_temp = []
    colors = []
    labels = []
    makers = []
    for key in t_correct:
        x_temp.append(key[0])
        y_temp.append(key[1])
    datas_X.append(x_temp)
    datas_Y.append(y_temp)
    colors.append('r')
    labels.append('correct')
    makers.append('o')
    x_temp = []
    y_temp = []
    t_preci = sorted(t_preci.items(),key = lambda x:x[0])
    for key in t_preci:
        x_temp.append(key[0])
        y_temp.append(key[1])
    datas_X.append(x_temp)
    datas_Y.append(y_temp)
    colors.append('b')
    labels.append('precision')
    #show_variable('Y',datas_Y,'w+')
    t_coms = sorted(t_coms.items(),key = lambda x:x[0])
    x_temp = []
    y_temp = []
    for key in t_coms:
        x_temp.append(key[0])
        y_temp.append(key[1])
    datas_X.append(x_temp)
    datas_Y.append(y_temp)
    makers.append('+')
    #show_variable('X',datas_X,'w+')
    #show_variable('Y',datas_Y,'w+')
    colors.append('g')
    labels.append('combine')
    makers.append('s')
    plot_linefigure(file_to,x_lable,y_lable,datas_X,datas_Y,colors,labels,makers,fillstyle='none')    

def show_variable(file_to,val,type):
    tempout = sys.stdout
    file = open(file_to,type)
    sys.stdout = file
    print(val)
    sys.stdout = tempout

datas_X = [[1,2,3,4],[1,2,3,4],[1,2,3,4]]
datas_f1mod = [[0,0.5000,0.2500,0.2857],[0,0.4444,0.4444,0.4444],[0,0.6000,0.9231,0.9231]]
datas_Yf1iec = [[0,0.5714,0.5714,0.6667],[0,0.6667,0.4,0.5333],[0,0.8696,0.9090,0.7368]]
datas_Yf1cip = [[0,0.3077,0.1538,0.3750],[0,0.5,0.5,0.40],[0,0.4,0.6667,0.6667]]

datas_preYmod = [[0.0,1.0,0.5,1.0],[0.0,0.6667,0.6667,0.6667],[0.0,0.7500,0.8571,0.8571]]
datas_recallmod = [[0.0,0.3333,0.1667,0.1667],[0.0,0.3333,0.3333,0.3333],[0.0,0.5000,1.0000,1.0000]]
datas_preiec = [[0.0,1.0,1.0,1.0],[0.0,1.0,0.6,0.8],[0.0,0.7692,0.8333,0.7778]]
datas_recalliec = [[0.0,0.4,0.4,0.5],[0.0,0.5,0.3,0.4],[0.0,1.0,1.0,0.7]]
datas_precip = [[0.0,1.0,0.5,0.6],[0.0,0.6,0.4444,0.375],[0,0.6667,0.625,0.625]]
datas_recallcip = [[0.0,0.1818,0.0909,0.2727],[0.0,0.4286,0.5714,0.4286],[0.0,0.2857,0.7143,0.7143]]
datas_Ys = []

datas_Ys.append(datas_Yf1iec)
datas_Ys.append(datas_f1mod)
#datas_Ys.append(datas_Yf1iec)
datas_Ys.append(datas_Yf1cip)
datas_Ys.append(datas_preYmod)
datas_Ys.append(datas_recallmod)
datas_Ys.append(datas_preiec)
datas_Ys.append(datas_recalliec)
datas_Ys.append(datas_precip)
datas_Ys.append(datas_recallcip)
paths = ['f1iec.jpg','f1mod.jpg','f1_cip.jpg','premod.jpg','recallmod.jpg','preiec.jpg','recalliec.jpg','precip.jpg','recallcip.jpg']
x_lable = "tree-depth"
y_lable = ["F1-measure","precious","recall"]
colors = ['r','b','#1EFF1E']
labels = ['LDA','VE','RGVE']
markers = ["o","+","s"]
i = 0
#path = "test.jpg"
#plot_linefigure(path,x_lable,y_lable,datas_X,datas_Y,colors,labels,markers)

for path in paths:
    if(path.find("f1") != -1):
        plot_linefigure(path,x_lable,y_lable[0],datas_X,datas_Ys[i],colors,labels,markers)
    elif(path.find("pre") != -1):
        plot_linefigure(path,x_lable,y_lable[1],datas_X,datas_Ys[i],colors,labels,markers)
    else:
        plot_linefigure(path,x_lable,y_lable[2],datas_X,datas_Ys[i],colors,labels,markers)
    i = i + 1

"""
file_from = sys.argv[1]
file_to = sys.argv[2]
process_data(file_from,file_to,'threshold T',"rate")
"""

        

        





