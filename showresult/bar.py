import numpy as np
import matplotlib.pyplot as plt
import os

def draw_pic(a,b,path):
    plt.rcParams.update({'font.size': 14})
    plt.ylim((0.0,1.09))
    total_width, n = 0.6, 2
    width = total_width / n
    x = np.array([1,3,5])
    x = x - (total_width - width) / 2
    names = ['corretness','precision','combine']
    plt.bar(x, a, width=width, label='netzob',facecolor = '#009E73')
    plt.bar(x + width, b, width=width, label='IPART',facecolor = '#9400D3')
    plt.xticks(x + width/2,names)
    plt.legend(loc = 0,bbox_to_anchor = (0.72,0.8))
    #plt.legend()
#plt.show()
    fpath = os.path.join(path,'six.jpg')
    plt.savefig(fpath)
    plt.close('all')

a = np.array([0.8,0.75,0.60])
b = np.array([1.0,1.0,1.0])
draw_pic(a,b,'/home/wxw/paper/researchresult/classify/modbus/pic')
#b = np.array([0.6667,0.3333,0.2222])
#a = np.array([0.7241,0.3333,0.2414])
#draw_pic(a,b,'/home/wxw/paper/researchresult/classify/iec104/pic')
a = np.array([0.5,0.5,0.25])
b = np.array([1.0,1.0,1.0])
draw_pic(a,b,'/home/wxw/paper/researchresult/classify/cip/pic')
