from netzob.all import *
from treelib import *
import numpy as np
import sys



data = np.array([0.4,0.2,0.1,0.1,0.2])
mean = np.mean(data)
std = np.std(data,ddof = 1)
data = (data-mean)/std
print (data)