import os
import sys

class R_out:
    def __init__(self):
        print("out start")
        self.out = None
        self.f_out = None

    def set_path(self, path, filename):
        self.path = os.path.join(path,filename)
    
    def trans_out(self):
        self.f_out = open(self.path,"w")
        self.out = sys.stdout
        sys.stdout = self.f_out


    def back_out(self):
        sys.stdout = self.out
        self.f_out.close()


    def print_raw(self,path,filename,content):
        file_c = open(self.path,"w")
        temp_out = sys.stdout
        sys.stdout = file_c
        print(content)
        sys.stdout = temp_out
        file_c.close()

    def print_dic(self,dic):
        for key in dic:
            if type(dic[key][0]) != int:
                print(key,':',-1)
                continue
            print(key,dic[key])
        

