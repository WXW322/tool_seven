

class prepare(object):


    def __init__(self,var1,var2):
        self.var1=var1
        self.var2=var2
        self.length1=len(var1)
        self.length2=len(var2)
        self.lists=[([0]*self.length1) for i in range(self.length2)]
        self.change=[([0]*self.length1) for i in range(self.length2)]
        self.num=[([0]*self.length1) for i in range(self.length2)]

    def get_lists(self):
        for i in range(self.length2-1):
            for j in range(self.length1-1):
                #if(self.var2[i]==self.var1[j] and self.var2[i+1]==self.var1[j+1]):
                if (self.var2[i] == self.var1[j]):
                    self.lists[i][j]=1
                    #self.lists[i+1][j+1]=1


    def get_data(self):
        global t_is
        global t_lo
        t_is=0
        t_lo=0
        for i in range(self.length1):
            if(self.lists[0][i]==1):
                t_lo=1
                if(t_lo==1):
                    self.num[0][i]=1
                if(t_is==0):
                    self.change[0][i]=1
                    t_is=1
            else:
                if(t_lo==1):
                    self.num[0][i]=1
        t_is=0
        t_lo=0
        for i in range(self.length2):
            if(self.lists[i][0]):
                t_lo=1
                if(t_lo==1):
                    self.num[i][0]=1
                if(t_is==0):
                    self.change[i][0]=1
                    t_is=1
            else:
                if(t_lo==1):
                    self.num[i][0]=1
        for i in range(1,self.length2):
            for j in range(1,self.length1):
                if(self.lists[i][j]==1):
                     t_max=max(self.num[i-1][j],self.num[i][j-1])
                     if(t_max<1+self.num[i-1][j-1]):
                         self.num[i][j]=self.num[i-1][j-1]+1
                         self.change[i][j]=1
                     else:
                         self.num[i][j]=t_max
                else:
                     self.num[i][j]=max(self.num[i-1][j],self.num[i][j-1])
