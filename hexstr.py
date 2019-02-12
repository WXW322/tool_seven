class hexstring:
    def __init__(self,messages):
        self.messages=messages

    def getstr(self):
        ss=""
        s=repr(self.messages.data)
        s1=s.encode('hex')
        t=0;
        for i in s1:
            ss+=i
            t=t+1
            if(t==2):
                ss+=" "
                t=0
        return ss
