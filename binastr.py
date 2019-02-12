from netzob.all import *
class binastr:
    def __init__(self,messages):
        self.messages=messages

    def getbina(self):
        metotal=""
        stemp=Raw(self.messages.data)
        ss=stemp.value.to01()
        metotal+=ss
        return metotal
