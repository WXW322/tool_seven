class strshow:
    def __init__(self,messages):
        self.messages=messages

    def getstr(self):
        strtotal=""
        strtotal+=repr(self.messages.data)
        return strtotal
