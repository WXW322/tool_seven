class node(object):

    def __init__(self,contain,start,end,proper):
        self.contain=contain
        self.start=start
        self.end=end
        self.proper=proper

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def get_pro(self):
        return self.proper

    def get_contain(self):
        return self.contain

