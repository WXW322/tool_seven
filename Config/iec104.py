import re

class iec104:
    def __init__(self):
        self.res = ["^104_[0-9]+_1_0_([0-9]+_){2}", "^104_([0-9]+_){2}(0_){3}"]

