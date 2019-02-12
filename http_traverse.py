# -*- coding: utf-8 -*-
from netzob.all import *
from generategrid import *


if __name__ == '__main__':
    messages = PCAPImporter.readFile("http_third.pcap").values()
    symbol = Symbol(messages=messages)
    Format.splitDelimiter(symbol, ASCII("\r\n"))
    data=symbol.getCells()
    f_r=[]
    for r in data:
        f_r1=[]
        for c in r:
            f_r1.append(c)
        f_r.append(f_r1)
    app = wx.PySimpleApp()
    frame = TestFrame(None,f_r)
    frame.Show(True)
    app.MainLoop()  

