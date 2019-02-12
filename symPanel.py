import wx
#coding:utf-8
from netzob.all import *
from datas import *
class SymbolsPanel(wx.Panel):
    def __init__(self,parent):
        wx.Panel.__init__(self,parent)
        self.symlabel=wx.StaticText(self,label="符号信息",size=(200,20))
        self.symlist=wx.ListBox(self,-1,size=(200,400),style=wx.LB_SINGLE)
        self.sizer=wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.symlabel,0,wx.EXPAND)
        self.sizer.Add(self.symlist,2,wx.EXPAND|wx.ALL,border=5)
        self.SetSizer(self.sizer)


    def readSymbols(self,symbols):
        for x in symbols:
            self.symlist.Append(x)

    def getSelect(self):
        col=self.symlist.GetSelection()
        return col
    
        
