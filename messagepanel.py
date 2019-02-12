import wx
#coding:utf-8
from netzob.all import *
from datas import *
from binastr import *
from hexstr import *
from str import *

class MePanel(wx.Panel):
    def __init__(self,parent):
        wx.Panel.__init__(self,parent)
        Melabel=wx.StaticText(self,label="协议信息")
        self.Melist=wx.ListBox(self,-1,size=(400,330),style=wx.LB_SINGLE)
        Melabel2=wx.StaticText(self,label="协议数据")
        self.Metext1=wx.TextCtrl(self,-1,size=(400,330),style=wx.TE_MULTILINE)
        self.Melist.Bind(wx.EVT_LISTBOX,self.showDetail,self.Melist)
        #Mesizer=wx.FlexGridSizer(cols=1,hgap=6,vgap=6)
        #Mesizer.AddMany([Melabel,self.Melist,Melabel2,self.Metext1])
        self.fsizer=wx.BoxSizer(wx.VERTICAL)
        #self.fsizer.Add(Mesizer,0,wx.EXPAND|wx.ALL,border=10)
        self.fsizer.Add(Melabel,0,wx.EXPAND|wx.ALL)
        self.fsizer.Add(self.Melist,0,wx.EXPAND|wx.ALL,border=5)
        self.fsizer.Add(Melabel2,0,wx.EXPAND|wx.ALL)
        self.fsizer.Add(self.Metext1,0,wx.EXPAND|wx.ALL,border=10)
        self.SetSizer(self.fsizer)
        self.selection = 0

    
    def readMessage(self,filename,data):
        MessageList=[]
        filename=str(filename)
        self.Messagelist=data.readMessage(filename)
        for x in self.Messagelist:
            singleMe="src: "+x.source+" "+"destination "+x.destination
            MessageList.append(singleMe)
        for Message in MessageList:
            self.Melist.Append(Message)

    def showDetail(self,event):
        col=self.Melist.GetSelection()
        self.selection = col
        detail=repr(self.Messagelist[col].data)
        self.Metext1.SetValue(detail)

    def show_bit(self):
        convert=binastr(self.Messagelist[self.selection])
        self.Metext1.SetValue(convert.getbina())

    def show_hex(self):
        convert = hexstring(self.Messagelist[self.selection])
        self.Metext1.SetValue(convert.getstr())

    def show_str(self):
        convert = strshow(self.Messagelist[self.selection])
        self.Metext1.SetValue(convert.getstr())



    
