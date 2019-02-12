import wx
#coding:utf-8
from netzob.all import *
from datas import *
from binastr import *
from hexstr import *
from str import *

class TotalPanel(wx.Panel):
    def __init__(self,parent):
        wx.Panel.__init__(self,parent)
        Melabel=wx.StaticText(self,label="协议信息")
        self.Metext1=wx.TextCtrl(self,-1,style=wx.TE_MULTILINE)
        #Mesizer=wx.FlexGridSizer(cols=2,hgap=6,vgap=6)
        #Mesizer.AddMany([Melabel,self.Metext1])
        Mesizer=wx.BoxSizer(wx.VERTICAL)
        Mesizer.Add(Melabel,0,wx.EXPAND)
        Mesizer.Add(self.Metext1,1,wx.EXPAND|wx.ALL,border=10)
        self.SetSizer(Mesizer)
    
    def readMessage(self,messages,biaozhi):
        str=""
        if(len(messages)==0):
             dlg=wx.MessageDialog(None, u"请首先引入文件", u"警告", wx.OK)
        else:
             if(biaozhi==1):
                 convert=binastr(messages)
                 str=convert.getbina()
             elif(biaozhi==2):
                 convert=hexstring(messages)
                 str=convert.getstr()
             else:
                 convert=strshow(messages)
                 str=convert.getstr()
        self.Metext1.SetValue(str)

    def set_message(self,value):
        self.Metext1.SetValue(value)
