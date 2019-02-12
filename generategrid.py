# -*- coding: utf-8 -*-
import wx
import wx.grid
import generictable
from netzob.all import *
class SimpleGrid(wx.grid.Grid):
    def __init__(self, parent,data):
        wx.grid.Grid.__init__(self, parent,-1,size=(600,300))
        tableBase = generictable.GenericTable(data)
        self.SetTable(tableBase)
        #self.Bind(wx.EVT_RIGHT_DOWN, self.showac)
        
    def showac(self,event):
        print "ppp"
        self.dlg=wx.SingleChoiceDialog(None,u"选择操作",u"操作列表",[u"聚合",u"对齐"])

class TestFrame(wx.Frame):
    def __init__(self,parent,data):
        print "enter"
        wx.Frame.__init__(self,parent,-1,size=(800,400))
        self.grid=SimpleGrid(self,data)
        gridWin = self.grid.GetGridWindow()
        gridWin.Bind(wx.EVT_RIGHT_DOWN, self.OnGrid1Motion) 


    def showac(self,event):
        print "ppp"
        self.dlg=wx.SingleChoiceDialog(None,u"选择操作",u"操作列表",[u"聚合",u"对齐"])
        
