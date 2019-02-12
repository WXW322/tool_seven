#coding=utf-8
import wx
from me_top_left import *
from me_meddle import *
from datas import *
class clus_panel(wx.Panel):
    def __init__(self,parent,siz):
        wx.Panel.__init__(self,parent,size=siz)
        self.width=siz.width
        self.height=siz.height
        self.up = self.height/3*2 #上面窗口高度
        self.left = self.width/ 4#嵌套窗口左窗口宽度
        self.sp=wx.SplitterWindow(self,size=(self.width,self.height))# 创建一个分割窗
        self.p1=wx.Panel(self.sp,style=wx.SUNKEN_BORDER)  #创建子面板
        self.p2=detail_panel(self.sp)
        self.box = wx.BoxSizer(wx.VERTICAL)
        self.sp1 = wx.SplitterWindow(self.p1)  # 创建一个子分割窗
        self.box.Add(self.sp1,1,wx.EXPAND)
        self.p1.SetSizer(self.box)
        self.p2.SetBackgroundColour("blue")
        self.p1_1=top_panel(self.sp1)
        self.p1_2=top_panel(self.sp1)
        self.p1_1.Hide()
        self.p1_2.Hide()
        self.p1_1.SetBackgroundColour("red")
        self.p1_2.SetBackgroundColour("yellow")
        self.p1.Hide()  # 确保备用的子面板被隐藏
        self.p2.Hide()
        self.sp1.SplitVertically(self.p1_1, self.p1_2, self.left)
        self.sp.SplitHorizontally(self.p1, self.p2, self.up)
        self.Bind(wx.EVT_SIZE,self.SizeOnchange)
    def SizeOnchange(self,evt):
        size = evt.Size
        self.sp.Size=size#这一句很重要
        self.sp.SetSashPosition(size.height/3*2)
        self.sp1.SetSashPosition(size.width/4 )
