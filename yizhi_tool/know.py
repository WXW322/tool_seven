#coding=utf-8
import wx
import time
from me_top import *
from me_meddle import *
from menu_one import *
from data import *
sys.path.append("/home/wxw/tools_five")
import mainlook 
class Myframe(wx.Frame):
    def __init__(self,flag=True):
        wx.Frame.__init__(self,None,size=(1000,800),title = 'IEC104 Parser')
        self.menu=importerMenu()
        self.SetMenuBar(self.menu.importbar)
        self.first=0
        self.flag=flag
        self.da=data();
        self.sp=wx.SplitterWindow(self)# 创建一个分割窗,parent是frame
        self.p1=wx.Panel(self.sp,style=wx.SUNKEN_BORDER)  #创建子面板p1
        #self.p1=top_panel()
        #self.p2=wx.Panel(self.sp,style=wx.SUNKEN_BORDER)  # 创建子面板p2
        self.p2=top_panel(self.sp)
        self.p1.Hide()  # 确保备用的子面板被隐藏
        self.p2.Hide()
        self.sp1 = wx.SplitterWindow(self.p1)  # 创建一个子分割窗，parent是p1
        self.box = wx.BoxSizer(wx.VERTICAL)#创建一个垂直布局
        self.box.Add(self.sp1, 1, wx.EXPAND)#将子分割窗布局延伸至整个p1空间
        self.p1.SetSizer(self.box)
        self.p2.SetBackgroundColour("TURQUOISE")
        #self.p1_1 = wx.Panel(self.sp1, style=wx.SUNKEN_BORDER)#在子分割窗self.sp1的基础上创建子画板p1_1
        #self.p1_2 = wx.Panel(self.sp1, style=wx.SUNKEN_BORDER)#在子分割窗self.sp1的基础上创建子画板p1_2
        self.p1_1=detail_panel(self.sp1)
        self.p1_2=detail_panel(self.sp1)
        self.p1_1.Hide()
        self.p1_2.Hide()
        self.p1_1.SetBackgroundColour("#CCCCCC")
        self.p1_2.SetBackgroundColour("white")
        self.sp.SplitHorizontally(self.p2, self.p1, 0)
        self.sp1.SplitHorizontally(self.p1_1, self.p1_2, 0)
        self.Bind(wx.EVT_ERASE_BACKGROUND, self.OnEraseBack)

    def init_event(self):
        self.Bind(wx.EVT_MENU,self.choice,self.menu.importmessage)
        self.Bind(wx.EVT_LISTBOX,self.selectsym,self.p2.Melist)
        self.Bind(wx.EVT_MENU,self.change_mode,self.menu.change)


    def choice(self,event):
        dlg=wx.FileDialog(self,"open the file",style=wx.OPEN)
        if dlg.ShowModal()==wx.ID_OK:
            filename=dlg.GetPath()
            self.da.read_file(filename)
            Messagelist=self.da.get_top()
            self.p2.readMessage(Messagelist)

    def selectsym(self,event):
        lo=self.p2.get_select()
        s_l=self.da.get_choice(lo)
        s_b=self.da.get_bchoice(lo)
        self.p1_1.showDetail(str(s_l))
        self.p1_2.showDetail(str(s_b))
    
    def change_mode(self,event):
        print "jinru"
        main_one=mainlook.Mainwindow()
        main_one.Show(True)
        self.Destroy()  
        print "chulai"     
    
        
        


    
    def OnEraseBack(self,event):
        if self.first<2 or self.flag:
            self.sp.SetSashPosition(0)
            self.sp1.SetSashPosition(0)
            self.first=self.first+1
        self.Refresh()

app = wx.PySimpleApp()
frame=Myframe()
frame.init_event()
frame.Show(True)
app.MainLoop()

