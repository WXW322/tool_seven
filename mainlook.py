#-*- coding: utf-8 -*-
import wx
from netzob.all import *
from messagepanel import *
from menu import *
from generategrid import *
from datas import *
from Totalpanel import *
from symPanel import *
from progress import *
from pic_py import *
from clus_panel import *

#主界面类

class Mainwindow(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self,None,-1,"protol infference",size=(1000,800))
        self.totalpanel=MePanel(self)
        self.menu=importMenu()
        self.syPanel=SymbolsPanel(self)
        self.SetMenuBar(self.menu.importbar)
        self.Bind(wx.EVT_MENU,self.choice,self.menu.importmessage)
        self.Bind(wx.EVT_MENU,self.update,self.menu.salign)
        self.Bind(wx.EVT_MENU,self.show11,self.menu.showways)
        self.Bind(wx.EVT_MENU,self.show22,self.menu.showways1)
        self.Bind(wx.EVT_MENU,self.show33,self.menu.showways2)
        self.Bind(wx.EVT_MENU,self.get_length,self.menu.lengthstatic)
        self.Bind(wx.EVT_MENU,self.get_pinfan,self.menu.pinfan)
        self.Bind(wx.EVT_MENU,self.splitde,self.menu.delit)
        #self.Bind(wx.EVT_MENU,self.show_state,self.menu.state_me)
        #self.Bind(wx.EVT_MENU,self.show_pic,self.menu.state_pic)
        self.Bind(wx.EVT_LISTBOX,self.selectsym,self.syPanel.symlist)
        self.Bind(wx.EVT_MENU,self.magical,self.menu.auto_do)
        self.Bind(wx.EVT_MENU,self.getnum,self.menu.autp_preinfo)
        self.Bind(wx.EVT_MENU,self.auto_two,self.menu.auto_done)
        self.datas=datas()
        self.totalsizer=wx.BoxSizer(wx.HORIZONTAL)
        self.sizerleft=wx.BoxSizer(wx.VERTICAL)
        self.sizer=wx.BoxSizer(wx.VERTICAL)
        self.sizerleft.Add(self.syPanel,1,wx.EXPAND)
        self.sizer.Add(self.totalpanel,1,wx.EXPAND)
        self.totalsizer.Add(self.sizerleft,0,wx.EXPAND|wx.ALL)
        self.totalsizer.Add(self.sizer,2,wx.EXPAND|wx.ALL)
        self.SetSizer(self.totalsizer)

    def get_length(self,event):
        self.datas.get_graphlength()

    def get_pinfan(self,event):
        result = self.datas.get_frequent(20,10)
        self.totalpanel.Metext1.SetValue(result)

        
    def choice(self,event):
        dlg=wx.FileDialog(self,"open the file",style=wx.OPEN)
        if dlg.ShowModal()==wx.ID_OK:
            filename=dlg.GetPath()
        self.totalpanel.readMessage(filename,self.datas)

    def update(self,event):
        self.sizer.Clear()
        symbol=self.datas.sealign();
        print "ccc"
        self.showsymbol(symbol)

    def show1(self,event):
        self.sizer.Clear()
        self.total=TotalPanel(self)
        self.sizer.Add(self.total,1,wx.EXPAND|wx.ALL)
        self.Layout()
        self.total.readMessage(self.datas.MessageList,1)

    def show11(self, event):
        self.totalpanel.show_bit()


    def show22(self,event):
        self.totalpanel.show_hex()
         
    def show2(self,event):
        self.sizer.Clear()
        self.total=TotalPanel(self)
        self.sizer.Add(self.total,1,wx.EXPAND|wx.ALL)
        self.Layout()
        self.total.readMessage(self.datas.MessageList,2)

    def show33(self, event):
        self.totalpanel.show_str()

    def show3(self,event):
        self.sizer.Clear()
        self.total=TotalPanel(self)
        self.sizer.Add(self.total,1,wx.EXPAND|wx.ALL)
        self.Layout()
        self.total.readMessage(self.datas.MessageList,3)

    def show_state(self,event):
        self.sizer.Clear()
        self.total=TotalPanel(self)
        self.sizer.Add(self.total,1,wx.EXPAND|wx.ALL)
        self.Layout()
        result=self.datas.get_state_mecine()
        self.total.set_message(result)

    def show_pic(self,event):
        f_show=pic_panel()
        f_show.Show()


    def splitde(self,event):
        print "kkkzz"
        dlg = wx.TextEntryDialog(self,u"请输入分隔符",u"分割")
        if dlg.ShowModal() == wx.ID_OK:
            response=dlg.GetValue()
        print "v "+response
        subre=response[0:1]
        leixing=0
        if(subre[0]==r"\x"):
            leixing=1
        else:
            leixing=0
        tom=Job()
        tom.start()
        symbol=self.datas.splitdilimeter(response,leixing)
        tom.stop()
        print "sssss"
        self.showsymbol(symbol)


    def showsymbol(self,symbol):
         self.sizer.Clear()
         if(symbol is None):
             print "lklklkl"
             dlg=wx.MessageDialog(self, u"请先引入文件", u"警告", wx.OK)
         else:
             print "hjhjjh"
             data=symbol.getCells()
             f_r=[]
             for r in data:
                f_r1=[]
                for c in r:
                   f_r1.append(repr(c))
                f_r.append(f_r1)
             #self.symbolPanel=TestFrame(None,f_r)
             self.grid=SimpleGrid(self,f_r)
             #self.gridWin = self.grid.GetGridWindow()
             #print "aaa"
             #self.gridWin.Bind(wx.EVT_RIGHT_DOWN, self.showac)
             #print "bbb"
             self.sizer.Add(self.grid,1,wx.EXPAND)
             self.Bind(wx.grid.EVT_GRID_LABEL_RIGHT_CLICK,self.showac,self.grid)
             self.Layout() 

    def showac(self,event):
         self.dlg2=wx.SingleChoiceDialog(self,u"选择操作",u"操作列表",[u"聚合",u"对齐",u"删除"])
         if self.dlg2.ShowModal() == wx.ID_OK:
            lo=self.dlg2.GetSelection()
            print lo
            if(lo==2):
               t_l=self.grid.GetSelectedRows()
               t_r=t_l[0]
               print t_r
               tom=Job()
               tom.start()
               self.datas.remove_col(t_r)
               tom.stop()
            elif(lo==0):
               t_l=self.grid.GetSelectedCols()
               t_r=t_l[0]
               tom=Job()
               tom.start()
               self.datas.cluster(t_r)
               tom.stop()
               t_xianshi=self.datas.get_symbolsl()
               self.syPanel.readSymbols(t_xianshi)
            else:
               t_l=self.grid.GetSelectedCols()
               t_r=t_l[0]
               tom=Job()
               tom.start()
               self.datas.do_align(t_r)
               tom.stop()
               print t_r
         sym=self.datas.get_symbol()
         self.showsymbol(sym)
         self.Layout()

    def selectsym(self,event):
         lo=self.syPanel.getSelect()
         self.datas.set_symbol(lo)
         sym=self.datas.get_symbol();
         self.showsymbol(sym)

    def magical(self,event):
        test = wx.TextEntryDialog(None, "请输入类别个数", '类别', '个数')
        count = 0
        if test.ShowModal() == wx.ID_OK:
            apples = test.GetValue()
            count = int(apples)
        self.sizer.Clear()
        self.cls=clus_panel(self,self.Size)
        #self.data=datas()
        #self.data.readMessage("final_second.pcap")
        self.datas.do_classify(10,count)
        self.cls.p1_1.readMessage(self.datas.get_top_left())
        self.Bind(wx.EVT_LISTBOX,self.selecter,self.cls.p1_1.Melist)

    def auto_two(self,event):
        self.sizer.Clear()
        self.cls=clus_panel(self,self.Size)
        #self.data=datas()
        #self.data.readMessage("final_second.pcap")
        self.datas.classify_bycode()
        self.cls.p1_1.readMessage(self.datas.get_t_L())
        self.Bind(wx.EVT_LISTBOX,self.selecter_one,self.cls.p1_1.Melist)

    def selecter(self,event):
        col=self.cls.p1_1.get_select()
        self.cls.p1_2.readMessage(self.datas.get_top_right(col))
        self.cls.p2.showDetail(self.datas.get_down(col))

    def selecter_one(self,event):
        col=self.cls.p1_1.get_select()
        self.cls.p1_2.readMessage(self.datas.get_t_R(col))
        self.cls.p2.showDetail(self.datas.get_down_one(col))

    def getnum(self,event):
        test = wx.TextEntryDialog(None, "请输入功能码location", '功能码', '位置')
        if test.ShowModal() == wx.ID_OK:
            apples = test.GetValue()
            self.datas.key_lo = int(apples)



if __name__=='__main__':
    app=wx.PySimpleApp()
    frame=Mainwindow()
    frame.Show()
    app.MainLoop()        


        
        
        
