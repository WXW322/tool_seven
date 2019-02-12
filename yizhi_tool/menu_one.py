#coding:utf-8
import wx
class importerMenu:
    def __init__(self):
        self.importbar=wx.MenuBar()
        self.alignbar=wx.Menu()
        self.importmenu=wx.Menu()
        self.showmenu=wx.Menu()
        self.delitmenu=wx.Menu()
        self.changemenu=wx.Menu()
        self.importmessage=self.importmenu.Append(-1,u"从文件中读取")
        self.salign=self.alignbar.Append(-1,u"模式抽取")
        self.showways=self.showmenu.Append(-1,u"二进制")
        self.showways1=self.showmenu.Append(-1,u"16进制")
        self.showways2=self.showmenu.Append(-1,u"字符串")
        self.delit=self.delitmenu.Append(-1,u"分割")
        self.change=self.changemenu.Append(-1,u"未知协议模式")
        self.importbar=wx.MenuBar()
        self.importbar.Append(self.importmenu,u"文件")
        self.importbar.Append(self.alignbar,u"对齐")
        self.importbar.Append(self.showmenu,u"显示方式")
        self.importbar.Append(self.delitmenu,u"分割")
        self.importbar.Append(self.changemenu,u"模式转换")
        
        
        
