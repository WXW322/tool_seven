import wx
class detail_panel(wx.Panel):
    def __init__(self,parent):
        wx.Panel.__init__(self,parent,style=wx.SUNKEN_BORDER)
        self.Metext=wx.TextCtrl(self,-1,style=wx.TE_MULTILINE)
        self.sizer=wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.Metext,1,wx.EXPAND)
        self.SetSizer(self.sizer)

    def showDetail(self,detail):
        self.Metext.SetValue(detail)

