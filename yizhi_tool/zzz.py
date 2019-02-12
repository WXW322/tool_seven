import wx
class Myframe(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self,None,size=(1000,500))
        self.sizer=wx.BoxSizer(wx.HORIZONTAL)
        self.panel_one=wx.Panel(self,size=(200,500))
        self.panel_one.SetBackgroundColour("blue")
        self.panel_two=wx.Panel(self,size=(500,500))
        self.panel_two.SetBackgroundColour("pink")
        self.panel_three=wx.Panel(self,size=(200,500))
        self.panel_three.SetBackgroundColour("white")
        self.sizer.Add(self.panel_one,0,wx.ALIGN_LEFT|wx.EXPAND,20)
        self.sizer.Add(self.panel_two,2,wx.EXPAND,20)
        self.sizer.Add(self.panel_three,0,wx.ALIGN_RIGHT|wx.EXPAND,20)
        self.SetSizer(self.sizer)

app = wx.PySimpleApp()
frame=Myframe()
frame.Show(True)
app.MainLoop()        
