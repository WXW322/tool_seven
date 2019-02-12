import wx
class pic_panel(wx.Frame):
    def __init__(self,parent=None,id=-1,pos=wx.DefaultPosition,title="aa"):
        image=wx.Image("/home/wxw/tools_four/pic_ture/second.png",wx.BITMAP_TYPE_PNG)
        temp1=image.ConvertToBitmap()
        #image.Rescale(temp1.GetWidth()/2,temp1.GetHeight())
        temp=image.ConvertToBitmap()
        size=temp.GetWidth(),temp.GetHeight()
        wx.Frame.__init__(self,parent,id,title,pos,size)
        wx.StaticBitmap(parent=self,bitmap=temp)

