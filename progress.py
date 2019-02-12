import threading
import time
import wx

class Job(threading.Thread):
    def __init__(self,*args,**kwargs):
        super(Job,self).__init__(*args,**kwargs)
        self._running=threading.Event()
        self._running.set()

    def run(self):
        progressMax = 100
        dialog = wx.ProgressDialog("A progress box","Time remaining",progressMax,style=wx.PD_CAN_ABORT|wx.PD_ELAPSED_TIME|wx.PD_REMAINING_TIME)
        count = 0
        while self._running.isSet():
            count = (count+1)%progressMax
            time.sleep(1)
            dialog.Update(count)
            #print "aaa"
        dialog.Destroy()

    def stop(self):
        self._running.clear()

