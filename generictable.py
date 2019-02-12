import wx
import wx.grid

class GenericTable(wx.grid.PyGridTableBase):

    def __init__(self, data):
        wx.grid.PyGridTableBase.__init__(self)
        self.data=data
        col_len=len(self.data[0])
        row_len=len(self.data)
        self.colLabels=[]
        self.rowLabels=[]
        for i in range(0,col_len):
            temp_str="Field"+str(i)
            self.colLabels.append(temp_str)
        for i in range(0,row_len):
            temp_str="row"+str(i)
            self.rowLabels.append(temp_str)

    def GetNumberRows(self):
        return len(self.data)

    def GetNumberCols(self):
        return len(self.data[0])

    def GetColLabelValue(self,col):
        if self.colLabels:
            return self.colLabels[col]

    def GetRowLabelValue(self,row):
        if self.rowLabels:
            return self.rowLabels[row]

    def IsEmptyCell(self,row,col):
            return False

    def GetValue(self,row,col):
            return self.data[row][col]

    def SetValue(self,row,col,value):
            self.data[row][col]=value

