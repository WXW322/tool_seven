from Mtree import *
from Node import *

def test_Mtree():
    t_ids = []
    t_ids[0] = Node("a",[0,2,3,5,7])
    t_ids[1] = Node("b",[0,2,3,5,9])
    t_ids[2] = Node("c",[0,2,3,5,12])
    t_ids[3] = Node("d",[1,3,5,7,10])
    t_ids[3] = Node("e",[1,3,5,7])
    t_ids[4] = Node("f",[1,3,5,7,12])

    mtr = Mtree("sss",t_ids,3,0,0)
    mtr.get_tree()
    mtr.print_exptree()



























