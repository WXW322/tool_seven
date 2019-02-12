from pydotplus import *
from netzob.all import *

class tree_graph:
    def __init__(self,graph_type,datas):
       
        """
        function: init_class
        graph_type: graph_type | tree or graph
        datas: graph datas
        """
        self.colors = {}
        self.colors["C"] = "grey"
        self.colors["S"] = "yellow"
        self.colors["L"] = "blue"
        self.colors["F"] = "red"
        self.colors["O"] = "green"
        self.colors["D"] = "pink"
        print("aaa")

    def tree2graph(self):
        """
        function: converse tree to graph
        tree: a tree like datas
        graph: a set of nodes and edges
        """
        print("BBB")

    def graph2fig(self,graph_datas,out_dir):
        """
        function: output fig to out_dir
        graph_datas: a set of nodes and edges
        out: a png file
        """
        t_nodes = graph_datas['nodes']
        t_edges = graph_datas['edges']
        t_graph = graphviz.Dot(graph_type="graph",rankdir="LR")
        for node in t_nodes:
            t_graph.add_node(node)
        for edge in t_edges:
            t_graph.add_edge(edge)
        #graph = graphviz.graph_from_dot_data(t_graph.getvalue())
        t_graph.write_png("examplefour.png")

    def graph_build(self,nodes,edges):
        Nodes = []
        Edges = []
        for node in nodes:
            t_Node = Node(str(node[0]),label = str(node[1]),shape = "circle",color = self.colors[node[2]],fillcolor=self.colors[node[2]],style="filled")
            Nodes.append(t_Node)
        for edge in edges:
            if len(edge) > 2:
                t_Edge = Edge(edge[0],edge[1],label=edge[2])
            else:
                t_Edge = Edge(edge[0],edge[1])
            Edges.append(t_Edge)
        graphs = {}
        graphs["nodes"] = Nodes
        graphs["edges"] = Edges
        self.graph2fig(graphs,"ccc")
    
    def test(self):
        S0 = Node("s0",shape="circle",color="yellow")
        S11 = Node("s11")
        S12 = Node("s12")
        #S13 = Node("s13")
        #S14 = Node("s14")
        S21 = Node("s21")
        S22 = Node("s22")
        S23 = Node("s23")
        S24 = Node("s24")
        Se = Node("se")
        e01 = Edge(S0,S11,label ="Get")
        e02 = Edge(S0,S12,label ="Post")
        #e03 = Edge(S0,S13,label ="Get")
        #e04 = Edge(S0,S14,label ="post")
        e11 = Edge(S11,S21,label ="HTTP 200")
        e21 = Edge(S12,S22,label ="HTTP 200")
        e22 = Edge(S11,S23,label ="HTTP 404")
        e23 = Edge(S12,S24,label ="HTTP 404")
        e31 = Edge(S21,Se,label="")
        e32 = Edge(S22,Se,label="")
        e33 = Edge(S23,Se,label="")
        e34 = Edge(S24,Se,label="")
        t_graph = {}
        t_graph["nodes"] = [S11,S12,S0,S21,S22,S23,S24,Se]
        t_graph["edges"] = [e01,e02,e11,e21,e23,e22,e31,e32,e33,e34]
        self.graph2fig(t_graph,"bbb")
def f_modbus_src():
    Nodes = [(0,0,"S"),(1,1,"O"),(2,2,"C"),(3,5,"L"),(4,6,"C"),(7,7,"F"),(8,8,"O"),(9,10,"O"),(10,11,"O"),(11,7,"F"),(12,8,"O"),(13,10,"O"),(14,11,"O"),(15,7,"F"),(16,8,"O"),(17,11,"O"),(18,16,"O"),(19,23,"O"),(20,24,"D"),(21,7,"F"),(22,8,"O"),(23,9,"O"),(24,12,"O"),(25,13,"D")]
    Edges = [(0,1),(1,2),(2,3),(3,4),(4,7,"02"),(4,11,"01"),(4,15,"04"),(4,21,"15"),(7,8),(8,9),(9,10),(11,12),(12,13),(13,14),(15,16),(16,17),(17,18),(18,19),(19,20),(21,22),(22,23),(23,24),(24,25)]
    tree = tree_graph("a","B")
    tree.graph_build(Nodes,Edges)
  
    
def f_modbus_des():
    Nodes = [(0,0,"S"),(1,1,"O"),(2,2,"C"),(3,5,"L"),(4,6,"C"),(7,7,"F"),(8,8,"O"),(9,9,"O"),(10,10,"D"),(11,7,"F"),(12,8,"O"),(13,9,"O"),(14,10,"O"),(15,11,"D"),(16,7,"F"),(17,8,"O"),(18,9,"O"),(19,14,"O"),(20,18,"O"),(21,"...","O"),(22,7,"F"),(23,8,"O"),(24,9,"O"),(25,10,"O")]
    Edges = [(0,1),(1,2),(2,3),(3,4),(4,7,"02"),(4,11,"01"),(4,16,"04"),(4,22,"15"),(7,8),(8,9),(9,10),(11,12),(12,13),(13,14),(14,15),(16,17),(17,18),(18,19),(19,20),(20,21),(22,23),(23,24),(24,25)]
    tree = tree_graph("a","B")
    tree.graph_build(Nodes,Edges)

f_modbus_src()   
#tree = tree_graph("a","B")
#tree.test()
