from ipmininet.ipnet import IPNet 
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from mininet.util import pmonitor
import time
import glob
import os
import random

TESTS = ["line_graph", "mesh_graph", "full_random"]

RUNS = 5

AMTFWDS = [3, 5, 7, 11]

AMTNODES = [50, 100, 150, 200]

class RandomizedTopo(IPTopo):
    def build(self, nodes, edges, hostcon, *args, **kwargs):
        hosts = []
        switches = []
        routers = []
        # Add routers
        for i in range(nodes):
            routers.append(self.addRouter("r"+str(i+1)))
        # Add hosts
        if hostcon[0] == 0: # Source should only communicate through forwarders
            hosts.append(self.addHost("h1")) # Source
            switches.append(self.addSwitch("s1"))
            self.addLink(hosts[0], switches[0])
            for i in range(1, len(hostcon)):
                hosts.append(self.addHost("h"+str(i+1)))
                switches.append(self.addSwitch("s"+str(i+1)))
                self.addLink(hosts[-1], switches[-1])
                self.addLink(switches[-1], routers[hostcon[i]-1])
                if i > 1: # Except for the destination
                    self.addLink(hosts[-1], switches[0])
        else: # Source has a connection into the network not through a forwarder
            for i in range(len(hostcon)):
                hosts.append(self.addHost("h"+str(i+1)))
                switches.append(self.addSwitch("s"+str(i+1)))
                self.addLink(hosts[-1], switches[-1])
                self.addLink(switches[-1], routers[hostcon[i]-1])
        # Add a direct connection between host and destination
        switches.append(self.addSwitch("s0"))
        self.addLink(hosts[0], switches[-1])
        self.addLink(hosts[1], switches[-1])
        # Add links
        for a, b in edges:
            self.addLink(routers[a-1], routers[b-1])
        super().build(*args, **kwargs)

def verify_graph_connected(nodes, edges):
    adj = {}
    for i in range(nodes):
        adj[str(i)] = set()
    for a, b in edges:
        adj[str(a-1)].add(b-1)
        adj[str(b-1)].add(a-1)
    queue = []
    queue.append(0)
    visited = set()
    while len(queue) > 0:
        cur = queue.pop()
        visited.add(cur)
        nexthops = adj[str(cur)]
        for hop in nexthops:
            if hop not in visited:
                queue.append(hop)
    return len(visited) == nodes

def verify_graph_hosts(hostcon, adj):
    dst = hostcon[1]
    accepted = True
    for fwd in hostcon[2:]:
        if dst == fwd:
            accepted = False
        nexthops = adj[str(fwd-1)]
        for hop in nexthops:
            if hop == dst:
                accepted = False
            else:
                if dst in adj[str(hop)]:
                    accepted = False
    s = set(hostcon)
    return accepted and len(s) == len(hostcon)

def fully_random_graph(nodes, edgeamt):
    edges = set()
    for _ in range(nodes * edgeamt):
        a = random.SystemRandom().randint(1, nodes)
        b = random.SystemRandom().randint(1, nodes)
        if a != b:
            edges.add((a, b))
    return list(edges)

def mesh_graph(nodes, edgeamt):
    edges = set()
    for i in range(nodes):
        for _ in range(edgeamt):
            b = random.SystemRandom().randint(1, nodes)
            if b != i+1:
                edges.add((i+1, b))
    return list(edges)

def line_graph(nodes):
    edges = set()
    for i in range(nodes):
        if i+1 == nodes:
            edges.add((i+1, 1))
        else:
            edges.add((i+1, i+2))
        if random.SystemRandom().randint(1, 2) == 2:
            b = random.SystemRandom().randint(1, nodes)
            if b != i+1:
                edges.add((i+1, b))
    return list(edges)

def generate_graph(test, nodes, run):
    edges = []
    if test == "full_random":
        edgeamt = [3, 5, 10]
        edges = fully_random_graph(nodes, edgeamt[run % 3])
    elif test == "mesh_graph":
        edgeamt = [3, 5, 10]
        edges = mesh_graph(nodes, edgeamt[run % 3])
    else:
        edges = line_graph(nodes)
    return edges

def generate_hostcon(nodes, adj):
    res = [0]
    amtConnections = 0
    dst = 0
    for i in range(nodes):
        connections = len(adj[str(i)])
        if connections > amtConnections:
            amtConnections = connections
            dst = i
    res.append(dst+1)
    for i in range(11):
        rng = random.SystemRandom().randint(1, nodes)
        res.append(rng)
    return res

def generate_and_verify_graph(testname, nodes, run):
    edges = generate_graph(testname, nodes, run)
    while not verify_graph_connected(nodes, edges):
        edges = generate_graph(testname, nodes, run)
    # Make adjacency list for efficiency
    adj = {}
    for i in range(nodes):
        adj[str(i)] = set()
    for a, b in edges:
        adj[str(a-1)].add(b-1)
        adj[str(b-1)].add(a-1)
    hostcon = generate_hostcon(nodes, adj)
    while not verify_graph_hosts(hostcon, adj):
        hostcon = generate_hostcon(nodes, adj)
    return edges, hostcon
    
def run_network(test, nodes, edges, hostcon):
    net = IPNet(topo=RandomizedTopo(nodes, edges, hostcon), use_v4=False) 
    captures = []
    try:
        net.start()
        src = net.hosts[0]
        dst = net.hosts[1]
        fwds = net.hosts[2:]
        dstsw = net.switches[0]
        srcsw = net.switches[1]
        a, b = src.connectionsTo(dstsw)[0]
        if str(src) in str(a):
            srcip = a.ip6
        else:
            srcip = b.ip6
        time.sleep(120)
        for i, r in enumerate(net.routers):
            captures.append(r.popen("sudo tcpdump -i any -nn -U -s 0 -w Logs/" + test + str(i+1)))
        fwdlst = []
        for fwd in fwds:
            fwd.popen("python3 sss_forwarder.py " + dst.defaultIntf().ip6)
            a, b = fwd.connectionsTo(srcsw)[0]
            if str(fwd) in str(a):
                fwdlst.append(a.ip6)
            else:
                fwdlst.append(b.ip6)
        time.sleep(5)
        for amtfwd in AMTFWDS:
            fwdstr = ""
            for i in range(amtfwd):
                fwdstr += fwdlst[i] + " "
            dst.popen("python3 sss_receiver.py 33 " + srcip)
            time.sleep(1)
            sender = src.popen("python3 sss_sender.py 33 " + fwdstr)
            print("Sender terminated with status:", sender.wait())
            time.sleep(10)
    finally:
        for cap in captures:
            cap.terminate()
        net.stop()

def main():
    files = glob.glob("Logs/*")
    # for f in files:
    #     os.remove(f)
    for testname in TESTS:
        if testname == "line_graph":
            runs = range(RUNS)
        else:
            runs = range(3*RUNS)
        for nodes in AMTNODES:
            for run in runs:
                test = testname + str(nodes) + "_" + str(run) + "_"
                if "Logs/" + test + "1" in files:
                    print(test + " already exists")
                    continue
                print("Starting test " + testname + str(nodes) + "_" + str(run))
                edges, hostcon = generate_and_verify_graph(testname, nodes, run)
                print(edges)
                print("Network was generated")
                run_network(test, nodes, edges, hostcon)

if __name__ == "__main__":
    main()