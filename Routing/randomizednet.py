from ipmininet.ipnet import IPNet 
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from mininet.util import pmonitor
import time
import glob
import os

TESTS = ["simple_test"]

RUNS = 1

AMTFWDS = [1, 2, 3]

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

def verify_graph_connected(nodes, edges, hostcon, adj):
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

def verify_graph_hopdist(nodes, edges, hostcon, adj):
    dst = hostcon[1]
    accepted = True
    for fwd in hostcon[2:]:
        nexthops = adj[str(fwd-1)]
        if dst in nexthops:
            accepted = False
    return accepted

def verify_graph_uniquepaths(nodes, edges, hostcon, adj):
    return True

def verify_graph(nodes, edges, hostcon):
    ans = True
    # Make adjacency list for effiency
    adj = {}
    for i in range(nodes):
        adj[str(i)] = set()
    for a, b in edges:
        adj[str(a-1)].add(b-1)
        adj[str(b-1)].add(a-1)
    ans = ans and verify_graph_connected(nodes, edges, hostcon, adj)
    ans = ans and verify_graph_hopdist(nodes, edges, hostcon, adj)
    ans = ans and verify_graph_uniquepaths(nodes, edges, hostcon, adj)
    
def run_network(test, nodes, edges, hostcon):
    net = IPNet(topo=RandomizedTopo(nodes, edges, hostcon)) 
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
            srcip = a.IP()
        else:
            srcip = b.IP()
        time.sleep(120)
        for i, r in enumerate(net.routers):
            captures.append(r.popen("sudo tcpdump -i any -nn -U -s 0 -w Logs/" + test + str(i+1)))
        fwdlst = []
        for fwd in fwds:
            fwd.popen("python3 sss_forwarder.py " + dst.IP())
            a, b = fwd.connectionsTo(srcsw)[0]
            if str(fwd) in str(a):
                fwdlst.append(a.IP())
            else:
                fwdlst.append(b.IP())
        time.sleep(5)
        for amtfwd in AMTFWDS:
            fwdstr = ""
            for i in range(amtfwd):
                fwdstr += fwdlst[i] + " "
            dst.popen("python3 sss_receiver.py 33 " + srcip)
            time.sleep(1)
            sender = src.popen("python3 sss_sender.py 33 " + fwdstr)
            print("Test done")
            print(sender.wait())
            time.sleep(10)
    finally:
        for cap in captures:
            cap.terminate()
        net.stop()

def main():
    files = glob.glob("Logs/*")
    for f in files:
        os.remove(f)
    for testname in TESTS:
        for run in range(RUNS):
            test = testname + str(run) + "_"
            print("Starting test " + testname + str(run))
            run_network(test, 5, [(1, 2), (2, 3), (3, 4), (4, 5), (5, 1)], [0, 2, 4, 5, 3])

if __name__ == "__main__":
    main()