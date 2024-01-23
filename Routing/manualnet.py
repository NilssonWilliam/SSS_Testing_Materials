from ipmininet.ipnet import IPNet 
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from mininet.util import pmonitor
import time
import glob
import os
import random
import sys

class RandomizedTopo(IPTopo):
    def build(self, nodes, edges, srccon, dstcon, *args, **kwargs):
        hosts = []
        switches = []
        routers = []
        # Add routers
        for i in range(nodes):
            routers.append(self.addRouter("r"+str(i+1)))
        # Add sender and receiver
        hosts.append(self.addHost("h1")) # Source
        switches.append(self.addSwitch("s1"))
        self.addLink(hosts[0], switches[0])
        hosts.append(self.addHost("h2")) # Source
        switches.append(self.addSwitch("s2"))
        self.addLink(hosts[1], switches[1])
        # Add sources
        for i in range(2, len(srccon)+2):
            hosts.append(self.addHost("h"+str(i+1)))
            switches.append(self.addSwitch("s"+str(i+1)))
            self.addLink(hosts[-1], switches[-1])
            self.addLink(switches[-1], routers[srccon[i-2]-1])
            self.addLink(hosts[-1], switches[0])
        # Add destinations
        for i in range(len(srccon) + 2, len(dstcon) + len(srccon) + 2):
            hosts.append(self.addHost("h"+str(i+1)))
            switches.append(self.addSwitch("s"+str(i+1)))
            self.addLink(hosts[-1], switches[-1])
            self.addLink(switches[-1], routers[dstcon[i-len(srccon)-2]-1])
            self.addLink(hosts[-1], switches[1])
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
        edgeamt = [3, 4, 5]
        edges = fully_random_graph(nodes, edgeamt[run % 3])
    elif test == "mesh_graph":
        edgeamt = [3, 4, 5]
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
    
def run_network(test, nodes, edges, srccon, dstcon):
    net = IPNet(topo=RandomizedTopo(nodes, edges, srccon, dstcon), use_v4=False) 
    captures = []
    try:
        net.start()
        src = net.hosts[0]
        dst = net.hosts[1]
        fwds = net.hosts[2:len(srccon)+2]
        rcvs = net.hosts[len(srccon)+2:]
        dstsw = net.switches[0]
        srcsw = net.switches[1]
        dstpsw = net.switches[2]
        a, b = src.connectionsTo(dstsw)[0]
        if str(src) in str(a):
            srcip = a.ip6
        else:
            srcip = b.ip6
        time.sleep(120)
        for i, r in enumerate(net.routers):
            captures.append(r.popen("sudo tcpdump -i any -nn -U -s 0 -w Logs/" + test + str(i+1)))
        fwdlst = []
        a, b = dst.connectionsTo(dstpsw)[0]
        if str(dst) in str(a):
            dstip = a.ip6
        else:
            dstip = b.ip6
        for i, fwd in enumerate(fwds):
            a, b = fwd.connectionsTo(srcsw)[0]
            if str(fwd) in str(a):
                fwdlst.append(a.ip6)
            else:
                fwdlst.append(b.ip6)
            nexthop = rcvs[i]
            a, b = nexthop.connectionsTo(net.switches[3+len(srccon)+i])[0]
            if str(nexthop) in str(a):
                nextip = a.ip6
            else:
                nextip = b.ip6
            fwd.popen("python3 sss_forwarder.py " + nextip)
        for fwd in rcvs:
            fwd.popen("python3 sss_forwarder.py " + dstip)
        time.sleep(5)
        fwdstr = ""
        for i in range(5):
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
    # edges, hostcon = generate_and_verify_graph("full_random", 100, 0)
    # for a, b in edges:
    #     print(str(a) + "," +str(b) + "," + str(1))
    # print(edges, file=sys.stderr)
    nodes = 100
    test = "manual_configuration" + str(nodes) + "_" + str(0) + "_"
    edges = [(92, 58), (16, 20), (62, 72), (33, 91), (53, 5), (44, 100), (85, 49), (10, 98), (35, 42), (62, 26), (91, 62), (39, 33), (30, 64), (46, 33), (20, 29), (47, 25), (38, 44), (36, 25), (34, 37), (68, 2), (5, 28), (5, 92), (51, 89), (69, 40), (72, 2), (57, 43), (75, 99), (50, 45), (35, 26), (69, 58), (96, 42), (4, 2), (89, 70), (45, 67), (61, 63), (16, 95), (37, 8), (19, 2), (11, 53), (74, 2), (75, 1), (74, 66), (94, 14), (19, 11), (63, 45), (43, 60), (56, 39), (85, 66), (72, 50), (4, 32), (52, 81), (29, 61), (55, 43), (79, 10), (7, 58), (21, 57), (61, 93), (81, 71), (47, 48), (1, 26), (65, 29), (84, 79), (30, 41), (10, 29), (87, 75), (48, 95), (3, 8), (56, 78), (99, 58), (91, 75), (40, 36), (93, 17), (65, 56), (92, 19), (20, 88), (37, 83), (32, 62), (91, 93), (21, 41), (85, 86), (64, 57), (78, 56), (96, 92), (2, 27), (54, 10), (79, 94), (48, 88), (71, 90), (36, 77), (31, 26), (48, 42), (5, 71), (94, 73), (95, 38), (20, 99), (78, 31), (77, 96), (1, 67), (84, 1), (44, 17), (71, 65), (47, 43), (44, 26), (78, 58), (79, 23), (41, 39), (72, 17), (82, 19), (27, 58), (36, 6), (22, 7), (56, 9), (99, 44), (12, 15), (97, 83), (78, 79), (85, 72), (13, 62), (61, 81), (92, 96), (72, 1), (33, 83), (79, 80), (8, 93), (53, 70), (82, 21), (48, 83), (11, 98), (73, 82), (14, 60), (71, 30), (83, 50), (31, 12), (77, 73), (1, 96), (23, 17), (32, 50), (85, 47), (51, 63), (89, 81), (12, 26), (14, 87), (32, 68), (44, 67), (34, 41), (98, 22), (61, 37), (76, 19), (44, 21), (81, 15), (15, 70), (89, 53), (11, 27), (22, 57), (76, 92), (97, 5), (25, 35), (30, 49), (83, 52), (54, 16), (95, 17), (28, 61), (29, 17), (20, 23), (78, 10), (48, 94), (23, 19), (63, 83), (5, 4), (18, 32), (24, 48), (18, 96), (51, 74), (44, 60), (59, 33), (46, 8), (93, 92), (16, 71), (98, 88), (1, 82), (76, 85), (10, 85), (62, 13), (38, 22), (51, 49), (26, 29), (63, 30), (95, 28), (14, 73), (77, 22), (35, 41), (59, 72), (70, 72), (73, 34), (87, 33), (32, 63), (23, 94), (4, 90), (56, 91), (47, 33), (56, 100), (83, 93), (76, 32), (39, 13), (54, 66), (31, 9), (13, 34), (49, 33), (23, 14), (18, 27), (36, 8), (4, 74), (21, 90), (62, 27), (49, 42), (34, 84), (99, 64), (5, 20), (48, 55), (2, 67), (11, 15), (62, 63), (64, 60), (17, 40), (84, 5), (32, 86), (94, 58), (69, 4), (87, 74), (38, 35), (72, 85), (90, 36), (9, 97), (90, 100), (58, 77), (91, 10), (2, 51), (90, 54), (79, 54), (13, 63), (96, 79), (38, 1), (94, 88), (99, 84), (38, 10), (69, 43), (86, 4), (72, 69), (98, 33), (6, 78), (52, 45), (15, 35), (88, 41), (16, 43), (56, 79), (39, 93), (16, 52), (47, 85), (47, 30), (76, 66), (68, 62), (20, 43), (3, 91), (9, 22), (66, 74), (10, 84), (9, 86), (97, 52), (39, 65), (97, 43), (18, 6), (86, 70), (94, 53), (53, 67), (67, 66), (89, 66), (32, 99), (67, 11), (64, 76), (78, 75), (55, 82), (99, 52), (73, 97), (10, 4), (2, 55), (81, 55), (70, 89), (74, 71), (90, 58), (31, 100), (23, 96), (46, 9), (37, 49), (85, 98), (6, 73)]
    srccon = [3, 12, 37, 63, 89]
    dstcon = [40, 7, 42, 76, 19]
    run_network(test, nodes, edges, srccon, dstcon)
    test = "manual_configuration" + str(nodes) + "_" + str(1) + "_"
    edges = [(69, 56), (97, 72), (42, 39), (58, 56), (79, 33), (45, 65), (47, 62), (47, 71), (87, 89), (2, 48), (10, 61), (53, 96), (91, 80), (17, 21), (86, 38), (68, 66), (17, 94), (29, 4), (75, 35), (31, 65), (42, 32), (90, 17), (90, 81), (55, 59), (52, 97), (42, 41), (15, 32), (41, 51), (44, 47), (82, 31), (76, 45), (56, 21), (76, 54), (46, 50), (92, 17), (40, 98), (67, 27), (4, 32), (11, 80), (55, 43), (58, 42), (97, 58), (1, 17), (33, 86), (6, 13), (73, 67), (90, 19), (62, 12), (16, 24), (93, 30), (63, 84), (63, 29), (54, 26), (45, 87), (100, 87), (60, 14), (92, 19), (92, 83), (89, 29), (48, 58), (97, 42), (38, 57), (80, 90), (41, 74), (24, 3), (32, 7), (52, 10), (87, 50), (71, 8), (72, 70), (78, 1), (25, 84), (81, 82), (4, 61), (56, 62), (44, 42), (56, 7), (63, 13), (46, 91), (73, 23), (36, 68), (45, 25), (97, 35), (5, 80), (89, 31), (5, 89), (44, 72), (50, 88), (70, 91), (95, 65), (24, 23), (76, 24), (55, 1), (24, 87), (30, 36), (1, 30), (44, 99), (62, 80), (91, 61), (93, 58), (29, 22), (73, 25), (39, 87), (11, 50), (37, 60), (32, 48), (34, 82), (38, 43), (86, 92), (85, 72), (21, 36), (81, 50), (26, 59), (38, 61), (41, 23), (80, 39), (19, 29), (90, 80), (56, 57), (11, 89), (64, 70), (81, 86), (48, 83), (68, 31), (20, 21), (77, 73), (21, 20), (3, 69), (37, 16), (29, 58), (57, 49), (40, 97), (97, 94), (4, 22), (12, 90), (70, 22), (50, 19), (26, 61), (58, 96), (99, 67), (42, 24), (53, 54), (96, 34), (11, 82), (44, 30), (57, 79), (28, 43), (30, 40), (22, 2), (48, 21), (82, 78), (39, 82), (23, 65), (84, 17), (32, 43), (67, 10), (3, 7), (95, 26), (20, 87), (21, 22), (21, 86), (78, 74), (51, 1), (78, 83), (81, 45), (58, 89), (64, 38), (52, 82), (62, 50), (2, 8), (100, 43), (39, 2), (5, 98), (83, 100), (45, 61), (65, 39), (49, 22), (5, 61), (40, 28), (58, 73), (58, 82), (41, 11), (10, 69), (82, 55), (62, 52), (53, 49), (33, 16), (98, 81), (10, 78), (13, 68), (20, 46), (16, 73), (5, 36), (82, 73), (71, 73), (1, 84), (76, 32), (28, 47), (32, 29), (77, 52), (9, 34), (78, 60), (22, 70), (83, 56), (21, 72), (87, 26), (43, 56), (50, 7), (87, 90), (6, 46), (97, 100), (42, 21), (47, 35), (63, 53), (22, 45), (37, 98), (71, 11), (76, 89), (37, 52), (29, 14), (57, 30), (40, 14), (24, 27), (5, 56), (46, 94), (14, 4), (77, 17), (53, 17), (90, 36), (95, 32), (64, 26), (18, 38), (70, 85), (74, 67), (28, 24), (82, 4), (17, 33), (92, 36), (97, 50), (9, 29), (40, 7), (97, 59), (3, 52), (89, 55), (4, 51), (35, 84), (51, 46), (24, 84), (57, 96), (97, 68), (77, 1), (88, 41), (1, 100), (7, 95), (8, 60), (42, 71), (34, 33), (9, 13), (88, 13), (3, 91), (23, 39), (6, 62), (63, 11), (20, 6), (24, 22), (23, 2), (70, 53), (61, 50), (15, 28), (84, 82), (16, 27), (58, 63), (79, 31), (36, 5), (73, 15), (98, 53), (50, 68), (10, 50), (93, 11), (34, 26), (54, 93), (40, 39), (36, 87), (9, 6), (65, 77), (29, 2), (9, 33), (61, 34), (60, 99), (70, 46), (97, 8)]
    srccon = [6, 99, 27, 15, 75]
    dstcon = [85, 5, 49, 54, 96]
    run_network(test, nodes, edges, srccon, dstcon)
    test = "manual_configuration" + str(nodes) + "_" + str(2) + "_"
    edges = [(15, 21), (72, 73), (67, 4), (86, 72), (78, 4), (35, 33), (64, 14), (16, 29), (15, 85), (13, 42), (41, 58), (64, 23), (54, 22), (35, 51), (16, 47), (3, 77), (92, 79), (68, 57), (74, 18), (5, 28), (46, 11), (41, 79), (32, 76), (41, 24), (48, 72), (94, 39), (75, 90), (38, 62), (9, 99), (42, 32), (18, 10), (43, 94), (95, 77), (8, 39), (50, 54), (76, 36), (81, 32), (22, 83), (46, 50), (12, 27), (56, 39), (83, 23), (24, 1), (57, 77), (23, 54), (62, 3), (51, 100), (22, 3), (99, 40), (30, 50), (48, 86), (53, 27), (3, 8), (77, 76), (54, 90), (29, 36), (75, 3), (86, 88), (86, 33), (93, 81), (56, 87), (48, 58), (84, 54), (35, 67), (77, 48), (14, 44), (49, 75), (7, 69), (30, 34), (26, 82), (33, 88), (47, 50), (87, 77), (53, 20), (86, 17), (12, 13), (9, 5), (28, 82), (92, 85), (6, 45), (80, 92), (58, 37), (24, 78), (56, 46), (82, 10), (89, 58), (99, 26), (8, 91), (54, 67), (45, 64), (81, 93), (14, 3), (48, 90), (43, 48), (42, 90), (92, 14), (29, 31), (77, 25), (61, 8), (32, 57), (23, 88), (83, 75), (85, 72), (32, 66), (86, 92), (87, 36), (50, 81), (15, 59), (23, 42), (96, 78), (84, 58), (70, 38), (33, 83), (30, 29), (33, 28), (17, 32), (8, 93), (18, 73), (35, 89), (47, 54), (68, 31), (82, 30), (20, 76), (22, 18), (52, 53), (56, 84), (4, 13), (92, 25), (77, 100), (13, 9), (45, 41), (88, 76), (55, 51), (30, 95), (65, 28), (31, 5), (77, 57), (31, 14), (9, 48), (6, 79), (74, 49), (91, 65), (80, 7), (6, 88), (20, 87), (92, 9), (95, 99), (86, 96), (35, 57), (86, 41), (35, 11), (93, 92), (65, 21), (91, 40), (30, 33), (28, 36), (90, 84), (62, 13), (83, 100), (73, 13), (63, 67), (66, 29), (79, 20), (93, 55), (36, 49), (11, 47), (24, 32), (37, 66), (86, 80), (69, 9), (92, 11), (50, 5), (43, 54), (7, 34), (35, 50), (81, 47), (96, 20), (13, 68), (65, 69), (30, 81), (79, 13), (61, 96), (73, 61), (85, 26), (90, 86), (82, 18), (21, 63), (37, 59), (2, 37), (50, 53), (3, 11), (69, 11), (29, 94), (35, 43), (41, 59), (21, 90), (21, 35), (59, 19), (64, 33), (69, 84), (55, 94), (50, 25), (27, 87), (71, 57), (25, 69), (28, 31), (36, 44), (30, 92), (5, 38), (86, 2), (6, 67), (95, 69), (48, 27), (75, 100), (24, 27), (69, 4), (60, 1), (81, 88), (53, 17), (6, 30), (61, 64), (91, 10), (95, 41), (39, 36), (55, 32), (7, 47), (55, 96), (65, 9), (20, 41), (68, 60), (94, 88), (83, 33), (38, 65), (8, 94), (54, 61), (51, 92), (31, 13), (35, 84), (52, 45), (87, 12), (7, 22), (97, 22), (77, 74), (33, 41), (24, 38), (23, 82), (15, 99), (55, 80), (82, 70), (82, 98), (65, 57), (9, 4), (27, 82), (19, 14), (37, 29), (57, 62), (93, 27), (83, 26), (29, 46), (66, 74), (57, 71), (56, 51), (10, 84), (88, 77), (3, 45), (32, 81), (85, 96), (39, 65), (38, 76), (74, 32), (41, 38), (12, 75), (36, 5), (55, 18), (67, 84), (87, 32), (59, 16), (44, 61), (76, 59), (46, 55), (31, 100), (68, 64), (95, 48), (43, 10), (57, 73), (60, 35), (13, 15), (32, 28), (97, 63), (49, 78)]
    srccon = [6, 99, 27, 15, 75]
    dstcon = [85, 5, 49, 54, 96]
    run_network(test, nodes, edges, srccon, dstcon)
    

if __name__ == "__main__":
    main()