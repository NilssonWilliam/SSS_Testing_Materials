from ipmininet.ipnet import IPNet 
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
import time
import glob
import os

tests = ["simple_test"]

class RandomizedTopo(IPTopo):
    def build(self, nodes, edges, hostcon, *args, **kwargs):
        hosts = []
        switches = []
        routers = []
        # Add routers
        for i in range(nodes):
            routers.append(self.addRouter("r"+str(i+1)))
        # Add hosts
        for i in range(len(hostcon)):
            hosts.append(self.addHost("h"+str(i+1)))
            switches.append(self.addSwitch("s"+str(i+1)))
            self.addLink(hosts[-1], switches[-1])
            self.addLink(switches[-1], routers[hostcon[i]-1])
        # Add links
        for a, b in edges:
            self.addLink(routers[a-1], routers[b-1])
        super().build(*args, **kwargs)

def main():
    files = glob.glob("Logs/*")
    for f in files:
        os.remove(f)
    for test in tests:
        net = IPNet(topo=RandomizedTopo(5, [(1, 2), (2, 3), (3, 4), (4, 5)], [1, 2, 4, 5])) 
        captures = []
        try:
            net.start()
            src = net.hosts[0]
            dst = net.hosts[1]
            fwds = net.hosts[2:]
            print(src.IP() + " " + dst.IP())
            time.sleep(120)
            for i, r in enumerate(net.routers):
                captures.append(r.popen("sudo tcpdump -i any -nn -s 0 -w Logs/" + test + str(i+1)))
            time.sleep(10)
            dst.popen("python3 sss_receiver.py 10 " + src.IP())
            fwdlst = ""
            for fwd in fwds:
                fwd.popen("python3 sss_forwarder.py " + dst.IP())
                fwdlst += fwd.IP() + " "
            time.sleep(2)
            sender = src.popen("python3 sss_sender.py 10 " + fwdlst)
            print(sender.wait())
            time.sleep(10)
        finally:
            for cap in captures:
                cap.terminate()
            net.stop()

if __name__ == "__main__":
    main()