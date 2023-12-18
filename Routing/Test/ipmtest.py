from ipmininet.ipnet import IPNet 
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
import time

class MyTopology(IPTopo):
    def build(self, *args, **kwargs):
        r1 = self.addRouter("r1")
        r2 = self.addRouter("r2")
        # Helper to create several routers in one function call 
        r3, r4, r5 = self.addRouters("r3", "r4", "r5")
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        self.addLink(r1, r2)
        # Helper to create several links in one function call 
        self.addLinks((s1, r1), (h1, s1), (s2, r2), (h2, s2), (r2, r3),
              (r3, r4), (r4, r5))
        super().build(*args, **kwargs)

def main():
    net = IPNet(topo=MyTopology()) 
    try:
        net.start()
        h1 = net.get("h1")
        h2 = net.get("h2")
        print(h1.IP() + h2.IP())
        r1 = net.get("r1")
        r1pcap = r1.popen("sudo tcpdump -i any -nn -s 0 -w r1cap ")
        r2 = net.get("r2")
        r2pcap = r2.popen("sudo tcpdump -i any -nn -s 0 -w r2cap ")
        IPCLI(net)
    finally:
        r1pcap.terminate()
        r2pcap.terminate()
        net.stop()

if __name__ == "__main__":
    main()