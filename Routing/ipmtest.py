from ipmininet.ipnet import IPNet 
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
import time
import glob
import os

class MyTopology(IPTopo):
    def build(self, n, *args, **kwargs):
        print(n)
        r1 = self.addRouter("r1")
        r2 = self.addRouter("r2")
        # Helper to create several routers in one function call 
        r3, r4, r5 = self.addRouters("r3", "r4", "r5")
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        self.addLink(r1, r2)
        # Helper to create several links in one function call 
        self.addLinks((s1, r1), (h1, s1), (s2, r2), (h2, s2), (r2, r3),
              (r3, r4), (r4, r5), (h3, s3), (s3, r5))
        super().build(*args, **kwargs)

def main():
    files = glob.glob("Logs/*")
    for f in files:
        os.remove(f)
    net = IPNet(topo=MyTopology(25)) 
    captures = []
    try:
        net.start()
        src = net.get("h1")
        dst = net.get("h2")
        fwd = net.get("h3")
        print(src.IP() + " " + dst.IP() + " " + fwd.IP())
        time.sleep(20)
        for i, r in enumerate(net.routers):
            captures.append(r.popen("sudo tcpdump -i any -nn -s 0 -w Logs/simple_test" + str(i+1)))
        IPCLI(net)
    finally:
        for cap in captures:
            cap.terminate()
        net.stop()

if __name__ == "__main__":
    main()