import pyshark
import pickle
import os
import datetime

FILEPATH = "/home/ubuntu/SSS_Testing_Materials/Routing/Logs"

SOURCE = "192.168.0.2"
DESTINATION = "192.168.2.1"
SSSPORT = "11111"

FILES = ["simple_test"]



def getSharesFromFile(filename):
    capture = pyshark.FileCapture(FILEPATH + "/" + filename)
    result = []
    acc = []
    last_timestamp = datetime.datetime.now()
    highest_index = 0
    for packet in capture:
        if hasattr(packet, "data") and hasattr(packet, "ip") and hasattr(packet, "tcp"): # Must be TCP with data
            if packet.ip.src == SOURCE or packet.ip.dst == DESTINATION: # or due to forwarder
                if packet.tcp.dstport == SSSPORT: # Only traffic on the port used for the secret sharing scheme
                    data = pickle.loads(bytes.fromhex(packet.data.data))
                    index, nr = data
                    if index > highest_index: 
                        highest_index = index # Track the highest share index
                    timestamp = packet.sniff_time
                    diff = timestamp - last_timestamp
                    if diff.total_seconds() > 9: 
                        # Tests have a time of 10 seconds inbetween themselves so we can be sure it is a new run
                        result.append(acc)
                        acc = []
                    last_timestamp = timestamp
                    acc.append((data, timestamp))
    result.append(acc)
    return result, highest_index

def getAllFiles(fn):
    allrouters = []
    highest_index = 0
    if os.path.exists(FILEPATH + "/" + fn + "1"):
        print("Reading the test " + fn)
        nextExists = True
        counter = 1
        while nextExists:
            data, index = getSharesFromFile(fn + str(counter))
            if index > highest_index:
                highest_index = index
            allrouters.append(data)
            counter += 1
            nextExists = os.path.exists(FILEPATH + "/" + fn + str(counter))
        print("There was a total of " + str(counter-1) + " routers in that test")
        print("The highest share index was " + str(highest_index))
    else:
        print("There were no routers with the name " + fn)
    return allrouters, highest_index

def extractTime(e):
    _, t = e
    return t

def getAllRoutes(data, index):
    sharePaths = []
    routerShares = []
    # Figure out which routers each packet passed
    for routerindex, router in enumerate(data):
        for i, run in enumerate(router):
            if routerindex == 0:
                sharePaths.append([])
                routerShares.append([])
                for j in range(len(data)):
                    routerShares[i].append([])
                for j in range(index):
                    sharePaths[i].append([])
            for (share, nr), time in run:
                sharePaths[i][share-1].append((routerindex + 1, time))
                if not share in routerShares[i][routerindex]:
                    routerShares[i][routerindex].append(share)
    # Sort the data for each packet based on the timestamp
    for run in sharePaths:
        for shares in run:
            shares.sort(key=extractTime)
    sharePathsNoTime = []
    for i, run in enumerate(sharePaths):
        sharePathsNoTime.append([])
        for shares in run:
            sharePathsNoTime[i].append([e[0] for e in shares])
    return sharePathsNoTime, routerShares

            




def main():
    for fn in FILES:
        data, index = getAllFiles(fn)
        sharePaths, routerShares = getAllRoutes(data, index)
        print(sharePaths)
        print(routerShares)
    


if __name__ == "__main__":
    main()
