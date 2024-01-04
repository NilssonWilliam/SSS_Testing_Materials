import pyshark
import pickle
import os
import datetime

FILEPATH = "/home/ubuntu/SSS_Testing_Materials/Routing/Logs"

SSSPORT = "11111"

FILES = ["simple_test"]
RUNS = 1



def getSharesFromFile(filename):
    capture = pyshark.FileCapture(FILEPATH + "/" + filename)
    result = []
    acc = []
    last_timestamp = datetime.datetime.now()
    highest_index = 0
    for packet in capture:
        if hasattr(packet, "data") and hasattr(packet, "ip") and hasattr(packet, "tcp"): # Must be TCP with data
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

def getIndexOfMissingRuns(a, b):
    indexes = []
    runindex = 0
    maxindex = len(a)
    for i, run in enumerate(b):
        if runindex == maxindex:
            indexes.append(i)
            continue
        if len(a[0]) == 0:
            indexes.append(i)
            continue
        _, timea = a[runindex][0]
        _, timeb = run[0]
        if timea - timeb > datetime.timedelta(seconds=9):
            indexes.append(i)
        else:
            runindex += 1
    return indexes

def getAllFiles(fn):
    allrouters = []
    highest_index = 0
    if os.path.exists(FILEPATH + "/" + fn + "1"):
        print("Reading the test " + fn)
        nextExists = True
        counter = 1
        highestRun = 0
        highestRunIndex = 1
        while nextExists:
            data, index = getSharesFromFile(fn + str(counter))
            if counter == 1:
                highestRun = len(data)
            else:
                if highestRun < len(data):
                    highestRun = len(data)
                    highestRunIndex = counter-1
            if index > highest_index:
                highest_index = index
            allrouters.append(data)
            counter += 1
            nextExists = os.path.exists(FILEPATH + "/" + fn + str(counter))
        for routerindex, router in enumerate(allrouters):
            if routerindex == highestRunIndex:
                continue
            missing = getIndexOfMissingRuns(router, allrouters[highestRunIndex])
            print(missing)
            for i in missing:
                allrouters[routerindex].insert(i, [])
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
    for routerindex, routerdata in enumerate(data):
        for runindex, rundata in enumerate(routerdata):
            if routerindex == 0:
                sharePaths.append([])
                routerShares.append([])
                for j in range(len(data)):
                    routerShares[runindex].append([])
                for j in range(index):
                    sharePaths[runindex].append([])
            for (share, nr), time in rundata:
                sharePaths[runindex][share-1].append((routerindex + 1, time))
                if not share in routerShares[runindex][routerindex]:
                    routerShares[runindex][routerindex].append(share)
    # Sort the data for each packet based on the timestamp
    for rundata in sharePaths:
        for shares in rundata:
            shares.sort(key=extractTime)
    sharePathsNoTime = []
    for runindex, rundata in enumerate(sharePaths):
        sharePathsNoTime.append([])
        for shares in rundata:
            sharePathsNoTime[runindex].append([e[0] for e in shares])
    return sharePathsNoTime, routerShares

            




def main():
    for fn in FILES:
        for run in range(RUNS):
            data, index = getAllFiles(fn + str(run) + "_")
            sharePaths, routerShares = getAllRoutes(data, index)
            print(sharePaths)
            print(routerShares)
    


if __name__ == "__main__":
    main()
