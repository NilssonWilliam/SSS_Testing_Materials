import pyshark
import pickle
import os
import datetime
import math
import random
import copy

FILEPATH = "/home/ubuntu/SSS_Testing_Materials/Routing/Logs"

SSSPORT = "11111"

FILES = ["line_graph", "mesh_graph", "full_random"]
RUNS = 5

AMTNODES = [50, 100, 150, 200]



def getSharesFromFile(filename):
    capture = pyshark.FileCapture(FILEPATH + "/" + filename)
    result = []
    acc = []
    last_timestamp = datetime.datetime.now()
    highest_index = 0
    for packet in capture:
        if hasattr(packet, "data") and hasattr(packet, "tcp"): # Must be TCP with data
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
    if a[0] == []:
        return [a for a in range(len(b)-1)]
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
        highestRunIndex = 0
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

def threshold_setcover(routerdatain, index):
    routerdata = copy.deepcopy(routerdatain)
    ans = []
    for j in range(len(routerdata)):
        run = routerdata[j]
        thresholds = [17, 22, 28, 33]
        taken = set()
        counter = 0
        acc = [] 
        while len(thresholds) > 0:
            maxlen = 0
            maxindex = -1
            counter += 1
            for routerindex, router in enumerate(run):
                if (maxlen < len(router)) and (len(router) != index - len(taken)):
                    maxlen = len(router)
                    maxindex = routerindex
            if maxindex == -1:
                for t in thresholds:
                    acc.append(counter)
                thresholds = []
            shares = run[maxindex].copy()
            for share in shares:
                taken.add(share)
                for i in range(len(run)):
                    router = run[i]
                    if share in router:
                        router.remove(share)
            i = 0
            while i < len(thresholds):
                if len(taken) >= thresholds[i]:
                    acc.append(counter)
                    thresholds.pop(i)
                else:
                    i += 1
        ans.append(acc)
    return ans

def path_similarity_single(a, b):
    overlap = len([v for v in a if v in b])
    total = len(set(a+b))
    return overlap/total

def path_similarity(paths):
    ans = []
    for run in paths:
        acc = 0
        nums = 0
        for i in range(len(run)):
            for j in range(i+1, len(run)):
                acc += path_similarity_single(run[i], run[j])
                nums += 1
        ans.append(acc/nums)
    return ans

def check_compromised(compromised_nodes, routers, index):
    shares = set()
    for compromised_node in compromised_nodes:
        router = routers[compromised_node]
        for share in router:
            shares.add(share)
    return len(shares) == index

def compromise_probability(routerdata, index):
    ans = []
    for run in routerdata:
        compromises5 = 0
        compromises10 = 0
        total = 0
        nodes = math.ceil(len(run)/10)
        for _ in range(10000):
            compromised_nodes = []
            while len(compromised_nodes) < nodes:
                rng = random.SystemRandom().randint(0, len(run)-1)
                if rng not in compromised_nodes:
                    compromised_nodes.append(rng)
            if check_compromised(compromised_nodes, run, index):
                compromises10 += 1
            if check_compromised(compromised_nodes[nodes//2:], run, index):
                compromises5 += 1
            total += 1
        ans.append((compromises5 / total, compromises10 / total))
    return ans

        


def calculate_metrics(paths, routerdata, index):
    print("Calculating captures")
    minimum_captures = threshold_setcover(routerdata, index)
    print("Minimum caps:")
    print(minimum_captures)
    print("Calculating path similarity")
    similarity = path_similarity(paths)
    print("Path similarity:")
    print(similarity)
    print("Calculating probability of compromise")
    probability = compromise_probability(routerdata, index)
    print("Probability of compromise:")
    print(probability)


            




def main():
    for fn in FILES:
        for nodes in AMTNODES:
            for run in range(RUNS):
                data, index = getAllFiles(fn + str(nodes) + "_" + str(run) + "_")
                sharePaths, routerShares = getAllRoutes(data, index)
                calculate_metrics(sharePaths, routerShares, index)
    


if __name__ == "__main__":
    main()
