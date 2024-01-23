import pyshark
import pickle
import os
import datetime
import math
import random
import copy

FILEPATH = "/home/ubuntu/SSS_Testing_Materials/Routing/Logs"

SSSPORT = "11111"

FILES = ["line_graph", "mesh_graph", "full_random", "manual_configuration"]
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
        if(len(run)) == 0:
            continue
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

def threshold_setcover(routerdatain, thresholdin, index):
    routerdata = copy.deepcopy(routerdatain)
    ans = []
    for j in range(len(routerdata)):
        run = routerdata[j]
        thresholds = copy.deepcopy(thresholdin)
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
    overlap = len([v for v in a if v in b]) - 1
    total = len(set(a+b)) - 1
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

def check_compromised(compromised_nodes, routers):
    shares = set()
    for compromised_node in compromised_nodes:
        router = routers[compromised_node]
        for share in router:
            shares.add(share)
    return len(shares)

def compromise_probability(fn, paths, routerdata, index):
    ansSec = []
    ansAva = []
    for i in range(len(routerdata)):
        run = routerdata[i]
        path_run = paths[i]
        ignored = path_run[0][-1]
        if fn == "manual_configuration":
            ignored = -1
        compromises5 = [0, 0, 0]
        compromises10 = [0, 0, 0]
        availability5 = [0, 0, 0]
        availability10 = [0, 0, 0]
        nosss5 = 0
        nosss10 = 0
        total = 0
        nossstotal = 0
        nodes = math.ceil(len(run)/10)
        for _ in range(10000):
            compromised_nodes = []
            while len(compromised_nodes) < nodes:
                rng = random.SystemRandom().randint(0, len(run)-1)
                if rng not in compromised_nodes and rng != ignored:
                    compromised_nodes.append(rng)
            full = check_compromised(compromised_nodes, run)
            half = check_compromised(compromised_nodes[nodes//2:], run)
            if full >= math.ceil(index/2):
                compromises10[0] += 1
            if full >= math.ceil(3*index/4):
                compromises10[1] += 1
            if full >= index:
                compromises10[2] += 1
            if half >= math.ceil(index/2):
                compromises5[0] += 1
            if half >= math.ceil(3*index/4):
                compromises5[1] += 1
            if half >= index:
                compromises5[2] += 1
            if full >= index + 1 - math.ceil(index/2):
                availability10[0] += 1
            if full >= index + 1 - math.ceil(3*index/4):
                availability10[1] += 1
            if full >= index + 1 - index:
                availability10[2] += 1
            if half >= index + 1 - math.ceil(index/2):
                availability5[0] += 1
            if half >= index + 1 - math.ceil(3*index/4):
                availability5[1] += 1
            if half >= index + 1 - index:
                availability5[2] += 1
            for p in path_run:
                for j, n in enumerate(compromised_nodes):
                    added5, added10 = False, False
                    if n in p:
                        if j < nodes / 2 and not added5:
                            nosss5 += 1
                            added5 = True
                        if not added10:
                            nosss10 += 1
                            added10 = True
                nossstotal += 1
            total += 1
        ansSec.append([[x/total for x in compromises5], [x/total for x in compromises10], nosss5 / nossstotal, nosss10 / nossstotal])
        ansAva.append([[x/total for x in availability5], [x/total for x in availability10], nosss5 / nossstotal, nosss10 / nossstotal])
    return ansSec, ansAva

        


def calculate_metrics(fn, paths, routerdata, index):
    minimum_captures_security = threshold_setcover(routerdata, [17, 22, 28, 33], index)
    minimum_captures_availability = threshold_setcover(routerdata, [1, 6, 12, 17], index)
    print("Minimum caps:")
    print(minimum_captures_security)
    print(minimum_captures_availability)
    similarity = path_similarity(paths)
    print("Path similarity:")
    print(similarity)
    probability_security, probability_availability = compromise_probability(fn, paths, routerdata, index)
    print("Probability of compromise:")
    print(probability_security)
    print(probability_availability)
    return minimum_captures_security, minimum_captures_availability, similarity, probability_security, probability_availability

def threedimarrayavg(arr):
    result = []
    for i in range(len(arr[0])):
        result.append([])
        for j in range(len(arr[0][0])):
            result[i].append(0)
    for file in range(len(arr)):
        for run in range(len(arr[0])):
            for elem in range(len(arr[0][0])):
                result[run][elem] += arr[file][run][elem]
    for i in range(len(result)):
        for j in range(len(result[0])):
            result[i][j] = result[i][j]/len(arr)
    return result

def threedimarrayavgcompromise(arr):
    result = []
    for i in range(len(arr[0])):
        result.append([])
        for j in range(0, 2):
            result[i].append([])
            for k in range(3):
                result[i][j].append(0)
        for j in range(2, len(arr[0][0])):
            result[i].append(0)
    for file in range(len(arr)):
        for run in range(len(arr[0])):
            for elem in range(len(arr[0][0])):
                if elem < 2:
                    for arrelem in range(len(arr[0][0][0])):
                        result[run][elem][arrelem] += arr[file][run][elem][arrelem]
                else:
                    result[run][elem] += arr[file][run][elem]
    for i in range(len(result)):
        for j in range(0, 2):
            for k in range(len(result[0][0])):
                result[i][j][k] = result[i][j][k]/len(arr)
        for j in range(2, len(result[0])):
            result[i][j] = result[i][j]/len(arr)
    return result

def twodimarrayavg(arr):
    result = []
    for i in range(len(arr[0])):
        result.append(0)
    for i in range(len(arr)):
        for j in range(len(arr[0])):
            result[j] += arr[i][j]
    for i in range(len(result)):
        result[i] = result[i]/len(arr)
    return result

            

def avg_metrics_over_test(fn, mincapsec, mincapava, pathsim, probsec, probava):
    #Minimum captures
    print()
    print("For group " + str(fn) + " the averages are: ")
    print("Minimum captures average: ")
    mincapsecavg = threedimarrayavg(mincapsec)
    mincapavaavg = threedimarrayavg(mincapava)
    print(mincapsecavg)
    print(mincapavaavg)
    #Path similarity
    print("Path similarity average: ")
    pathsimavg = twodimarrayavg(pathsim)
    print(pathsimavg)
    #Probability
    print("Probabilities of compromise: ")
    probsecavg = threedimarrayavgcompromise(probsec)
    probavaavg = threedimarrayavgcompromise(probava)
    print(probsecavg)
    print(probavaavg)
    return 0



def main():
    for fn in FILES:
        for nodes in AMTNODES:
            if fn == "line_graph":
                runs = range(RUNS)
            else:
                runs = range(3*RUNS)
            if nodes != 200 or fn == "line_graph":
                mincapsec = []
                mincapava = []
                pathsim = []
                probsec = []
                probava = []
                for run in runs:
                    data, index = getAllFiles(fn + str(nodes) + "_" + str(run) + "_")
                    sharePaths, routerShares = getAllRoutes(data, index)
                    mcs, mca, sim, pcs, pca = calculate_metrics(fn, sharePaths, routerShares, index)
                    mincapsec.append(mcs)
                    mincapava.append(mca)
                    pathsim.append(sim)
                    probsec.append(pcs)
                    probava.append(pca)
                if fn == "line_graph":
                    avg_metrics_over_test(fn + str(nodes), mincapsec, mincapava, pathsim, probsec, probava)
                elif fn == "manual_configuration":
                    pass
                else:
                    for i in range(3):
                        avg_metrics_over_test(fn + str(nodes) + "_" + str(i), mincapsec[i::3], mincapava[i::3], pathsim[i::3], probsec[i::3], probava[i::3])

    


if __name__ == "__main__":
    main()
