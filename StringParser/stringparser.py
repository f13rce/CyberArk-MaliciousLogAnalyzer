import json

import os
cwd = os.getcwd()

behavior = {}
originalLogMessages = []

jsonFileExt = ".json"

def GetLogHash(aLog):
    ret = ""
    skippedPre = False
    for entry in aLog:
        if not skippedPre:
            if entry[0] == "event_id":
                skippedPre = True

        if skippedPre:
            ret += entry[0]
            ret += "|||"
            ret += entry[1]
    return ret

def GetLogDifferences(aLog):
    global originalLogMessages

    alertId = ""
    entryList = []
    differences = []

    # Find initial entries
    startAddingEntries = False
    for entry in aLog:
        if entry[0] == "event_id":
            alertId = entry[1]
            startAddingEntries = True

        if startAddingEntries:
            entryList.append(entry)
    
    # Find differences per log
    keyVals = {}
    for log in originalLogMessages:
        isSameId = False
        it = 0
        for entry in log:
            # Find start entry
            if entry[0] == "event_id":
                if entry[1] == alertId:
                    isSameId = True
                else:
                    break
            # Log differences
            if isSameId:
                if not entry[0] in keyVals:
                    keyVals[entry[0]] = [entry[1]]
                else:
                    keyVals[entry[0]].append(entry[1])
                #if not (entry[0] == entryList[it][0] and entry[1] == entryList[it][1]):
                #    differences.append(entryList[it])
                it += 1

    for entry in entryList:
        if entry[0] in keyVals:
            if entry[1] not in keyVals[entry[0]]:
                differences.append(entry)
        else:
            differences = entryList

    for entry in differences:
        if entry[0] == "externalId":
            differences.remove(entry)
    return differences


def LearnFromNormalBehavior(aPath):
    print("Learning normal behavior from {}...".format(aPath))

    contents = ""
    with open(aPath, "r") as f:
        contents = f.read()
    jObj = json.loads(contents)

    global behavior
    global originalLogMessages
    for log in jObj:
        originalLogMessages.append(log)
        hashResult = GetLogHash(log)
        if not hashResult in behavior:
            behavior[hashResult] = 1
        else:
            behavior[hashResult] += 1

def SanitizeLog(aLog):
    ret = ""

    i = 0
    ret += "["
    isFirstLog = True
    for entry in aLog:
        if isFirstLog:
            isFirstLog = False
        else:
            ret += ", "

        ret += '["'
        ret += entry[0].replace("\\", "\\\\")
        ret += '", "'
        ret += entry[1].replace("\\", "\\\\")
        ret += '"]'
    ret += "]"

    return ret

def ScanLogFile(aPath):
    print(f"Scanning log file for suspicious behavior ({aPath})...")

    contents = ""
    with open(aPath, "r") as f:
        contents = f.read()
    jObj = json.loads(contents)

    global behavior
    detectedLogCounts = {}
    detectedLogs = {}
    entryNames = {}

    for log in jObj:
        hashResult = GetLogHash(log)
        if not hashResult in detectedLogCounts:
            detectedLogCounts[hashResult] = 1
            detectedLogs[hashResult] = log

            # Find start entry
            for entry in log:
                if entry[0] == "event_message":
                    entryNames[hashResult] = entry[1]
        else:
            detectedLogCounts[hashResult] += 1

    filePath = aPath[0: len(aPath) - len(jsonFileExt)] + "_suspicious.txt"
    with open(filePath, "w") as f:
        f.truncate()
        f.write("[")

    isFirstLog = True
    # Check what the differences are in this log
    for logHash in detectedLogCounts:
        if not logHash in behavior:
            differences = GetLogDifferences(detectedLogs[logHash])
            if len(differences) >= 1:
                sanitizedLog = SanitizeLog(detectedLogs[logHash])
                #logMsg = "SUSPICIOUS BEHAVIOR: {}".format(entryNames[logHash]) + '\n'
                #logMsg += "\t" + "Differences: {}".format(differences) + '\n'
                #logMsg += "\t" + "Full log: {}".format(detectedLogs[logHash]) + '\n'
                #logMsg += "\t" + "Path: {}".format(aPath) + '\n'
                #print(logMsg)

                with open(filePath, "a") as f:
                    if isFirstLog:
                        isFirstLog = False
                    else:
                         sanitizedLog = ", " + sanitizedLog
                    #sanitizedLog = "[" + sanitizedLog + "]"
                    #sanitizedLog = sanitizedLog.replace("[[[[", "[[[").replace("]]]]", "]]]")
                    f.write(sanitizedLog)
    # Finish json
    with open(filePath, "a") as f:
        f.write("]")

def LearnFromFilesIn(aPath):
    for subdir, dirs, files in os.walk(aPath):
        for file in files:
            filePath = subdir + os.sep + file
            if filePath.endswith("_sanitized.json"):
                LearnFromNormalBehavior(filePath)

def ScanLogsForSuspiciousBehavior(aPath):
    for subdir, dirs, files in os.walk(aPath):
        for file in files:
            filePath = subdir + os.sep + file
            if filePath.endswith("_sanitized.json"):
                ScanLogFile(filePath)

def main():
    scriptPath = os.path.dirname(os.path.realpath(__file__))

    print("Learning from normal behavior...")
    LearnFromFilesIn(scriptPath + "/../Experiments/Normal Behavior/".replace('/', os.sep))
    print("Successfully parsed normal behavior!")

    print("Scanning logs for suspicious behavior...")
    ScanLogsForSuspiciousBehavior(scriptPath + "/../Experiments/Techniques/".replace('/', os.sep))
    ScanLogsForSuspiciousBehavior(scriptPath + "/../Experiments/Additional (PAS and PVWA)/".replace('/', os.sep))
    print("All done!")

if __name__ == "__main__":
    # execute only if run as a script
    main()