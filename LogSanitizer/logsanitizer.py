#!/bin/python3

import sys
import json

def ParseLine(aLine):
	# Define keys to read
	predefined_keys = [
			["month", "day", "time", "ip", "idk", "timestamp", "hostname", "format"],
			["platform", "application", "application_version", "alert_id", "alert_message", "act_id"],
		]
	predefined_delims = [" ", "|", "="]
	predefined_index = 0

	# Sanitize logs
	while True:
		replacement = aLine.replace("  ", " ")

		# Stop if filtering is done
		if (replacement == aLine):
			break;

		aLine = replacement

	# Initialize key-value pairs
	keyvalue_pairs = []

	# Read log info
	predefined_key_index = 0
	readIt = 0
	key = ""
	value = ""
	logLength = len(aLine)
	standard_delim = predefined_delims[len(predefined_delims)-1]
	isFirstKey = True

	while (readIt < logLength):
		c = aLine[readIt]

		if predefined_index < len(predefined_keys):
			# Predefined keys delimiter found?
			if c == predefined_delims[predefined_index]:
				key = predefined_keys[predefined_index][predefined_key_index]
				#print("Key: {} | Value: {}".format(key, value))
				keyvalue_pairs.append((key,value))
				key = ""
				value = ""
				predefined_key_index += 1

				# Reached cap of predefines?
				if predefined_key_index == len(predefined_keys[predefined_index]):
					predefined_index += 1
					predefined_key_index = 0

			# Transition to new predefined keys?
			elif c == predefined_delims[predefined_index + 1]:
				#print("index: {} | key index: {}".format(predefined_index, predefined_key_index))
				key = predefined_keys[predefined_index][predefined_key_index]
				#print("Key: {} | Value: {}".format(key, value))
				keyvalue_pairs.append((key,value))
				key = ""
				value = ""
				predefined_index += 1
				predefined_key_index = 0
			# No delimiter found - add it to value
			else:
				value += c
		else:
			if c == standard_delim:
				if isFirstKey:
					key = value
					value = ""
					isFirstKey = False
				else:
					#sudo EDITOR\\/=/usr/bin/nano visudo
					#              ^
					i = len(value)

					# Find first space character
					while i > 0:
						i -= 1
						if value[i] == ' ':
							break

					#print("Current key: {}".format(key))
					# Reason is an exception because of the bad logging from CyberArk
					if key != "reason":
						futureKey = value[(i+1):len(value)]
						value = value[0:i]
						value = value.replace('"', '')
						keyvalue_pairs.append((key,value))

						key = futureKey
						value = ""
					elif key == "reason":
						nextKey = "cs1Label"
						if nextKey in value:
							#print("{} found! {}".format(nextKey, value))
							pos = value.find(nextKey)
							value = value[0:pos-1]
							value = value.replace('"', '')
							#print("Key: {} | Value: {}".format(key, value))
							keyvalue_pairs.append((key,value))
							key = nextKey
							value = ""
						else:
							value += c
							#print("Value so far: {}".format(value[0:i]))
					else:
						value += c
			else:
				value += c

		readIt += 1

	#for entry in keyvalue_pairs:
	#	print("\tKey: '{}' Value: '{}'".format(entry[0], entry[1]))
	return keyvalue_pairs

def ParseLog(filePath):
	entries = []

	print("Parsing log...")
	with open(filePath, "r") as f:
		content = f.readlines()
		for line in content:
			entries.append( ParseLine(line) )
			#break # TEMP FOR TESTING

	print("Writing output to json...")
	outFile = "{}.json".format(filePath)
	with open(outFile, "w") as f:
		f.truncate()
		json.dump(entries, f)

	print("All done! Sanitized log file has been written to {}".format(outFile))

def main():
	print(sys.argv)
	if len(sys.argv) < 2:
		printf("Error: Please specify a CyberArk log file to analyze")
	else:
		ParseLog(sys.argv[1])

if __name__ == "__main__":
    # execute only if run as a script
    main()
