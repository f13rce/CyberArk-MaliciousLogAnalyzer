# CyberArk-MaliciousLogAnalyzer

Machine learning and string parsing tool to identify and classify malicious logs correlating to attack techniques.
 
# What is this?

This repository entails the source code from the research regarding the generated logs from CyberArk. Our goal was to identify these logs in order to classify them as either malicious or normal behavior, as well as identifying the attack technique that was used in the malicious events.

For this research we have tested two approaches: string parsing and machine learning.

The string parsing technique takes in normal behavioral logs and matches suspicious and malicious logs to find anomalies. Our sample logs have been added in the Experiments directory.

The machine learning technique learns from the normal behavior by using a bag of words per log entry field. By collecting the values of these fields, the network is able to take in the word frequencies based on the total amount of occurances that this value has for all of the logs. By doing so, the network can be trained to find anomalies and therefore detect malicious behavior.

# Requirements

For the string parser, python3 is required with no additional packages that come outside of the base installation. The code has been tested on Windows 10, but likely works on Unix-based operating systems as well.

For the neural network code, the experimental C++17 is required with the support of the experimental filesystem component. The code is written cross-platform compatibility in mind and has been tested on Windows 10 and Ubuntu 18.04.4.

# Read more about this project

See our presentation slides to get a general idea of what has been done: https://rp.delaat.net/2019-2020/p15/presentation.pdf 

Read the report to view all of the information: https://rp.delaat.net/2019-2020/p15/report.pdf 