#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from scapy.all import *

def readFile(fileName):
   
    retDict={}

    try:
        fileObj = open(fileName, 'r')
    except IOError:
        fileObj = open(fileName, 'w')
        return retDict


    for item in fileObj.readlines():
        pieces = item.rstrip('\n').split(' ')
        
        retDict[pieces[0]] = pieces[1]
        
    fileObj.close()

    return retDict

def writeFile(data, fileName):
    
    fileObj = open(fileName,'w')
  
    for key, value in data.items():
        fileObj.write(key + ' ' + value + '\n')
    
    fileObj.close()
    


def checkMacAddressDifferent(first, second):
   
    retDict = {}

    for fkey, fvalue in first.items():
        for skey, svalue in second.items(): 
                        
            if fkey == skey:
                if fvalue != svalue:
                    retDict.update({fkey:svalue})

    return retDict

def checkMacAddressNew(first, second):

    news = {}
    counter = 0

    for skey, svalue in second.items():
        for fkey, fvalue in first.items():
            if(skey == fkey):
                counter = counter + 1
                
        if(counter == 0):
            news.update({skey: svalue})
        
        counter = 0

    return news


def addNewMacAddress(data, fileName):

    fileObj = open(fileName,'a')
  
    for key, value in data.items():
        fileObj.write(key + ' ' + value + '\n')
    
    fileObj.close()    


def scanner(host):
    
    resultFile = open('temp.txt','w+')
       
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2)

    ans.summary(lambda (s, r): resultFile.write(r.sprintf("%Ether.src% %ARP.psrc% \n")))

    resultFile.close()
    

if __name__ == '__main__':
   
    beforeScanResult = readFile('results.txt')
    
    scanner('192.168.1.*')

    afterScanResult = readFile('temp.txt')

    # newest check
    resultNewest = checkMacAddressNew(beforeScanResult, afterScanResult)
    print 'before: ',  beforeScanResult
    print 'after: ',  afterScanResult
    print resultNewest

    
    if(resultNewest):
        dialogResult = raw_input("There are new mac addresses coming, write them to file?(yes or no): ")
        if dialogResult == 'yes':
            addNewMacAddress(resultNewest, 'results.txt')


    # different check
    resultDifferent = checkMacAddressDifferent(beforeScanResult, afterScanResult)
    print resultDifferent

    if(resultDifferent):
        dialogResult = raw_input("There are differences in mac addresses, write them to file? (yes or no): ")
        if dialogResult == 'yes':

            for key, value in resultDifferent.items():
                beforeScanResult.update({key:value})

            writeFile(beforeScanResult, 'results.txt')
   
