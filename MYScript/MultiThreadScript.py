import requests
import json
import csv
import datetime
import time
import threading 


manish = '5ae5155ef6e433fdb5775309029afa8a94510b4dec73e075180e6751e4716167'
mkrat9 = '0f20084a84b77cb268e9f29c2eedbf5546a03d4242ebdeb028c1f27b5e50c7b0'

querystring = {"limit":"10"}


###########  Start CSV Writer    ###########
try:
    rfile = open('results.csv', 'w+')
    dataWriter = csv.writer(rfile, delimiter = ',')
    header = ['Scan Date', 'Domain','host_name']
    dataWriter.writerow(header)

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)
##########  End Csv header Writr #############


def DomainReportReader(domain , api1):
    headers = {'x-apikey': api1 }
    url = "https://www.virustotal.com/api/v3/domains/" + domain + "/resolutions"
    response = requests.request("GET", url, headers=headers, params=querystring)
    #print(response.text)
    if response.status_code== 200:
        print("Succesful "+ domain +" wait 16 sec for next...")
        read_content = response.json()
        tmp = 0
        for i in read_content['data']:
            ip_address = read_content['data'][tmp]['attributes']['ip_address'] ###Read IP
            host_name = read_content['data'][tmp]['attributes']['host_name'] ###Read host Name
            date = read_content['data'][tmp]['attributes']['date']  ###Read date in number Form
            timestamp = datetime.datetime.fromtimestamp(date) ###Convert date number to Date TimeStamp
            date = timestamp.strftime('%Y-%m-%d %H:%M:%S')  ###Convert TimeStamp to Date formate
            tmp += 1
            data = [date,ip_address,host_name]
            dataWriter.writerow(data)
            
    else:
        print("error  wait 16 sec for next...")
        data = [domain,'NA','NA']
        dataWriter.writerow(data)
    time.sleep(8)  # wait for VT API rate limiting
try:
    # read domains from file and pass them to DomainScanner and DomainReportReader
    with open('domains.txt', 'r') as infile:  # keeping the file open because it shouldnt
                                              # be opened/modified during reading anyway
        for domain in infile:
            domain = domain.strip('\n')
            domain2 = infile.next()
            domain = domain.strip('\n')
            #DomainReportReader(domain,manish)
            t1 = threading.Thread(target=DomainReportReader(domain,manish))  
            t2 = threading.Thread(target=DomainReportReader(domain2,mkrat9))  
            t1.start()
            t2.start() 

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)


def test():
    domain = domain.strip('\n')
    domain2 = infile.next()
    domain = domain.strip('\n')
    #DomainReportReader(domain,manish)
    t1 = threading.Thread(target=DomainReportReader(domain,manish))  
    t2 = threading.Thread(target=DomainReportReader(domain2,mkrat9))  
    t1.start()
    t2.start()   