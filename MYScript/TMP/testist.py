import requests
import json
import csv
import datetime
import time

querystring = {"limit":"10"}
headers = {'x-apikey': '5ae5155ef6e433fdb5775309029afa8a94510b4dec73e075180e6751e4716167'}

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


def DomainReportReader(domain):
    url = "https://www.virustotal.com/api/v3/domains/" + domain + "/relationship"
    response = requests.request("GET", url, headers=headers, params=querystring)
    print(response.text)

try:
    # read domains from file and pass them to DomainScanner and DomainReportReader
    with open('domains.txt', 'r') as infile:  # keeping the file open because it shouldnt
                                              # be opened/modified during reading anyway
        for domain in infile:
            domain = domain.strip('\n')
            DomainReportReader(domain)
            print("Succesful..... wait 20 sec")
            #time.sleep(20)  # wait for VT API rate limiting
except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)


