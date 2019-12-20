import requests
import json
import csv
import datetime

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


def DomainReportReader(domain, delay):
    url = "https://www.virustotal.com/api/v3/domains/" + domain + "/resolutions"
    response = requests.request("GET", url, headers=headers, params=querystring)
    #print(response.text)
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
        return data
    
try:
    # read domains from file and pass them to DomainScanner and DomainReportReader
    with open('domains.txt', 'r') as infile:  # keeping the file open because it shouldnt
                                              # be opened/modified during reading anyway
        for domain in infile:
            domain = domain.strip('\n')
            try:
                data = DomainReportReader(domain)
                if data:
                    dataWriter.writerow(data)
                    time.sleep(20)  # wait for VT API rate limiting
            except Exception as err:  # keeping it
                print('Encountered an error but scanning will continue.', err)

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)


