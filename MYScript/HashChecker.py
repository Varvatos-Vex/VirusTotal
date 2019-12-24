import requests
import json
import csv
import datetime
import time

querystring = {"limit":"10"}
headers = {'x-apikey': '5ae5155ef6e433fdb5775309029afa8a94510b4dec73e075180e6751e4716167'}

###########  Start CSV Writer    ###########
try:
    rfile = open('resultHashes.csv', 'w+')
    dataWriter = csv.writer(rfile, delimiter = ',')
    header = ['Hashes', 'Derived IP','Country','as_owner','Date','Remark']
    dataWriter.writerow(header)

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)
##########  End Csv header Writr #############


def hashesReportReader(hashes):
    url = "https://www.virustotal.com/api/v3/files/" + hashes +"/contacted_ips"
    response = requests.request("GET", url, headers=headers, params=querystring)
    #print(response.text)
    if response.status_code== 200:
        read_content = response.json()
        #print(read_content['data'])
        if len(read_content['data']) != 0:
            tmp = 0
            for i in read_content['data']:
                ip_address = read_content['data'][tmp]['id']
                country = read_content['data'][tmp]['attributes']['country']
                Owner = read_content['data'][tmp]['attributes']['as_owner']
                date =  read_content['data'][tmp]['attributes']['whois_date']
                timestamp = datetime.datetime.fromtimestamp(date) ###Convert date number to Date TimeStamp
                Date = timestamp.strftime('%Y-%m-%d %H:%M:%S')  ###Convert TimeStamp to Date formate
                #print(ip_address)
                data = [hashes,ip_address,country,Owner,Date]
                dataWriter.writerow(data)
                tmp += 1
        else:                                               #Add Remark for Node
            #print("Empty")
            data = [hashes,'NA','NA','NA','NA','Node Only']
            dataWriter.writerow(data)
    else:
        data = [hashes,'NA','NA','NA','NA','Not Found']
        dataWriter.writerow(data)
try:
    # read hashess from file and pass them to hashesScanner and hashesReportReader
    with open('hashes.txt', 'r') as infile:  # keeping the file open because it shouldnt
                                              # be opened/modified during reading anyway
        for hashes in infile:
            hashes = hashes.strip('\n')
            hashesReportReader(hashes)
            print("Succesful..... wait 16 sec for prevent API hit level")
            time.sleep(16)  # wait for VT API rate limiting
except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)
print("Done")

