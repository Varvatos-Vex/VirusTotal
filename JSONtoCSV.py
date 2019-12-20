import json
import requests.packages.urllib3
import csv
import datetime

with open('output.json') as access_json:
    read_content = json.load(access_json)
tmp = 0


###########  For CSV Writer    ###########
try:
    rfile = open('results.csv', 'w+')
    dataWriter = csv.writer(rfile, delimiter = ',')
    header = ['Scan Date', 'Domain','host_name']
    dataWriter.writerow(header)

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)


################ loop for Single Data ###########
for i in read_content['data']:
    ip_address = read_content['data'][tmp]['attributes']['ip_address'] ###Read IP
    host_name = read_content['data'][tmp]['attributes']['host_name'] ###Read host Name
    date = read_content['data'][tmp]['attributes']['date']  ###Read date in number Form
    timestamp = datetime.datetime.fromtimestamp(date) ###Convert date number to Date TimeStamp
    date = timestamp.strftime('%Y-%m-%d %H:%M:%S')  ###Convert TimeStamp to Date formate
    tmp += 1
    data = [date,ip_address,host_name]
    if data:
        dataWriter.writerow(data)
    
