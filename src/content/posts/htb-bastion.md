---
title: 'HTB - Arkham'
published: 2019-09-07
draft: false
tags: ['hackthebox', 'bastion', 'htb', 'writeups', 'mRemoteNG', 'smb', 'vhd', 'hash', 'bruteforce']
---
This post is a write-up for the Bastion box on hackthebox.eu
<img data-src="https://res.cloudinary.com/dvi2dcepy/image/upload/w_auto,c_scale,f_auto,q_auto/v1577459106/chadporter.net/HTB/Bastion/BLieUh18xIKESzWo_nqlzgr.png" alt="" caption="Bastion Info" class="cld-responsive">

### Enumeration

Start by enumerating the ports on the victim machine. Run `Masscan` and `Nmap`, then document the results:
```
masscan -e tun0 -p1-65535,U:1-65535 10.10.10.134 --max-rate=500
nmap -n -v -Pn -p80 -A --reason -oN bastion_nmap.txt 10.10.10.134
```
<img data-src="https://res.cloudinary.com/dvi2dcepy/image/upload/w_auto,c_scale,f_auto,q_auto/v1577459106/chadporter.net/HTB/Bastion/ey0zmGeHRMlfspOS_yjcxu9.png" alt="" caption="Running nmap reveals 4 open ports" class="cld-responsive">

Checked port 445 with `smbmap`, and noticed a readable and writable share called Backups:
<img data-src="https://res.cloudinary.com/dvi2dcepy/image/upload/w_auto,c_scale,f_auto,q_auto/v1577459106/chadporter.net/HTB/Bastion/Pe1qC32VoVzXAglG_nppafc.png" alt="" caption="SMBMap shares" class="cld-responsive">

Given that this is a Windows victim, at this point I usually switch over to a Windows VM. I have been using Commando VM 2.0 lately, and I cannot recommend it enough especially for the task of mounting SMB shares.

### User flag
Connect to the share via windows explorer and notice it has 2 .vhd backup files in it. The .vhd backups are quite large, so to make this faster you can simply mount them over the smb share:
<img data-src="https://res.cloudinary.com/dvi2dcepy/image/upload/w_auto,c_scale,f_auto,q_auto/v1577459106/chadporter.net/HTB/Bastion/UUH6FqB7OD5r2Y11_brcewb.png" alt="" caption="vhd mount" class="cld-responsive">

You should be able to read the backup of the c drive from `L4mpje`. Digging through the backup did not result in anything interesting, but you can pull the `SAM` and `SYSTEM` file from `C:\windows\system32\config` to the attacking machine for some hash cracking fun:
```
pwdump SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```

Use hashkiller to bruteforce the hashed password of user `L4mpje`
```
L4mpje:bureaulampje
```

SSH into the victim machine with the credentials to get the user flag:
<img data-src="https://res.cloudinary.com/dvi2dcepy/image/upload/w_auto,c_scale,f_auto,q_auto/v1577459106/chadporter.net/HTB/Bastion/Mk4dXNfshmTEcLAm_n22fot.png" alt="" caption="user flag" class="cld-responsive">

### Root Flag
Enumerate the victim machine, and locate an application called `mRemoteNG`.

`mRemoteNG` manages connections (to ssh, rdp, ftp, etc.) and saves the connection details in an xml, including the encrypted saved credentials. It saves these encrypted secrets in `C:\users\l4mpje\AppData\Roaming\mRemoteNG\confCons.xml`. We could attempt to bruteforce these, but that might take a long time.

Easier method: Install `mRemoteNG` on the attackimg machine and copy in the `confCons.xml` file.

Connect as administrator to the victim machine (change the IP & Protocol accordingly).
<img data-src="https://res.cloudinary.com/dvi2dcepy/image/upload/w_auto,c_scale,f_auto,q_auto/v1577459106/chadporter.net/HTB/Bastion/KBTK23je0i9xWY91_c59t60.png" alt="" caption="root flag" class="cld-responsive">