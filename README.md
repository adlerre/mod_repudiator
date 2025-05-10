# mod_repudiator - Reputation-based limiting/blocking of malicious clients

## Requirements

Installed headers for __apache2__, __libmaxminddb__ and optional for __pcre2__. 
Download the ASN database with __geoipupdate__.

RHEL based

```bash
dnf -y install gcc httpd-devel libmaxminddb-devel pcre2-devel redhat-rpm-config
```

Debian/Ubuntu

```bash
apt -y install gcc apache2-dev libmaxminddb-dev libpcre2-dev
```

## Build

```bash
apxs -c -lmaxminddb mod_repudiator.c
```

With __pcre2__ support

```bash
apxs -c -DPCRE2 -lmaxminddb -lpcre2-8 mod_repudiator.c
```

Debug build

```bash
apxs -c -DPCRE2 -DREP_DEBUG -lmaxminddb -lpcre2-8 mod_repudiator.c
```

## Modul config

* **RepudiatorEnabled**<br />
  *Default:* `false`

  Enable module

* **RepudiatorEvilModeEnabled**<br />
  *Default:* `false`

  Let's get mad!

* **RepudiatorEvilRedirectURL**<br />
  *Default:* `NULL`

  Redirect the bad boy to this URL

* **RepudiatorWarnReputation**<br />
  *Default:* `-200`

  Reputation warning score

* **RepudiatorBlockReputation**<br/>
  *Default:* `-400`

  Reputation blocking score

* **RepudiatorPerIPReputation**<br/>
  *Default:* `-0.033`

  Reputation score per IP address

* **RepudiatorPerNetReputation**<br/>
  *Default:* `-0.0033`

  Reputation score per IP address within network

* **RepudiatorPerASNReputation**<br/>
  *Default:* `-0.00033`

  Reputation score per IP address within ASN block

* **RepudiatorScanTime**<br/>
  *Default:* `60`

  Scan time in seconds

* **RepudiatorWarnHttpReply**<br/>
  *Default:* `429`

  HTTP status code if warning score is reached

* **RepudiatorBlockHttpReply**<br/>
  *Default:* `403`

  HTTP status code if blocking score is reached

* **RepudiatorASNDatabase**<br/>

  Path to GeoLite2 ASN database

* **RepudiatorIPReputation**<br/>
  *iterable*

  Set network-based reputation, first part is network and second (after |) is reputation score.<br />
  *Example:*<br />
  `RepudiatorIPReputation 192.168.0.0/16|1000.0`

* **RepudiatorUAReputation**<br/>
  *iterable*

  Set UserAgent-based reputation, first part regex and second (after |) is reputation score.<br />
  *Example:*<br />
  `RepudiatorUAReputation "/.*MSIE [1-9].0.*/|-400.0"`

* **RepudiatorURIReputation**<br/>
  *iterable*

  Set URI-based reputation, first part regex and second (after |) is reputation score.<br />
  *Example:*<br />
  `RepudiatorURIReputation "/.*\.(env|git|bash(rc|_(history|profile))).*/|-1000.0"`

* **RepudiatorASNReputation**<br/>
  *iterable*

  Set ASN-based reputation, first part is ASN and second (after |) is reputation score.<br />
  *Example:*<br />
  `RepudiatorASNReputation 15169|100.0`

* **RepudiatorRCReputation**<br />
  *iterable*
  
  Set HTTP-Return-Code-based reputaion, first part status code (after |) is reputation score.<br />
  *Example:*<br />
  `RepudiatorRCReputation 404|-1.0`

## Let's ban these bad guys

Install __fail2ban__ and add custom jail.

```bash
cp fail2ban/filter.d/apache-mod_repudiator.conf /etc/fail2ban/filter.d/

cat >> /etc/fail2ban/jail.local << EOF
[apache-mod_repudiator]
enabled = true
backend = polling
port    = http,https
filter  = apache-mod_repudiator
logpath = /var/log/httpd/error_log
maxretry = 1
findtime = 120
bantime  = 600
EOF

systemctl restart fail2ban
```
