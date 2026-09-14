# mod_repudiator

<img src="templates/src/assets/simple-logo.svg" alt="Logo" style="width: 200px; height: 200px">

**mod_repudiator** is an Apache HTTP Server module for reputation-based
limiting and blocking of potentially malicious clients.

The module evaluates incoming HTTP requests using several reputation sources:

- client IP address and configured IP/network ranges
- User-Agent regular expressions
- requested URI regular expressions
- Autonomous System Number (ASN)
- country code
- HTTP response status codes
- request frequency per IP, network and ASN

Depending on the resulting reputation score, a client is classified as
`OK`, `WARN` or `BLOCK`. Clients in the configurable intermediate range can
optionally be challenged with a Proof-of-Work (POW) challenge.

The module is implemented as an Apache module in C and uses Apache Portable
Runtime (APR), libmaxminddb and, optionally, PCRE2.

## Features

- Apache HTTP Server module using the Apache module API
- IPv4 and IPv6 support
- configurable reputation rules
- IP/CIDR-based reputation
- User-Agent regex reputation
- URI regex reputation
- ASN-based reputation
- country-based reputation
- HTTP status-based reputation
- request counters per IP, network and ASN
- configurable warning and blocking thresholds
- configurable HTTP response codes
- optional Proof-of-Work challenge
- MaxMind database integration for ASN and country lookups
- optional PCRE2 regex engine
- `X-Reputation` response header
- optional debug logging
- fail2ban integration

## How reputation works

For every request, the module determines the client IP and, when configured,
looks up the corresponding ASN and country using MaxMind databases.

The configured reputation components are accumulated and combined with
frequency-based penalties.

Conceptually, the resulting score consists of:

```text
basic reputation
+ per-IP reputation
+ per-network reputation
+ per-ASN reputation
+ HTTP-status reputation
```

The basic reputation is calculated from the configured IP, User-Agent, URI,
ASN and country rules.

For repeated requests, the configured per-IP, per-network and per-ASN
penalties are applied according to the request counters.

By default, negative values represent undesirable behaviour while positive
values can be used to explicitly increase reputation.

### Default thresholds

| Setting | Default | Meaning |
|---|---:|---|
| `RepudiatorWarnReputation` | `-200` | Warning threshold |
| `RepudiatorBlockReputation` | `-400` | Blocking threshold |
| `RepudiatorPerIPReputation` | `-0.033` | Penalty per IP request |
| `RepudiatorPerNetReputation` | `-0.0033` | Penalty per network request |
| `RepudiatorPerASNReputation` | `-0.00033` | Penalty per ASN request |
| `RepudiatorScanTime` | `60` | Request counting interval in seconds |

The module supports both the usual configuration where the block threshold is
lower than the warning threshold and the inverse ordering.

## Proof-of-Work challenge

Requests whose reputation falls into the configured POW range can be redirected
to a challenge endpoint.

The default endpoint is:

```text
/rep-pow-challenge
```

The challenge contains a random token and a difficulty value. The client has
to find a numeric solution whose SHA-256 hash contains at least the required
number of leading zero bits.

A successful solution creates the `REP-PASSED` cookie. The cookie contains the
client IP and is valid for the configured period.

The default POW settings are:

| Setting | Default |
|---|---:|
| `RepudiatorPOWUri` | `/rep-pow-challenge` |
| `RepudiatorPOWCookieMaxAge` | `3600` seconds |
| `RepudiatorPOWAboveReputation` | `-150.0` |
| `RepudiatorPOWBelowReputation` | `-1000.0` |

The challenge template is supplied through `RepudiatorPOWTemplateFile`.

The module also performs basic client-information checks. For example,
clients reporting WebDriver/headless operation, disabled cookies, zero
hardware concurrency, a `0x0` screen resolution or zero colour depth are
rejected by the POW validation path.

## Requirements

The following development packages are required:

- Apache HTTP Server development headers
- GCC or another compatible C compiler
- libmaxminddb development headers
- MaxMind GeoLite2 ASN database
- MaxMind GeoLite2 Country database when country reputation is used
- PCRE2 development headers when PCRE2 support is enabled

The source also includes the following implementation files directly:

```text
json.c
sha256.c
pow_template.c
state_template.c
```

Therefore these files must be available in the source directory when building
`mod_repudiator.c`.

### RHEL / Fedora based systems

```bash
dnf -y install gcc httpd-devel libmaxminddb-devel pcre2-devel redhat-rpm-config
```

### Debian / Ubuntu

```bash
apt -y install gcc apache2-dev libmaxminddb-dev libpcre2-dev
```

## MaxMind databases

The module uses libmaxminddb to obtain:

- ASN information from the `autonomous_system_number` field
- country information from `country.iso_code`

The original project documentation recommends obtaining the ASN database
with `geoipupdate`.

Example configuration:

```apache
RepudiatorASNDatabase /path/to/GeoLite2-ASN.mmdb
RepudiatorCountryDatabase /path/to/GeoLite2-Country.mmdb
```

If no matching MaxMind entry is found, the module falls back to a host-specific
network mask (`/32` for IPv4 or `/128` for IPv6).

## Build

### Standard build

```bash
apxs -c -lmaxminddb mod_repudiator.c
```

### Build with PCRE2

```bash
apxs -c -DPCRE2 -lmaxminddb -lpcre2-8 mod_repudiator.c
```

PCRE2 is used instead of the POSIX `regex.h` implementation when the
`PCRE2` preprocessor symbol is defined.

### Debug build

```bash
apxs -c -DPCRE2 -DREP_DEBUG -lmaxminddb -lpcre2-8 mod_repudiator.c
```

With `REP_DEBUG`, the module emits extended reputation information to the
Apache error log.

## Apache configuration

A minimal configuration looks like this:

```apache
LoadModule repudiator_module modules/mod_repudiator.so

RepudiatorEnabled true

RepudiatorASNDatabase /path/to/GeoLite2-ASN.mmdb
RepudiatorCountryDatabase /path/to/GeoLite2-Country.mmdb

RepudiatorWarnReputation -200
RepudiatorBlockReputation -400
```

The module configuration commands are restricted to server configuration
contexts (`RSRC_CONF`), i.e. they are intended for the Apache server or
virtual-host configuration.

After changing the Apache configuration, validate it before restarting:

```bash
apachectl configtest
```

Then restart Apache using the service mechanism of the operating system, for
example:

```bash
systemctl restart httpd
```

or:

```bash
systemctl restart apache2
```

## Configuration reference

### Module activation

#### `RepudiatorEnabled`

Enables or disables the module.

Default:

```apache
RepudiatorEnabled false
```

Accepted values:

```apache
RepudiatorEnabled true
RepudiatorEnabled false
```

Invalid values disable the module and are logged as warnings.

### Reputation thresholds

#### `RepudiatorWarnReputation`

Sets the warning threshold.

Default:

```apache
RepudiatorWarnReputation -200
```

#### `RepudiatorBlockReputation`

Sets the blocking threshold.

Default:

```apache
RepudiatorBlockReputation -400
```

The threshold comparison adapts to the ordering of the two configured values.

### Frequency penalties

#### `RepudiatorPerIPReputation`

Reputation penalty per request from the same IP within the scan window.

Default:

```apache
RepudiatorPerIPReputation -0.033
```

#### `RepudiatorPerNetReputation`

Reputation penalty based on request frequency within the network returned by
the MaxMind lookup.

Default:

```apache
RepudiatorPerNetReputation -0.0033
```

#### `RepudiatorPerASNReputation`

Reputation penalty based on request frequency within the ASN.

Default:

```apache
RepudiatorPerASNReputation -0.00033
```

#### `RepudiatorScanTime`

Defines the request counting interval in seconds.

Default:

```apache
RepudiatorScanTime 60
```

ASN and network counters older than twice the scan interval are cleaned up.

### IP reputation

#### `RepudiatorIPReputation`

Adds a reputation value for an IP address or CIDR network.

The directive can be specified multiple times.

Example:

```apache
RepudiatorIPReputation 192.168.0.0/16 1000.0
RepudiatorIPReputation 203.0.113.42 -500.0
RepudiatorIPReputation 2001:db8::/32 -100.0
```

Both IPv4 and IPv6 are supported.

Multiple matching IP rules contribute to the resulting reputation.

### User-Agent reputation

#### `RepudiatorUAReputation`

Adds a reputation value when the User-Agent matches a regular expression.

Example:

```apache
RepudiatorUAReputation ".*MSIE [1-9].0.*" -400.0
```

The regular expression engine is:

- PCRE2 when compiled with `-DPCRE2`
- POSIX extended regular expressions otherwise

### URI reputation

#### `RepudiatorURIReputation`

Adds a reputation value when the requested URI matches a regular expression.

Example:

```apache
RepudiatorURIReputation ".*\\.(env|git|bash(rc|_(history|profile))).*" -1000.0
```

Multiple URI rules can be configured.

### ASN reputation

#### `RepudiatorASNReputation`

Adds a reputation value for a specific ASN.

Example:

```apache
RepudiatorASNReputation 15169 100.0
```

ASN `0` can be used as a fallback/default ASN rule when no more specific
matching ASN is configured.

### Country reputation

#### `RepudiatorCountryReputation`

Adds a reputation value for a country identified by its ISO country code.

Example:

```apache
RepudiatorCountryReputation DE 100.0
RepudiatorCountryReputation CN -100.0
```

Country matching is case-insensitive.

### HTTP status reputation

#### `RepudiatorStatusReputation`

Adds a reputation value based on the HTTP response status.

The accepted status range is `99` through `599`.

Example:

```apache
RepudiatorStatusReputation 404 -1.0
RepudiatorStatusReputation 500 -10.0
```

The status contribution is evaluated when the response filters process the
request.

### HTTP response codes

#### `RepudiatorWarnHttpReply`

HTTP status returned when the warning threshold is reached.

Default:

```apache
RepudiatorWarnHttpReply 429
```

#### `RepudiatorBlockHttpReply`

HTTP status returned when the blocking threshold is reached.

Default:

```apache
RepudiatorBlockHttpReply 403
```

### State template

#### `RepudiatorStateTemplateFile`

Loads an HTML template used when a request reaches `WARN` or `BLOCK`.

Example:

```apache
RepudiatorStateTemplateFile /path/to/state.html
```

The template can contain the following placeholder:

```text
{JSON}
```

The placeholder is replaced with JSON containing the current reputation
information.

The generated data includes:

```json
{
  "state": "warn",
  "warn": -200.00,
  "block": -400.00,
  "ip": 0.00,
  "asn": 0.00,
  "ua": 0.00,
  "uri": 0.00,
  "country": 0.00,
  "status": 0.00,
  "perIp": 0.00,
  "perNet": 0.00,
  "perASN": 0.00
}
```

The repository is expected to contain example templates in a `templates/`
directory.

### POW configuration

#### `RepudiatorPOWUri`

Sets the POW challenge URI.

Default:

```apache
RepudiatorPOWUri /rep-pow-challenge
```

Example:

```apache
RepudiatorPOWUri /pow-challenge
```

#### `RepudiatorPOWTemplateFile`

Loads the HTML template used by the POW challenge.

Example:

```apache
RepudiatorPOWTemplateFile /path/to/pow.html
```

The template uses the following placeholder:

```text
{TOKEN}
```

The placeholder receives a Base64 encoded JSON challenge token.

#### `RepudiatorPOWDifficulty`

Sets the difficulty of the POW challenge.

Default:

```apache
RepudiatorPOWDifficulty 16
```

Example:

```apache
RepudiatorPOWDifficulty 8
```

#### `RepudiatorPOWCookieMaxAge`

Sets the lifetime of the successful POW cookie in seconds.

Default:

```apache
RepudiatorPOWCookieMaxAge 3600
```

Example:

```apache
RepudiatorPOWCookieMaxAge 1800
```

#### `RepudiatorPOWAboveReputation`

Sets the upper reputation boundary of the POW range.

Default:

```apache
RepudiatorPOWAboveReputation -150.0
```

#### `RepudiatorPOWBelowReputation`

Sets the lower reputation boundary of the POW range.

Default:

```apache
RepudiatorPOWBelowReputation -1000.0
```

A request enters the POW flow when:

```text
reputation < RepudiatorPOWAboveReputation
AND
reputation >= RepudiatorPOWBelowReputation
```

## Example configuration

The following example combines several reputation sources:

```apache
LoadModule repudiator_module modules/mod_repudiator.so

RepudiatorEnabled true

RepudiatorASNDatabase /var/lib/GeoIP/GeoLite2-ASN.mmdb
RepudiatorCountryDatabase /var/lib/GeoIP/GeoLite2-Country.mmdb

RepudiatorWarnReputation -200
RepudiatorBlockReputation -400

RepudiatorPerIPReputation -0.033
RepudiatorPerNetReputation -0.0033
RepudiatorPerASNReputation -0.00033
RepudiatorScanTime 60

RepudiatorWarnHttpReply 429
RepudiatorBlockHttpReply 403

RepudiatorIPReputation 192.168.0.0/16 1000.0
RepudiatorIPReputation 203.0.113.0/24 -100.0

RepudiatorUAReputation ".*MSIE [1-9].0.*" -400.0
RepudiatorURIReputation ".*\\.(env|git|bash(rc|_(history|profile))).*" -1000.0

RepudiatorASNReputation 15169 100.0
RepudiatorCountryReputation DE 100.0
RepudiatorStatusReputation 404 -1.0

RepudiatorPOWUri /rep-pow-challenge
RepudiatorPOWCookieMaxAge 3600
RepudiatorPOWAboveReputation -150
RepudiatorPOWBelowReputation -1000

RepudiatorStateTemplateFile /path/to/templates/state.html
RepudiatorPOWTemplateFile /path/to/templates/pow.html
```

## Request processing

The relevant processing path is:

```text
HTTP request
    |
    v
Client IP detection
    |
    +--> MaxMind ASN lookup
    |
    +--> MaxMind country lookup
    |
    +--> IP reputation rules
    +--> User-Agent reputation rules
    +--> URI reputation rules
    +--> ASN reputation rules
    +--> Country reputation rules
    |
    +--> IP/network/ASN request counters
    |
    v
Calculate total reputation
    |
    +--> OK
    |
    +--> POW range --> POW challenge
    |
    +--> WARN --> configured warning response
    |
    +--> BLOCK --> configured blocking response
    |
    v
Response filters
    |
    +--> X-Reputation header
    +--> HTTP status reputation
```

The module registers its access checks with Apache and also installs output and
error filters. These filters add the `X-Reputation` header and feed the final
HTTP response status back into the reputation calculation.

## `X-Reputation` header

For requests already tracked by the module, the response can contain:

```text
X-Reputation: WARN (-250.00)
```

Possible states are:

```text
OK
WARN
BLOCK
```

The header therefore provides a convenient way to expose the current
classification and score to downstream components.

## Logging

The module logs reputation decisions through the Apache error log.

A normal log entry contains information such as:

- client IP
- network mask
- ASN
- country
- hostname
- requested URI
- User-Agent
- reputation state
- total reputation score

A build with `REP_DEBUG` additionally logs the individual reputation
components and request counters.

## fail2ban integration

The repository can be integrated with fail2ban to ban clients that are
reported by the Apache module.

Install the supplied filter:

```bash
cp fail2ban/filter.d/apache-mod_repudiator.conf /etc/fail2ban/filter.d/
```

Then add a jail to `/etc/fail2ban/jail.local`:

```ini
[apache-mod_repudiator]
enabled = true
backend = polling
port    = http,https
filter  = apache-mod_repudiator
logpath = /var/log/httpd/error_log
maxretry = 1
findtime = 120
bantime  = 600
```

Restart fail2ban:

```bash
systemctl restart fail2ban
```

Adjust `logpath` for systems where Apache uses a different error-log location.

## Source layout

The main implementation is contained in:

```text
mod_repudiator.c
```

The module directly includes several source files:

```text
json.c
sha256.c
pow_template.c
state_template.c
...
```

A typical repository layout is:

```text
.
├── mod_repudiator.c
├── json.c
├── sha256.c
├── pow_template.c
├── state_template.c
├── templates/
├── fail2ban/
│   └── filter.d/
│       └── apache-mod_repudiator.conf
└── README.md
```

## Memory and lifetime considerations

The module maintains request, network and ASN counters in dynamically allocated
vectors. Network and ASN counters are periodically removed when they have not
been seen for twice the configured scan interval.

Configuration cleanup releases the dynamically allocated reputation vectors,
regular expressions, request/network/ASN vectors and configured strings.
MaxMind databases are registered with APR pool cleanup handlers.

Because the module runs inside the Apache process, memory handling errors can
affect the complete Apache worker process. Production deployments should
therefore be tested with the intended Apache MPM and representative traffic.

## Security considerations

`mod_repudiator` is a traffic-control mechanism and should be treated as one
layer of a broader security architecture.

Recommended practices include:

- keep MaxMind databases up to date
- carefully test reputation thresholds before enabling blocking
- whitelist trusted networks using positive reputation where appropriate
- test regular expressions against representative User-Agent and URI values
- monitor Apache logs for false positives
- validate Apache configuration before reload/restart
- use fail2ban only after confirming that the generated log events are correct
- test the POW templates and redirect handling before deployment

The module derives its client IP from Apache's request connection information.
If Apache is deployed behind a reverse proxy, load balancer or another
forwarding layer, the Apache client-IP configuration must be correct before
using reputation decisions based on the client address.

## Development

A useful development build is:

```bash
apxs -c -DPCRE2 -DREP_DEBUG -lmaxminddb -lpcre2-8 mod_repudiator.c
```

After installation, verify:

```bash
apachectl configtest
```

Then inspect the Apache error log while generating test traffic.

When changing reputation rules, test at least:

- IPv4 addresses
- IPv6 addresses
- CIDR networks
- matching and non-matching User-Agent rules
- matching and non-matching URI rules
- configured ASN and country rules
- repeated requests inside and outside `RepudiatorScanTime`
- warning threshold
- blocking threshold
- POW challenge and successful POW cookie
- HTTP status reputation
- response header generation

## License

This program is licensed under the **GNU General Public License, version 3 or
any later version (GPLv3+)**.

See the source header and the accompanying `LICENSE` file for
the complete license text.

## Disclaimer

This software is provided in the hope that it will be useful, but **without
any warranty**. See the GNU General Public License for the applicable terms
and conditions.
