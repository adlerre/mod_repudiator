/*
* This program is free software; you can use it, redistribute it
 * and / or modify it under the terms of the GNU General Public License
 * (GPL) as published by the Free Software Foundation; either version 3
 * of the License or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program, in a file called gpl.txt or license.txt.
 * If not, write to the Free Software Foundation Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <unistd.h>
#include <time.h>

#ifdef PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
#include <regex.h>
#endif

#include "maxminddb.h"

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "http_request.h"
#include "http_protocol.h"

AP_DECLARE_MODULE(repudiator);

#define _STR(x) #x
#define STR(x) _STR(x)

#ifndef REP_VERSION
#define REP_VERSION                 "dev"
#endif

#define LP_ASN                      "autonomous_system_number"

#define REP_OK      0
#define REP_WARN    1
#define REP_BLOCK   2

#define X_HEADER_REPUTATION         "X-Reputation"

#define FIXUP_HEADERS_OUT_FILTER    "REP_FIXUP_HEADERS_OUT"
#define FIXUP_HEADERS_ERR_FILTER    "REP_FIXUP_HEADERS_ERR"

#define DEFAULT_EVIL_DELAY          (-1)
#define DEFAULT_WARN_REPUTATION     (-200.0)
#define DEFAULT_BLOCK_REPUTATION    (-400.0)
#define DEFAULT_PER_IP_REPUTATION   (-0.033)
#define DEFAULT_PER_NET_REPUTATION  (-0.0033)
#define DEFAULT_PER_ASN_REPUTATION  (-0.00033)
#define DEFAULT_SCAN_TIME           60
#define DEFAULT_WARN_HTTP_REPLY     HTTP_TOO_MANY_REQUESTS
#define DEFAULT_BLOCK_HTTP_REPLY    HTTP_FORBIDDEN

struct ip_node {
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } ip;

    union {
        struct in_addr v4;
        struct in6_addr v6;
    } mask;

    double reputation;
    char family; // AF_INET or AF_INET6
};

struct ip_vector {
    struct ip_node *data;
    size_t size;
};

struct re_node {
#ifdef PCRE2
    pcre2_code *re;
    pcre2_match_data *match_data;
#else
    regex_t re;
#endif
    double reputation;
};

struct re_vector {
    struct re_node *data;
    size_t size;
};

struct asn_node {
    u_int32_t asn;
    double reputation;
};

struct asn_vector {
    struct asn_node *data;
    size_t size;
};

struct country_node {
    char *code;
    double reputation;
};

struct country_vector {
    struct country_node *data;
    size_t size;
};

struct status_node {
    uint32_t status;
    double reputation;
};

struct status_vector {
    struct status_node *data;
    size_t size;
};

struct asn_count {
    u_int32_t asn;
    size_t count;
    time_t lastSeen;
};

struct asn_count_vector {
    struct asn_count *data;
    size_t size;
};

struct nw_count {
    struct ip_node addr;
    size_t count;
    time_t lastSeen;
};

struct nw_count_vector {
    struct nw_count *data;
    size_t size;
};

struct req_node {
    u_int32_t asn;
    char *countryCode;
    struct ip_node addr;

    size_t count;
    time_t lastSeen;

    double ipReputation;
    double uaReputation;
    double uriReputation;
    double asnReputation;
    double countryReputation;
    double statusReputation;
    double reputation;
};

struct req_vector {
    struct req_node *data;
    size_t size;
};

typedef struct {
    int enabled;
    int evilMode;
    char *evilRedirectURL;
    int evilAppendURI;
    long evilDelay;
    char *asnDBPath;
    char *countryDBPath;
    struct ip_vector ipReputation;
    struct re_vector uaReputation;
    struct re_vector uriReputation;
    struct asn_vector asnReputation;
    struct country_vector countryReputation;
    struct status_vector statusReputation;
    double warnReputation;
    double blockReputation;
    double perIPReputation;
    double perNetworkReputation;
    double perASNReputation;
    long scanTime;
    int warnHttpReply;
    int blockHttpReply;

    MMDB_s *mmdbASN;
    MMDB_s *mmdbCountry;
    struct asn_count_vector asns;
    struct nw_count_vector networks;
    struct req_vector requests;
} repudiator_config;

double calcIPReputation(const struct ip_vector *ipReputation, const struct ip_node *ipNode);

double calcRegexReputation(const struct re_vector *reVector, const char *str);

double calcASNReputation(const struct asn_vector *asnVector, u_int32_t asn);

double calcCountryReputation(const struct country_vector *countryVector, const char *code);

double calcStatusReputation(const struct status_vector *statusVector, u_int32_t status);

static void *reallocArray(void *ptr, const size_t nmemb, const size_t size) {
    if (size && nmemb > SIZE_MAX / size) {
        errno = ENOMEM;
        return NULL;
    }

    return realloc(ptr, nmemb * size);
}

static void delay(const long millis) {
    const clock_t start = clock();
    while (clock() < start + CLOCKS_PER_SEC / 1000 * millis);
}

static int startsWith(const char *str, const char *prefix) {
    while (*prefix && *str == *prefix) ++str, ++prefix;
    return *prefix == 0;
}

static uint32_t prefix2mask(int prefix) {
    struct in_addr mask;
    memset(&mask, 0, sizeof(mask));
    if (prefix) {
        return htonl(~((1 << (32 - prefix)) - 1));
    }
    return htonl(0);
}

static void ipv6ApplyMask(struct in6_addr *restrict addr, const struct in6_addr *restrict mask) {
    for (size_t i = 0; i < sizeof(struct in6_addr); i++) {
        addr->s6_addr[i] &= mask->s6_addr[i];
    }
}

static int ipv6PrefixToMask(const unsigned prefix, struct in6_addr *mask) {
    struct in6_addr in6;
    int i, j;

    if (prefix > 128)
        return -1;

    memset(&in6, 0x0, sizeof(in6));
    for (i = (int) prefix, j = 0; i > 0; i -= 8, j++) {
        if (i >= 8) {
            in6.s6_addr[j] = 0xff;
        } else {
            in6.s6_addr[j] = (unsigned long) (0xffU << (8 - i));
        }
    }

    memcpy(mask, &in6, sizeof(*mask));
    return 0;
}

static int isInRange(const struct ip_node *range, const struct ip_node *ipNode) {
    if (range->family != ipNode->family) {
        return 0;
    }

    if (range->family == AF_INET) {
        const unsigned long ip = ntohl(ipNode->ip.v4.s_addr);
        const unsigned long fip = ntohl(range->ip.v4.s_addr & range->mask.v4.s_addr);
        const unsigned long lip = ntohl(range->ip.v4.s_addr | ~(range->mask.v4.s_addr));

        return fip <= ip && lip >= ip;
    }

    struct in6_addr network = range->ip.v6;
    ipv6ApplyMask(&network, &range->mask.v6);

    struct in6_addr ip = ipNode->ip.v6;
    ipv6ApplyMask(&ip, &range->mask.v6);

    return memcmp(&ip, &network, sizeof(network)) == 0;
}

static int convertAddress(const char *addr, struct ip_node *ipNode) {
    if (addr == NULL) {
        return -1;
    }

    int rc = 0;
    if (strstr(addr, ":") != NULL) {
        ipNode->family = AF_INET6;
        rc = inet_pton(AF_INET6, addr, &ipNode->ip.v6);
    } else {
        ipNode->family = AF_INET;
        rc = inet_pton(AF_INET, addr, &ipNode->ip.v4);
    }

    return rc;
}

static int parseIPReputation(struct ip_vector *ipReputation, const char *ipm, const char *rep) {
    int rc = 0;
    int pos = 0;
    int m = 0;
    int n = 0;
    char family = AF_INET;
    char addr[128] = {0};
    char mask[128] = {0};

    for (size_t i = 0; i < strlen(ipm); i++) {
        if (ipm[i] == ':') {
            family = AF_INET6;
        }
        if (ipm[i] != '|') {
            if (ipm[i] == '/') {
                addr[pos] = '\0';
                pos = 0;
                m = 1;
                continue;
            }

            if (m == 0) {
                addr[pos] = ipm[i];
            } else {
                mask[pos] = ipm[i];
            }
            ++pos;
            ++n;
        } else {
            break;
        }
    }

    if (m == 1) {
        mask[pos] = '\0';
    }

    int prefix = (int) strtol(mask, NULL, 10);
    struct in_addr ipv4, mv4 = {};
    struct in6_addr ipv6, mv6 = {};

    if (family == AF_INET) {
        rc = inet_pton(AF_INET, addr, &ipv4);
        mv4.s_addr = prefix2mask(strlen(mask) == 0 ? 32 : prefix);
    } else {
        rc = inet_pton(AF_INET6, addr, &ipv6);
        ipv6PrefixToMask(strlen(mask) == 0 ? 128 : prefix, &mv6);
    }

    if (rc != 0) {
        struct ip_node *node = reallocArray(ipReputation->data, ipReputation->size + 1, sizeof(*(ipReputation->data)));
        if (!node) {
            return -1;
        }

        ipReputation->data = node;

        if (family == AF_INET) {
            ipReputation->data[ipReputation->size++] = (struct ip_node){
                .family = AF_INET,
                .ip.v4 = ipv4,
                .mask.v4 = mv4,
                .reputation = strtod(rep, NULL)
            };
        } else {
            ipReputation->data[ipReputation->size++] = (struct ip_node){
                .family = AF_INET6,
                .ip.v6 = ipv6,
                .mask.v6 = mv6,
                .reputation = strtod(rep, NULL)
            };
        }

        rc = 0;
    } else {
        rc = -2;
    }

    return rc;
}

static int parseRegexReputation(struct re_vector *reVector, const char *regex, const char *rep) {
    int rc = 0;

    if (strlen(regex) != 0 && strlen(rep) != 0) {
#ifdef PCRE2
        int errornumber;
        PCRE2_SIZE erroroffset;

        PCRE2_SPTR pattern = (PCRE2_SPTR) regex;

        pcre2_code *re = pcre2_compile(
            pattern, /* the pattern */
            PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
            PCRE2_NO_AUTO_CAPTURE, /* Disable numbered capturing parentheses */
            &errornumber, /* for error number */
            &erroroffset, /* for error offset */
            NULL); /* use default compile context */

        if (re) {
            pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);

            struct re_node *node = reallocArray(reVector->data, reVector->size + 1, sizeof(*(reVector->data)));
            if (!node) {
                return -1;
            }

            reVector->data = node;
            reVector->data[reVector->size++] = (struct re_node){
                .re = re,
                .match_data = match_data,
                .reputation = strtod(rep, NULL)
            };
        }
#else
        regex_t re;
        rc = regcomp(&re, regex, REG_EXTENDED | REG_ICASE);

        if (!rc) {
            struct re_node *node = reallocArray(reVector->data, reVector->size + 1, sizeof(*(reVector->data)));
            if (!node) {
                return -1;
            }

            reVector->data = node;
            reVector->data[reVector->size++] = (struct re_node){
                .re = re,
                .reputation = strtod(rep, NULL)
            };
        }
#endif
    }

    return rc;
}

static int parseASNReputation(struct asn_vector *asnVector, const char *asn, const char *rep) {
    int rc = 0;

    if (strlen(asn) != 0 && strlen(rep) != 0) {
        struct asn_node *node = reallocArray(asnVector->data, asnVector->size + 1, sizeof(*(asnVector->data)));
        if (!node) {
            return -1;
        }

        asnVector->data = node;
        asnVector->data[asnVector->size++] = (struct asn_node){
            .asn = strtol(asn, NULL, 10),
            .reputation = strtod(rep, NULL)
        };
    } else {
        rc = -2;
    }

    return rc;
}

static int parseCountryReputation(struct country_vector *countryVector, const char *code, const char *rep) {
    int rc = 0;

    if (strlen(code) != 0 && strlen(rep) != 0) {
        struct country_node *node = reallocArray(countryVector->data, countryVector->size + 1,
                                                 sizeof(*(countryVector->data)));
        if (!node) {
            return -1;
        }

        countryVector->data = node;
        countryVector->data[countryVector->size++] = (struct country_node){
            .code = strdup(code),
            .reputation = strtod(rep, NULL)
        };
    } else {
        rc = -2;
    }

    return rc;
}

static int parseStatusReputation(struct status_vector *statusVector, const char *ret, const char *rep) {
    int rc = 0;

    if (strlen(ret) != 0 && strlen(rep) != 0) {
        uint32_t status = strtol(ret, NULL, 10);
        if (status < 99 || status > 599) {
            rc = -2;
        } else {
            struct status_node *node = reallocArray(statusVector->data, statusVector->size + 1,
                                                    sizeof(*(statusVector->data)));
            if (!node) {
                return -1;
            }

            statusVector->data = node;
            statusVector->data[statusVector->size++] = (struct status_node){
                .status = status,
                .reputation = strtod(rep, NULL)
            };
        }
    } else {
        rc = -2;
    }

    return rc;
}

double calcIPReputation(const struct ip_vector *ipReputation, const struct ip_node *ipNode) {
    double rc = 0.0;
    for (size_t i = 0; i < ipReputation->size; ++i) {
        const struct ip_node *node = &ipReputation->data[i];
        if (node->family == ipNode->family) {
            if (node->family == AF_INET && (node->ip.v4.s_addr == ipNode->ip.v4.s_addr || isInRange(node, ipNode))) {
                rc += node->reputation;
            } else if (node->family == AF_INET6 &&
                       (memcmp(&node->ip.v6, &ipNode->ip.v6, sizeof(node->ip.v6)) == 0 || isInRange(node, ipNode))) {
                rc += node->reputation;
            }
        }
    }
    return rc;
}

double calcRegexReputation(const struct re_vector *reVector, const char *str) {
    double ret = 0.0;
    if (str != NULL && strlen(str) != 0) {
        for (size_t i = 0; i < reVector->size; ++i) {
            const struct re_node *node = &reVector->data[i];
#ifdef PCRE2
            PCRE2_SPTR subject = (PCRE2_SPTR) str;
            size_t subject_length = strlen((const char *) subject);

            int rc = pcre2_match(
                node->re, /* the compiled pattern */
                subject, /* the subject string */
                subject_length, /* the length of the subject */
                0, /* start at offset 0 in the subject */
                0, /* default options */
                node->match_data, /* block for storing the result */
                NULL);

            if (rc >= 0) {
                ret += node->reputation;
            }
#else
            if (!regexec(&node->re, str, 0, NULL, 0)) {
                ret += node->reputation;
            }
#endif
        }
    }
    return ret;
}

double calcASNReputation(const struct asn_vector *asnVector, const u_int32_t asn) {
    const struct asn_node *wnode = NULL;
    for (size_t i = 0; i < asnVector->size; ++i) {
        const struct asn_node *node = &asnVector->data[i];
        if (node->asn == asn) {
            return node->reputation;
        }
        if (node->asn == 0) {
            wnode = node;
        }
    }

    if (wnode != NULL) {
        return wnode->reputation;
    }

    return 0.0;
}

double calcCountryReputation(const struct country_vector *countryVector, const char *code) {
    for (size_t i = 0; i < countryVector->size; ++i) {
        const struct country_node *node = &countryVector->data[i];
        if (code != NULL && node->code != NULL && strcasecmp(node->code, code) == 0) {
            return node->reputation;
        }
    }

    return 0.0;
}

double calcStatusReputation(const struct status_vector *statusVector, const u_int32_t status) {
    for (size_t i = 0; i < statusVector->size; ++i) {
        const struct status_node *node = &statusVector->data[i];
        if (node->status == status) {
            return node->reputation;
        }
    }
    return 0.0;
}

uint32_t lookupIPInfo(MMDB_s *mmdb, struct ip_node *node) {
    uint32_t asn = 0;
    int mmdb_error = 0;
    int gai_error = 0;

    if (mmdb != NULL) {
        char buf[128] = {0};
        if (node->family == AF_INET) {
            inet_ntop(AF_INET, &node->ip.v4, buf, sizeof(buf));
        } else {
            inet_ntop(AF_INET6, &node->ip.v6, buf, sizeof(buf));
        }

        MMDB_lookup_result_s lookup_result = MMDB_lookup_string(mmdb, buf, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            if (lookup_result.found_entry) {
                if (node->family == AF_INET) {
                    node->mask.v4.s_addr = prefix2mask(lookup_result.netmask);
                } else {
                    struct in6_addr m = node->ip.v6;
                    ipv6PrefixToMask(lookup_result.netmask, &m);
                    node->mask.v6 = m;
                }

                MMDB_entry_data_s entry_data;

                const char **lookup_path = calloc(1, sizeof(const char *));
                lookup_path[0] = LP_ASN;

                mmdb_error = MMDB_aget_value(&lookup_result.entry, &entry_data, lookup_path);
                if (mmdb_error == MMDB_SUCCESS) {
                    asn = entry_data.uint32;
                }
                free(lookup_path);

                return asn;
            }
        }
    }

    if (node->family == AF_INET) {
        node->mask.v4.s_addr = prefix2mask(32);
    } else {
        struct in6_addr m = node->ip.v6;
        ipv6PrefixToMask(128, &m);
        node->mask.v6 = m;
    }

    return asn;
}

char *lookupCountryInfo(MMDB_s *mmdb, struct ip_node *node) {
    char *code = NULL;
    int mmdb_error = 0;
    int gai_error = 0;

    if (mmdb != NULL) {
        char buf[128] = {0};
        if (node->family == AF_INET) {
            inet_ntop(AF_INET, &node->ip.v4, buf, sizeof(buf));
        } else {
            inet_ntop(AF_INET6, &node->ip.v6, buf, sizeof(buf));
        }

        MMDB_lookup_result_s lookup_result = MMDB_lookup_string(mmdb, buf, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            if (lookup_result.found_entry) {
                MMDB_entry_data_s entry_data;

                const char **lookup_path = calloc(2, sizeof(const char *));
                lookup_path[0] = "country";
                lookup_path[1] = "iso_code";

                mmdb_error = MMDB_aget_value(&lookup_result.entry, &entry_data, lookup_path);
                if (mmdb_error == MMDB_SUCCESS) {
                    code = strndup(entry_data.utf8_string, entry_data.data_size);
                }
                free(lookup_path);

                return code;
            }
        }
    }
    return code;
}

long findRequest(const struct req_vector *requests, const struct ip_node *ip) {
    long idx = -1;
    for (size_t i = 0; i < requests->size; ++i) {
        const struct req_node *node = &requests->data[i];
        if (node->addr.family == ip->family) {
            if ((node->addr.family == AF_INET && node->addr.ip.v4.s_addr == ip->ip.v4.s_addr) ||
                (node->addr.family == AF_INET6 &&
                 memcmp(&node->addr.ip.v6, &ip->ip.v6, sizeof(node->addr.ip.v6)) == 0)) {
                idx = (long) i;
                break;
            }
        }
    }
    return idx;
}

struct req_node *addRequest(repudiator_config *cfg, const struct ip_node *ip, const uint32_t asn,
                            const char *countryCode, const char *userAgent,
                            const char *uri, const time_t timestamp) {
    const long idx = findRequest(&cfg->requests, ip);
    if (idx == -1) {
        struct req_node *node = reallocArray(cfg->requests.data, cfg->requests.size + 1, sizeof(*(cfg->requests.data)));
        if (node == NULL) {
            return NULL;
        }

        cfg->requests.data = node;
        cfg->requests.data[cfg->requests.size++] = (struct req_node){
            .asn = asn,
            .countryCode = countryCode != NULL ? strdup(countryCode) : NULL,
            .addr = *ip,
            .count = 1,
            .lastSeen = timestamp
        };

        node = &cfg->requests.data[cfg->requests.size - 1];
        node->ipReputation = calcIPReputation(&cfg->ipReputation, ip);
        node->uaReputation = calcRegexReputation(&cfg->uaReputation, userAgent);
        node->uriReputation = calcRegexReputation(&cfg->uriReputation, uri);
        node->asnReputation = calcASNReputation(&cfg->asnReputation, asn);
        node->countryReputation = calcCountryReputation(&cfg->countryReputation, countryCode);
        return node;
    }

    struct req_node *node = &cfg->requests.data[idx];

    if (node->lastSeen > timestamp - cfg->scanTime) {
        node->count++;
        node->ipReputation += calcIPReputation(&cfg->ipReputation, ip);
        node->uaReputation += calcRegexReputation(&cfg->uaReputation, userAgent);
        node->uriReputation += calcRegexReputation(&cfg->uriReputation, uri);
        node->asnReputation += calcASNReputation(&cfg->asnReputation, asn);
        node->countryReputation += calcCountryReputation(&cfg->countryReputation, countryCode);
    } else {
        node->count = 1;
        node->ipReputation = calcIPReputation(&cfg->ipReputation, ip);
        node->uaReputation = calcRegexReputation(&cfg->uaReputation, userAgent);
        node->uriReputation = calcRegexReputation(&cfg->uriReputation, uri);
        node->asnReputation = calcASNReputation(&cfg->asnReputation, asn);
        node->countryReputation = calcCountryReputation(&cfg->countryReputation, countryCode);
    }
    node->lastSeen = timestamp;

    return node;
}

int removeRequest(struct req_vector *requests, const size_t idx) {
    for (size_t i = idx; i < requests->size - 1; ++i) {
        requests->data[i] = requests->data[i + 1];
    }
    struct req_node *tmp = reallocArray(requests->data, requests->size - 1, sizeof(*(requests->data)));
    if (tmp == NULL && requests->size > 1) {
        return -1;
    }
    requests->data = tmp;
    requests->size--;
    return 0;
}

long findNetwork(const struct nw_count_vector *networks, const struct ip_node *addr) {
    long idx = -1;

    for (size_t i = 0; i < networks->size; ++i) {
        const struct nw_count *node = &networks->data[i];
        if (isInRange(&node->addr, addr)) {
            idx = (long) i;
            break;
        }
    }

    return idx;
}

int removeNetwork(struct nw_count_vector *networks, const size_t idx) {
    for (size_t i = idx; i < networks->size - 1; ++i) {
        networks->data[i] = networks->data[i + 1];
    }
    struct nw_count *tmp = reallocArray(networks->data, networks->size - 1, sizeof(*(networks->data)));
    if (tmp == NULL && networks->size > 1) {
        return -1;
    }
    networks->data = tmp;
    networks->size--;
    return 0;
}

int incNetworkCount(struct nw_count_vector *networks, const struct ip_node *addr, const time_t update,
                    const time_t scanTime) {
    long idx = findNetwork(networks, addr);
    if (idx != -1) {
        struct nw_count *node = &networks->data[idx];
        if (node->lastSeen < update - scanTime)
            node->count = 1;
        else
            node->count++;
        node->lastSeen = update;
    } else {
        struct nw_count *node = reallocArray(networks->data, networks->size + 1, sizeof(*(networks->data)));
        if (node == NULL) {
            return -1;
        }

        networks->data = node;
        networks->data[networks->size++] = (struct nw_count){
            .addr = *addr,
            .count = 1,
            .lastSeen = update
        };
    }

    return 0;
}

void cleanNetworks(struct nw_count_vector *networks, const time_t before) {
    size_t idx = 0;
    while (idx < networks->size) {
        const struct nw_count *node = &networks->data[idx];
        if (node != NULL && node->lastSeen < before) {
            removeNetwork(networks, idx);
        } else {
            idx++;
        }
    }
}

long findASN(const struct asn_count_vector *asns, const u_int32_t asn) {
    long idx = -1;

    for (size_t i = 0; i < asns->size; ++i) {
        const struct asn_count *node = &asns->data[i];
        if (node->asn == asn) {
            idx = (long) i;
            break;
        }
    }

    return idx;
}

int removeASN(struct asn_count_vector *asns, const size_t idx) {
    for (size_t i = idx; i < asns->size - 1; ++i) {
        asns->data[i] = asns->data[i + 1];
    }
    struct asn_count *tmp = reallocArray(asns->data, asns->size - 1, sizeof(*(asns->data)));
    if (tmp == NULL && asns->size > 1) {
        return -1;
    }
    asns->data = tmp;
    asns->size--;
    return 0;
}

int incASNCount(struct asn_count_vector *asns, const u_int32_t asn, const time_t update, const time_t scanTime) {
    const long idx = findASN(asns, asn);
    if (idx != -1) {
        struct asn_count *node = &asns->data[idx];
        if (node->lastSeen < update - scanTime)
            node->count = 1;
        else
            node->count++;
        node->lastSeen = update;
    } else {
        struct asn_count *node = reallocArray(asns->data, asns->size + 1, sizeof(*(asns->data)));
        if (node == NULL) {
            return -1;
        }

        asns->data = node;
        asns->data[asns->size++] = (struct asn_count){
            .asn = asn,
            .count = 1,
            .lastSeen = update
        };
    }

    return 0;
}

void cleanASNs(struct asn_count_vector *asns, const time_t before) {
    size_t idx = 0;
    while (idx < asns->size) {
        const struct asn_count *node = &asns->data[idx];
        if (node != NULL && node->lastSeen < before) {
            removeASN(asns, idx);
        } else {
            idx++;
        }
    }
}

int reputationState(const repudiator_config *cfg, const double reputation) {
    if (cfg->blockReputation < cfg->warnReputation) {
        if (reputation <= cfg->warnReputation && reputation >= cfg->blockReputation) {
            return REP_WARN;
        }
        if (reputation <= cfg->blockReputation) {
            return REP_BLOCK;
        }
    } else {
        if (reputation >= cfg->warnReputation && reputation <= cfg->blockReputation) {
            return REP_WARN;
        }
        if (reputation >= cfg->blockReputation) {
            return REP_BLOCK;
        }
    }

    return REP_OK;
}

double calcReputation(const repudiator_config *cfg, const struct req_node *reqNode, const int type) {
    long idx;
    switch (type) {
        case 1:
            return cfg->perIPReputation * (double) reqNode->count;
        case 2:
            idx = findNetwork(&cfg->networks, &reqNode->addr);
            return idx != -1 ? cfg->perNetworkReputation * (double) cfg->networks.data[idx].count : 0;
        case 3:
            idx = findASN(&cfg->asns, reqNode->asn);
            return reqNode->asn != 0 && idx != -1
                       ? cfg->perASNReputation * (double) cfg->asns.data[idx].count
                       : 0.0;
        default:
            return (reqNode->ipReputation + reqNode->uaReputation + reqNode->uriReputation + reqNode->asnReputation +
                    reqNode->countryReputation) / (double) reqNode->count;
    }
}

static void *createDirConf(apr_pool_t *p, __attribute__((unused)) char *context) {
    repudiator_config *cfg = apr_palloc(p, sizeof(repudiator_config));
    if (!cfg) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Failed to allocate configuration");
        return NULL;
    }

    *cfg = (repudiator_config){
        .enabled = 0,
        .asnDBPath = NULL,
        .countryDBPath = NULL,
        .ipReputation = (struct ip_vector){.data = NULL, .size = 0},
        .uaReputation = (struct re_vector){.data = NULL, .size = 0},
        .uriReputation = (struct re_vector){.data = NULL, .size = 0},
        .asnReputation = (struct asn_vector){.data = NULL, .size = 0},
        .countryReputation = (struct country_vector){.data = NULL, .size = 0},
        .warnReputation = DEFAULT_WARN_REPUTATION,
        .blockReputation = DEFAULT_BLOCK_REPUTATION,
        .perIPReputation = DEFAULT_PER_IP_REPUTATION,
        .perNetworkReputation = DEFAULT_PER_NET_REPUTATION,
        .perASNReputation = DEFAULT_PER_ASN_REPUTATION,
        .scanTime = DEFAULT_SCAN_TIME,
        .warnHttpReply = DEFAULT_WARN_HTTP_REPLY,
        .blockHttpReply = DEFAULT_BLOCK_HTTP_REPLY,
        .asns = (struct asn_count_vector){.data = NULL, .size = 0},
        .networks = (struct nw_count_vector){.data = NULL, .size = 0},
        .requests = (struct req_vector){.data = NULL, .size = 0},
    };

    return cfg;
}

static char const *getClientIp(request_rec *r) {
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    return r->useragent_ip;
#else
    return r->connection->remote_ip;
#endif
}

static int accessChecker(request_rec *r) {
    repudiator_config *cfg = (repudiator_config *) ap_get_module_config(r->per_dir_config, &repudiator_module);

    int ret = OK;

    if (cfg->enabled && r->prev == NULL && r->main == NULL) {
        apr_time_t t = r->request_time / 1000 / 1000;

        struct ip_node addr;
        if (convertAddress(getClientIp(r), &addr) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Couldn't parse ip address");
            return OK;
        }

        const uint32_t asn = lookupIPInfo(cfg->mmdbASN, &addr);
        const char *countryCode = lookupCountryInfo(cfg->mmdbCountry, &addr);
        const char *userAgent = apr_table_get(r->headers_in, "user-agent");

        incASNCount(&cfg->asns, asn, t, cfg->scanTime);
        incNetworkCount(&cfg->networks, &addr, t, cfg->scanTime);

        struct req_node *req = addRequest(cfg, &addr, asn, countryCode, userAgent, r->unparsed_uri, t);
        if (req == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Couldn't add request: OOM");
            return OK;
        }

        const double basicRep = calcReputation(cfg, req, 0);
        const double perIPRep = calcReputation(cfg, req, 1);
        const double perNetRep = calcReputation(cfg, req, 2);
        const double perASNRep = calcReputation(cfg, req, 3);

        req->reputation = basicRep + perIPRep + perNetRep + perASNRep + req->statusReputation;

        const int repState = reputationState(cfg, req->reputation);

#ifdef REP_DEBUG
        long idx = findNetwork(&cfg->networks, &addr);
        const size_t nwCount = idx != -1 ? cfg->networks.data[idx].count : 0;

        idx = findASN(&cfg->asns, req->asn);
        const size_t asnCount = idx != -1 ? cfg->asns.data[idx].count : 0;
#endif

        cleanASNs(&cfg->asns, t - cfg->scanTime * 2);
        cleanNetworks(&cfg->networks, t - cfg->scanTime * 2);

#ifndef REP_DEBUG
        if (repState != REP_OK) {
#endif
            char ip[128] = {0};
            char mask[128] = {0};
            char asnStr[20] = {0};
            char countryStr[20] = {0};

            if (req->addr.family == AF_INET) {
                inet_ntop(AF_INET, &req->addr.ip.v4, ip, sizeof(ip));
                inet_ntop(AF_INET, &req->addr.mask.v4, mask, sizeof(mask));
            } else {
                inet_ntop(AF_INET6, &req->addr.ip.v6, ip, sizeof(ip));
                inet_ntop(AF_INET6, &req->addr.mask.v6, mask, sizeof(mask));
            }

            snprintf(asnStr, sizeof(asnStr), "AS%d", asn);
            snprintf(countryStr, sizeof(countryStr), "|%s", countryCode != NULL ? countryCode : "private");

#ifdef REP_DEBUG
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                         "%s/%s (%s%s) %s %s \"%s\" - %s (b:%4.2f (%4.2f %4.2f %4.2f %4.2f %4.2f)|ip:%4.2f (%lu)|net:%4.2f (%lu)|asn:%4.2f (%lu) %4.2f)",
                         ip, mask, asnStr, countryStr, r->hostname, r->unparsed_uri, userAgent ? userAgent : "-",
                         repState == REP_OK ? "OK" : repState == REP_WARN ? "WARN" : "BLOCK", basicRep,
                         req->ipReputation / req->count, req->uaReputation / req->count,
                         req->uriReputation / req->count, req->countryReputation / req->count, req->statusReputation,
                         perIPRep, req->count, perNetRep,
                         nwCount,
                         perASNRep, asnCount, req->reputation);
#else
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                         "%s/%s (%s%s) %s %s \"%s\" - %s (%4.2f)",
                         ip, mask, asnStr, countryStr, r->hostname, r->unparsed_uri, userAgent ? userAgent : "-",
                         repState == REP_OK ? "OK" : repState == REP_WARN ? "WARN" : "BLOCK", req->reputation);
#endif

#ifdef REP_DEBUG
            if (repState != REP_OK) {
#endif
            if (cfg->evilMode == 1 && repState == REP_BLOCK) {
                char location[4096] = {0};

                if (cfg->evilRedirectURL != NULL) {
                    if (cfg->evilAppendURI == 1) {
                        snprintf(location, sizeof(location), "%s%s", cfg->evilRedirectURL, r->unparsed_uri);
                    } else {
                        snprintf(location, sizeof(location), "%s", cfg->evilRedirectURL);
                    }
                } else {
                    // send traffic to a random bad guy
                    if (cfg->requests.size > 1) {
                        struct req_node *rreq;
                        size_t ec = 0;
                        do {
                            const size_t ridx = rand() % (cfg->requests.size + 1);
                            rreq = &cfg->requests.data[ridx];
                            ec++;
                        } while (rreq->reputation < cfg->blockReputation && ec < 10);

                        if (rreq->reputation > cfg->blockReputation) {
                            req = rreq;
                        }

                        if (req->addr.family == AF_INET) {
                            inet_ntop(AF_INET, &req->addr.ip.v4, ip, sizeof(ip));
                            inet_ntop(AF_INET, &req->addr.mask.v4, mask, sizeof(mask));
                        } else {
                            inet_ntop(AF_INET6, &req->addr.ip.v6, ip, sizeof(ip));
                            inet_ntop(AF_INET6, &req->addr.mask.v6, mask, sizeof(mask));
                        }
                    }

                    snprintf(location, sizeof(location), req->addr.family == AF_INET ? "http://%s" : "http://[%s]", ip);
                }

                if (cfg->evilDelay > 0) {
                    delay(cfg->evilDelay);
                }

                apr_table_setn(r->headers_out, "Location", location);
                return HTTP_MOVED_TEMPORARILY;
            }

            return repState == REP_WARN ? cfg->warnHttpReply : cfg->blockHttpReply;
        }
    }

    return ret;
}

static int preConfig(apr_pool_t *mp, apr_pool_t *mp_log, apr_pool_t *mp_temp) {
    void *data = NULL;
    const char *key = "repudiator-pre-config-init-flag";
    int first_time = 0;

    apr_pool_userdata_get(&data, key, mp);
    if (data == NULL) {
        apr_pool_userdata_set((const void *) 1, key,
                              apr_pool_cleanup_null, mp);
        first_time = 1;
    }

    if (!first_time) {
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, "ModRepudiator version %s",
                 STR(REP_VERSION));

    return OK;
}

int doHeaders(const repudiator_config *cfg, request_rec *r, apr_table_t *headers) {
    if (cfg->enabled) {
        struct ip_node addr;
        if (convertAddress(getClientIp(r), &addr) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Couldn't parse ip address");
            return DECLINED;
        }

        const long idx = findRequest(&cfg->requests, &addr);
        if (idx != -1) {
            const struct req_node *req = &cfg->requests.data[idx];

            const int repState = reputationState(cfg, req->reputation);

            char repStr[50] = {0};
            snprintf(repStr, sizeof(repStr), "%s (%4.2f)",
                     repState == REP_OK ? "OK" : repState == REP_WARN ? "WARN" : "BLOCK", req->reputation);

            if (apr_table_get(headers, X_HEADER_REPUTATION) != NULL) {
                apr_table_unset(headers, X_HEADER_REPUTATION);
            }

            apr_table_add(headers, X_HEADER_REPUTATION, strdup(repStr));
        }
    }

    return OK;
}

int handleStatusCode(const repudiator_config *cfg, request_rec *r) {
    if (cfg->enabled) {
        struct ip_node addr;
        if (convertAddress(getClientIp(r), &addr) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Couldn't parse ip address");
            return DECLINED;
        }

        const long idx = findRequest(&cfg->requests, &addr);
        if (idx != -1) {
            struct req_node *req = &cfg->requests.data[idx];
            req->statusReputation += calcStatusReputation(&cfg->statusReputation, r->status);
        }
    }

    return OK;
}

static apr_status_t headersOutputFilter(ap_filter_t *f, apr_bucket_brigade *in) {
    repudiator_config *cfg = (repudiator_config *) ap_get_module_config(f->r->per_dir_config, &repudiator_module);

    doHeaders(cfg, f->r, f->r->headers_out);

    handleStatusCode(cfg, f->r);

    ap_remove_output_filter(f);

    return ap_pass_brigade(f->next, in);
}

static apr_status_t headersErrorFilter(ap_filter_t *f, apr_bucket_brigade *in) {
    repudiator_config *cfg = (repudiator_config *) ap_get_module_config(f->r->per_dir_config, &repudiator_module);

    doHeaders(cfg, f->r, f->r->err_headers_out);

    handleStatusCode(cfg, f->r);

    ap_remove_output_filter(f);

    return ap_pass_brigade(f->next, in);
}

static void headersInsertOutputFilter(request_rec *r) {
    ap_add_output_filter(FIXUP_HEADERS_OUT_FILTER, NULL, r, r->connection);
}

static void headersInsertErrorFilter(request_rec *r) {
    ap_add_output_filter(FIXUP_HEADERS_ERR_FILTER, NULL, r, r->connection);
}

static void destroyREVector(struct re_vector *vec) {
#ifdef PCRE2
    for (size_t i = 0; i < vec->size; i++) {
        struct re_node *node = &vec->data[i];
        pcre2_code_free(node->re);
        pcre2_match_data_free(node->match_data);
    }
#endif
    free(vec->data);
}

static apr_status_t destroyConfig(void *dconfig) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    if (cfg != NULL) {
        free(cfg->evilRedirectURL);
        free(cfg->ipReputation.data);
        destroyREVector(&cfg->uaReputation);
        destroyREVector(&cfg->uriReputation);
        free(cfg->asnReputation.data);
        free(cfg->requests.data);
        free(cfg->networks.data);
        free(cfg->asns.data);
        free(cfg->asnDBPath);
        free(cfg->countryDBPath);
    }
    return APR_SUCCESS;
}

static const char *setEnabled(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    if (strcmp("true", value) == 0) {
        cfg->enabled = 1;
    } else if (strcmp("false", value) == 0) {
        cfg->enabled = 0;
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorEnabled value '%s', mod_repudiator disabled.", value);
        cfg->enabled = 0;
    }

    return NULL;
}

static const char *setEvilModeEnabled(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    if (!strcasecmp("true", value) || !strcasecmp("on", value)) {
        cfg->evilMode = 1;
    } else if (!strcasecmp("false", value) || !strcasecmp("off", value)) {
        cfg->evilMode = 0;
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorEvilModeEnabled value '%s'", value);
        cfg->evilMode = 0;
    }

    return NULL;
}

static const char *setEvilRedirectURL(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    if (startsWith(value, "http") == 1 || startsWith(value, "/") == 1) {
        cfg->evilRedirectURL = strdup(value);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorEvilRedirectURL value '%s'", value);
        cfg->evilRedirectURL = NULL;
    }

    return NULL;
}

static const char *setEvilAppendURI(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    if (!strcasecmp("true", value) || !strcasecmp("on", value)) {
        cfg->evilAppendURI = 1;
    } else if (!strcasecmp("false", value) || !strcasecmp("off", value)) {
        cfg->evilAppendURI = 0;
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorEvilAppendURI value '%s'", value);
        cfg->evilAppendURI = 0;
    }

    return NULL;
}

static const char *setEvilDelay(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorEvilDelay value '%s', using default %d.",
                     value, DEFAULT_SCAN_TIME);
        cfg->evilDelay = DEFAULT_EVIL_DELAY;
    } else {
        cfg->evilDelay = n;
    }

    return NULL;
}

static apr_status_t cleanupDatabase(void *mmdb) {
    MMDB_close((MMDB_s *) mmdb);
    return APR_SUCCESS;
}

static const char *setASNDatabase(cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    cfg->asnDBPath = strdup(value);

    MMDB_s *mmdb = apr_pcalloc(cmd->pool, sizeof(MMDB_s));
    int mmdb_error = MMDB_open(cfg->asnDBPath, MMDB_MODE_MMAP, mmdb);
    if (mmdb_error != MMDB_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "ASNDatabase: Failed to open %s: %s",
                     cfg->asnDBPath, MMDB_strerror(mmdb_error));
        return NULL;
    }

    apr_pool_pre_cleanup_register(cmd->pool, mmdb, cleanupDatabase);

    cfg->mmdbASN = mmdb;

    return NULL;
}

static const char *setCountryDatabase(cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    cfg->countryDBPath = strdup(value);

    MMDB_s *mmdb = apr_pcalloc(cmd->pool, sizeof(MMDB_s));
    int mmdb_error = MMDB_open(cfg->countryDBPath, MMDB_MODE_MMAP, mmdb);
    if (mmdb_error != MMDB_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "CountryDatabase: Failed to open %s: %s",
                     cfg->countryDBPath, MMDB_strerror(mmdb_error));
        return NULL;
    }

    apr_pool_pre_cleanup_register(cmd->pool, mmdb, cleanupDatabase);

    cfg->mmdbCountry = mmdb;

    return NULL;
}

static const char *setIPReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value,
                                   const char *value2) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    const int rc = parseIPReputation(&cfg->ipReputation, value, value2);

    if (rc == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "IPReputation: OOM");
    } else if (rc != 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid RepudiatorIPReputation value '%s' '%s",
                     value, value2);
    }

    return NULL;
}

static const char *setUAReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value,
                                   const char *value2) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    const int rc = parseRegexReputation(&cfg->uaReputation, value, value2);

    if (rc == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "UAReputation: OOM");
    } else if (rc != 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid RepudiatorUAReputation value '%s' '%s",
                     value, value2);
    }

    return NULL;
}

static const char *setURIReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value,
                                    const char *value2) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    const int rc = parseRegexReputation(&cfg->uriReputation, value, value2);

    if (rc == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "URIReputation: OOM");
    } else if (rc != 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid RepudiatorURIReputation value '%s' '%s",
                     value, value2);
    }

    return NULL;
}

static const char *setASNReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value,
                                    const char *value2) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    const int rc = parseASNReputation(&cfg->asnReputation, value, value2);

    if (rc == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "ASNReputation: OOM");
    } else if (rc != 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid RepudiatorASNReputation value '%s' '%s",
                     value, value2);
    }

    return NULL;
}

static const char *setCountryReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value,
                                        const char *value2) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    const int rc = parseCountryReputation(&cfg->countryReputation, value, value2);

    if (rc == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "CountryReputation: OOM");
    } else if (rc != 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid RepudiatorCountyReputation value '%s' '%s",
                     value, value2);
    }

    return NULL;
}

static const char *setStatusReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value,
                                       const char *value2) {
    repudiator_config *cfg = (repudiator_config *) dconfig;

    const int rc = parseStatusReputation(&cfg->statusReputation, value, value2);

    if (rc == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "StatusReputation: OOM");
    } else if (rc != 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid RepudiatorStatusReputation value '%s' '%s'",
                     value, value2);
    }

    return NULL;
}

static const char *setWarnReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    double n;

    errno = 0;
    n = strtod(value, &endptr);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorWarnReputation value '%s', using default %4.2f.",
                     value, DEFAULT_WARN_REPUTATION);
        cfg->warnReputation = DEFAULT_WARN_REPUTATION;
    } else {
        cfg->warnReputation = n;
    }

    return NULL;
}

static const char *setBlockReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    double n;

    errno = 0;
    n = strtod(value, &endptr);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorBlockReputation value '%s', using default %4.2f.",
                     value, DEFAULT_BLOCK_REPUTATION);
        cfg->blockReputation = DEFAULT_BLOCK_REPUTATION;
    } else {
        cfg->blockReputation = n;
    }

    return NULL;
}

static const char *setPerIPReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    double n;

    errno = 0;
    n = strtod(value, &endptr);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorPerIPReputation value '%s', using default %4.2f.",
                     value, DEFAULT_PER_IP_REPUTATION);
        cfg->perIPReputation = DEFAULT_PER_IP_REPUTATION;
    } else {
        cfg->perIPReputation = n;
    }

    return NULL;
}

static const char *setPerNetworkReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    double n;

    errno = 0;
    n = strtod(value, &endptr);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorPerNetReputation value '%s', using default %4.2f.",
                     value, DEFAULT_PER_NET_REPUTATION);
        cfg->perNetworkReputation = DEFAULT_PER_NET_REPUTATION;
    } else {
        cfg->perNetworkReputation = n;
    }

    return NULL;
}

static const char *setPerASNReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    double n;

    errno = 0;
    n = strtod(value, &endptr);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorPerASNReputation value '%s', using default %4.2f.",
                     value, DEFAULT_PER_ASN_REPUTATION);
        cfg->perASNReputation = DEFAULT_PER_ASN_REPUTATION;
    } else {
        cfg->perASNReputation = n;
    }

    return NULL;
}

static const char *setScanTime(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorScanTime value '%s', using default %d.",
                     value, DEFAULT_SCAN_TIME);
        cfg->scanTime = DEFAULT_SCAN_TIME;
    } else {
        cfg->scanTime = n;
    }

    return NULL;
}

static const char *setWarnHttpReply(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || ((n < 99 || n > 599) && n != OK && n != DECLINED)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorWarnHttpReply value '%s', using default %d.",
                     value, DEFAULT_WARN_HTTP_REPLY);
        cfg->warnHttpReply = DEFAULT_WARN_HTTP_REPLY;
    } else {
        cfg->warnHttpReply = n;
    }

    return NULL;
}

static const char *setBlocHttpReply(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config *cfg = (repudiator_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || ((n < 99 || n > 599) && n != OK && n != DECLINED)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorWarnHttpReply value '%s', using default %d.",
                     value, DEFAULT_BLOCK_HTTP_REPLY);
        cfg->blockHttpReply = DEFAULT_BLOCK_HTTP_REPLY;
    } else {
        cfg->blockHttpReply = n;
    }

    return NULL;
}

static const command_rec configCmds[] = {
    AP_INIT_TAKE1("RepudiatorEnabled", setEnabled, NULL, RSRC_CONF,
                  "Enable mod_repudiator (either globally or in the virtualhost where it is specified)"),

    AP_INIT_TAKE1("RepudiatorEvilModeEnabled", setEvilModeEnabled, NULL, RSRC_CONF,
                  "Enable evil mode - let's get mad"),

    AP_INIT_TAKE1("RepudiatorEvilRedirectURL", setEvilRedirectURL, NULL, RSRC_CONF, "Set evil redirect URL"),

    AP_INIT_TAKE1("RepudiatorEvilAppendURI", setEvilAppendURI, NULL, RSRC_CONF, "Enable URI append to redirectURL"),

    AP_INIT_TAKE1("RepudiatorEvilDelay", setEvilDelay, NULL, RSRC_CONF, "Set evil delay in milliseconds"),

    AP_INIT_TAKE1("RepudiatorASNDatabase", setASNDatabase, NULL, RSRC_CONF, "Set path to Maxmind ASN database"),

    AP_INIT_TAKE1("RepudiatorCountryDatabase", setCountryDatabase, NULL, RSRC_CONF,
                  "Set path to Maxmind country database"),

    AP_INIT_ITERATE2("RepudiatorIPReputation", setIPReputation, NULL, RSRC_CONF, "IP-address based reputation"),

    AP_INIT_ITERATE2("RepudiatorUAReputation", setUAReputation, NULL, RSRC_CONF, "User agent based reputation"),

    AP_INIT_ITERATE2("RepudiatorURIReputation", setURIReputation, NULL, RSRC_CONF, "URI based reputation"),

    AP_INIT_ITERATE2("RepudiatorASNReputation", setASNReputation, NULL, RSRC_CONF, "ASN based reputation"),

    AP_INIT_ITERATE2("RepudiatorCountryReputation", setCountryReputation, NULL, RSRC_CONF, "Country based reputation"),

    AP_INIT_ITERATE2("RepudiatorStatusReputation", setStatusReputation, NULL, RSRC_CONF,
                     "Return Code based reputation"),

    AP_INIT_TAKE1("RepudiatorWarnReputation", setWarnReputation, NULL, RSRC_CONF, "Warning reputation"),

    AP_INIT_TAKE1("RepudiatorBlockReputation", setBlockReputation, NULL, RSRC_CONF, "Blocking reputation"),

    AP_INIT_TAKE1("RepudiatorPerIPReputation", setPerIPReputation, NULL, RSRC_CONF, "Per IP reputation"),

    AP_INIT_TAKE1("RepudiatorPerNetReputation", setPerNetworkReputation, NULL, RSRC_CONF, "Per network reputation"),

    AP_INIT_TAKE1("RepudiatorPerASNReputation", setPerASNReputation, NULL, RSRC_CONF, "Per ASN reputation"),

    AP_INIT_TAKE1("RepudiatorScanTime", setScanTime, NULL, RSRC_CONF, "Scan time"),

    AP_INIT_TAKE1("RepudiatorWarnHttpReply", setWarnHttpReply, NULL, RSRC_CONF, "Warning HTTP error code"),

    AP_INIT_TAKE1("RepudiatorBlockHttpReply", setBlocHttpReply, NULL, RSRC_CONF, "Blocking HTTP error code"),

    {NULL}
};

static void registerHooks(apr_pool_t *p) {
    ap_hook_pre_config(preConfig, NULL, NULL, APR_HOOK_FIRST);

    ap_register_output_filter(FIXUP_HEADERS_OUT_FILTER, headersOutputFilter,NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter(FIXUP_HEADERS_ERR_FILTER, headersErrorFilter,NULL, AP_FTYPE_CONTENT_SET);

    ap_hook_insert_filter(headersInsertOutputFilter, NULL, NULL, APR_HOOK_LAST);
    ap_hook_insert_error_filter(headersInsertErrorFilter, NULL, NULL, APR_HOOK_LAST);
    ap_hook_access_checker(accessChecker, NULL, NULL, APR_HOOK_FIRST - 5);

    apr_pool_cleanup_register(p, NULL, apr_pool_cleanup_null, destroyConfig);
};

module AP_MODULE_DECLARE_DATA repudiator_module = {
    STANDARD20_MODULE_STUFF,
    createDirConf,
    NULL,
    NULL,
    NULL,
    configCmds,
    registerHooks,
    AP_MODULE_FLAG_NONE
};
