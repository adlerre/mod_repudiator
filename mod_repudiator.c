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

#ifdef PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
#include <regex.h>
#endif

#include "maxminddb.h"

#include "apr.h"
#include "apr_strings.h"
#include "apr_random.h"
#include "apr_file_io.h"
#include "apr_general.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "http_request.h"
#include "http_protocol.h"
#include "util_cookies.h"
#include "ap_slotmem.h"

#include "json.c"
#include "sha256.c"

#include "pow_template.c"
#include "state_template.c"

module AP_MODULE_DECLARE_DATA repudiator_module;

#define _STR(x) #x
#define STR(x) _STR(x)

#ifndef REP_VERSION
#define REP_VERSION                     "dev"
#endif

#define LP_ASN                          "autonomous_system_number"

#define REP_OK                          0
#define REP_WARN                        1
#define REP_BLOCK                       2

#define REP_STATS                       "repudiator-stats"
#define REP_STATS_MAGIC_TYPE            "application/x-rep-stats"

#define POW_PASSED_COOKIE               "REP-PASSED"
#define POW_REDIRECT_URI                "redirect_uri"

#define X_HEADER_REPUTATION             "X-Reputation"

#define FIXUP_HEADERS_OUT_FILTER        "REP_FIXUP_HEADERS_OUT"
#define FIXUP_HEADERS_ERR_FILTER        "REP_FIXUP_HEADERS_ERR"

#define DEFAULT_POW_URI                 "/rep-pow-challenge"
#define DEFAULT_POW_COOKIE_MAXAGE       3600
#define DEFAULT_POW_DIFFICULTY          16
#define DEFAULT_POW_ABOVE_REPUTATION    (-150.0)
#define DEFAULT_POW_BELOW_REPUTATION    (-1000.0)

#define DEFAULT_EVIL_DELAY              (-1)
#define DEFAULT_WARN_REPUTATION         (-200.0)
#define DEFAULT_BLOCK_REPUTATION        (-400.0)
#define DEFAULT_PER_IP_REPUTATION       (-0.033)
#define DEFAULT_PER_NET_REPUTATION      (-0.0033)
#define DEFAULT_PER_ASN_REPUTATION      (-0.00033)
#define DEFAULT_SCAN_TIME               60
#define DEFAULT_WARN_HTTP_REPLY         HTTP_TOO_MANY_REQUESTS
#define DEFAULT_BLOCK_HTTP_REPLY        HTTP_FORBIDDEN

#define MAX_BUF_LEN 1000000

static const char hex_chars[] = "0123456789ABCDEF";

typedef struct {
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
} ip_node_t;

typedef struct {
    ip_node_t *data;
    size_t size;
} ip_vector_t;

typedef struct {
#ifdef PCRE2
    pcre2_code *re;
    pcre2_match_data *match_data;
#else
    regex_t re;
#endif
    double reputation;
} re_node_t;

typedef struct {
    re_node_t *data;
    size_t size;
} re_vector_t;

typedef struct {
    u_int32_t asn;
    double reputation;
} asn_node_t;

typedef struct {
    asn_node_t *data;
    size_t size;
} asn_vector_t;

typedef struct {
    char *code;
    double reputation;
} country_node_t;

typedef struct {
    country_node_t *data;
    size_t size;
} country_vector_t;

typedef struct {
    uint32_t status;
    double reputation;
} status_node_t;

typedef struct {
    status_node_t *data;
    size_t size;
} status_vector_t;

typedef struct {
    u_int32_t asn;
    size_t count;
    time_t lastSeen;
} asn_count_t;

typedef struct {
    asn_count_t *data;
    size_t size;
} asn_count_vector_t;

typedef struct {
    ip_node_t addr;
    size_t count;
    time_t lastSeen;
} nw_count_t;

typedef struct {
    nw_count_t *data;
    size_t size;
} nw_count_vector_t;

typedef struct {
    u_int32_t asn;
    char *countryCode;
    ip_node_t addr;

    size_t count;
    time_t lastSeen;

    double ipReputation;
    double uaReputation;
    double uriReputation;
    double asnReputation;
    double countryReputation;
    double statusReputation;
    double reputation;
} req_node_t;

typedef struct {
    req_node_t *data;
    size_t size;
} req_vector_t;

typedef struct {
    apr_pool_t *pool;

    int enabled;
    char *asnDBPath;
    char *countryDBPath;
    ip_vector_t ipReputation;
    re_vector_t uaReputation;
    re_vector_t uriReputation;
    asn_vector_t asnReputation;
    country_vector_t countryReputation;
    status_vector_t statusReputation;
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
    asn_count_vector_t asns;
    nw_count_vector_t networks;
    req_vector_t requests;

    char *stateTemplate;

    char *powTemplate;
    char *powURI;
    char *powCookiePassphrase;
    int powDifficulty;
    int powCookieMaxAge;
    double powAboveReputation;
    double powBelowReputation;
} repudiator_config_t;

// --------------------------------------------------------------------------------------------------------------------
// Counters
// --------------------------------------------------------------------------------------------------------------------

typedef struct {
    unsigned long requests;
    unsigned long blocked;
    unsigned long warned;
    unsigned long powRequests;
    unsigned long powCIFailed;
    unsigned long powCompleted;
    time_t updated;
} counters_t;

typedef struct {
    apr_status_t enabled;
    counters_t *counter;
    apr_time_t lastUpdate;
    apr_pool_t *pool;
    server_rec *s;
} repudiator_counters_t;

static repudiator_counters_t *repudiator_counters = NULL;

// --------------------------------------------------------------------------------------------------------------------
// Utils
// --------------------------------------------------------------------------------------------------------------------

static void qsToTable(const char *input, apr_table_t *parms, apr_pool_t *p);

static apr_table_t *parseFormData(request_rec *r);

static void *reallocArray(void *ptr, size_t nmemb, size_t size);

static int startsWith(const char *str, const char *prefix);

// https://stackoverflow.com/questions/779875/what-function-is-to-replace-a-substring-from-a-string-in-c
static char *strReplace(char *orig, char *rep, char *with);

static char *bin_to_hex(const unsigned char *data, size_t len);

static int hex_value(char c);

static unsigned char *hex_to_bin(const char *hex, size_t hex_len, size_t *out_len);

static uint32_t prefix2mask(int prefix);

static void ipv6ApplyMask(struct in6_addr *restrict addr, const struct in6_addr *restrict mask);

static int ipv6PrefixToMask(unsigned prefix, struct in6_addr *mask);

static int isInRange(const ip_node_t *range, const ip_node_t *ipNode);

static int convertAddress(const char *addr, ip_node_t *ipNode);

static char const *getClientIp(request_rec *r);

// --------------------------------------------------------------------------------------------------------------------
// Reputation
// --------------------------------------------------------------------------------------------------------------------

static int parseIPReputation(ip_vector_t *ipReputation, const char *ipm, const char *rep);

static int parseRegexReputation(re_vector_t *reVector, const char *regex, const char *rep);

static int parseASNReputation(asn_vector_t *asnVector, const char *asn, const char *rep);

static int parseCountryReputation(apr_pool_t *p, country_vector_t *countryVector, const char *code, const char *rep);

static int parseStatusReputation(status_vector_t *statusVector, const char *ret, const char *rep);

static double calcIPReputation(const ip_vector_t *ipReputation, const ip_node_t *ipNode);

static double calcRegexReputation(const re_vector_t *reVector, const char *str);

static double calcASNReputation(const asn_vector_t *asnVector, u_int32_t asn);

static double calcCountryReputation(const country_vector_t *countryVector, const char *code);

static double calcStatusReputation(const status_vector_t *statusVector, u_int32_t status);

static uint32_t lookupIPInfo(const MMDB_s *mmdb, ip_node_t *node);

static char *lookupCountryInfo(const MMDB_s *mmdb, const ip_node_t *node);

static long findRequest(const req_vector_t *requests, const ip_node_t *ip);

static req_node_t *addRequest(repudiator_config_t *cfg, const ip_node_t *ip, uint32_t asn, const char *countryCode,
                              const char *userAgent, const char *uri, time_t timestamp);

static int removeRequest(req_vector_t *requests, size_t idx);

static void cleanRequests(req_vector_t *requests, time_t before);

static long findNetwork(const nw_count_vector_t *networks, const ip_node_t *addr);

static int removeNetwork(nw_count_vector_t *networks, size_t idx);

static int incNetworkCount(nw_count_vector_t *networks, const ip_node_t *addr, time_t update, time_t scanTime);

static void cleanNetworks(nw_count_vector_t *networks, time_t before);

static long findASN(const asn_count_vector_t *asns, u_int32_t asn);

static int removeASN(asn_count_vector_t *asns, size_t idx);

static int incASNCount(asn_count_vector_t *asns, u_int32_t asn, time_t update, time_t scanTime);

static void cleanASNs(asn_count_vector_t *asns, time_t before);

static int reputationState(const repudiator_config_t *cfg, double reputation);

static double calcReputation(const repudiator_config_t *cfg, const req_node_t *reqNode, int type);

static int accessChecker(request_rec *r);

static int doHeaders(const repudiator_config_t *cfg, request_rec *r, apr_table_t *headers);

static int handleStatusCode(const repudiator_config_t *cfg, request_rec *r);

static apr_status_t headersOutputFilter(ap_filter_t *f, apr_bucket_brigade *in);

static apr_status_t headersErrorFilter(ap_filter_t *f, apr_bucket_brigade *in);

// --------------------------------------------------------------------------------------------------------------------
// POW Challenge
// --------------------------------------------------------------------------------------------------------------------

static int countLeadingZeroBits(const uint8_t *hash, size_t nbytes);

static void xorCrypt(char *data, size_t length, const char *key, size_t key_length);

static char *xorEncrypt(const char *data, const char *passphrase);

static char *xorDecrypt(const char *data, const char *passphrase);

static void powGenerateRandomChallenge(char *challenge, size_t bytes);

static int powValidateClientInfo(const char *ci);

static int powCookieHandler(request_rec *r);

static int powChallenge(request_rec *r);

// --------------------------------------------------------------------------------------------------------------------
// Counters
// --------------------------------------------------------------------------------------------------------------------

static const char *statsFilename(apr_pool_t *pool);

static apr_status_t statsEnabled(apr_pool_t *pool);

static apr_status_t readStats(apr_pool_t *pool, counters_t *counters);

static apr_status_t writeStats(apr_pool_t *pool, const counters_t *counters);

static apr_status_t updateStats();

static void incNumRequests();

static void incNumBlocked();

static void incNumWarned();

static void incNumPOWRequests();

static void incNumPOWCIFailed();

static void incNumPOWCompleted();

static int counterStats(request_rec *r);

// --------------------------------------------------------------------------------------------------------------------
// Utils
// --------------------------------------------------------------------------------------------------------------------

static void *reallocArray(void *ptr, const size_t nmemb, const size_t size) {
    if (size && nmemb > SIZE_MAX / size) {
        errno = ENOMEM;
        return NULL;
    }

    void **tmp = realloc(ptr, nmemb * size);

    if (!tmp) {
        if (ptr) free(ptr);
        tmp = malloc(nmemb * size);
    }

    ptr = tmp;

    return ptr;
}

static int startsWith(const char *str, const char *prefix) {
    while (*prefix && *str == *prefix) ++str, ++prefix;
    return *prefix == 0;
}

static char *strReplace(char *orig, char *rep, char *with) {
    char *result; // the return string
    char *ins; // the next insert point
    char *tmp; // varies
    size_t len_rep; // length of rep (the string to remove)
    size_t len_with; // length of with (the string to replace rep with)
    size_t len_front; // distance between rep and end of last rep
    size_t count; // number of replacements

    // sanity checks and initialization
    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL; // empty rep causes infinite loop during count
    if (!with)
        with = "";
    len_with = strlen(with);

    // count the number of replacements needed
    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
}

static char *bin_to_hex(const unsigned char *data, const size_t len) {
    if (data == NULL && len != 0)
        return NULL;

    char *hex = (char *) malloc(len * 2 + 1);
    if (hex == NULL)
        return NULL;

    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[data[i] >> 4];
        hex[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }

    hex[len * 2] = '\0';

    return hex;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}

unsigned char *hex_to_bin(const char *hex, size_t hex_len, size_t *out_len) {
    if (hex == NULL || out_len == NULL)
        return NULL;

    if ((hex_len & 1) != 0)
        return NULL;

    *out_len = hex_len / 2;

    if (*out_len == 0)
        return NULL;

    unsigned char *data = (unsigned char *) malloc(*out_len);
    if (data == NULL)
        return NULL;

    for (size_t i = 0; i < *out_len; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            free(data);
            *out_len = 0;
            return NULL;
        }

        data[i] = (unsigned char) ((hi << 4) | lo);
    }

    return data;
}

static void qsToTable(const char *input, apr_table_t *parms, apr_pool_t *p) {
    char *strtok_state;

    if (input == NULL) {
        return;
    }

    char *query_string = apr_pstrdup(p, input);

    char *key = apr_strtok(query_string, "&", &strtok_state);
    while (key) {
        char *value = strchr(key, '=');
        if (value) {
            *value = '\0';
            value++;
        } else {
            value = "1";
        }
        ap_unescape_url(key);
        ap_unescape_url(value);
        apr_table_set(parms, key, value);
        key = apr_strtok(NULL, "&", &strtok_state);
    }
}

static apr_table_t *parseFormData(request_rec *r) {
    apr_table_t *tbl;
    apr_array_header_t *pairs = NULL;
    apr_off_t len;
    apr_size_t size;
    char *buffer;

    int res = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);
    if (res != OK || !pairs) return NULL;

    tbl = apr_table_make(r->pool, pairs->nelts + 1);

    while (pairs && !apr_is_empty_array(pairs)) {
        ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
        apr_brigade_length(pair->value, 1, &len);
        size = (apr_size_t) len;
        buffer = apr_palloc(r->pool, size + 1);
        apr_brigade_flatten(pair->value, buffer, &size);
        buffer[len] = 0;
        apr_table_set(tbl, apr_pstrdup(r->pool, pair->name), buffer);
    }

    return tbl;
}

static char const *getClientIp(request_rec *r) {
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    return r->useragent_ip;
#else
    return r->connection->remote_ip;
#endif
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

static int isInRange(const ip_node_t *range, const ip_node_t *ipNode) {
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

static int convertAddress(const char *addr, ip_node_t *ipNode) {
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

// --------------------------------------------------------------------------------------------------------------------
// Reputation
// --------------------------------------------------------------------------------------------------------------------

static int parseIPReputation(ip_vector_t *ipReputation, const char *ipm, const char *rep) {
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
                if (pos < sizeof(addr) - 1) {
                    addr[pos] = ipm[i];
                    ++pos;
                }
            } else {
                if (pos < sizeof(mask) - 1) {
                    mask[pos] = ipm[i];
                    ++pos;
                }
            }
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
        ip_node_t *node = reallocArray(ipReputation->data, ipReputation->size + 1, sizeof(*(ipReputation->data)));
        if (!node) {
            return -1;
        }

        ipReputation->data = node;

        if (family == AF_INET) {
            ipReputation->data[ipReputation->size++] = (ip_node_t){
                .family = AF_INET,
                .ip.v4 = ipv4,
                .mask.v4 = mv4,
                .reputation = strtod(rep, NULL)
            };
        } else {
            ipReputation->data[ipReputation->size++] = (ip_node_t){
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

static int parseRegexReputation(re_vector_t *reVector, const char *regex, const char *rep) {
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

            re_node_t *node = reallocArray(reVector->data, reVector->size + 1, sizeof(*(reVector->data)));
            if (!node) {
                pcre2_match_data_free(match_data);
                pcre2_code_free(re);
                return -1;
            }

            reVector->data = node;
            reVector->data[reVector->size++] = (re_node_t){
                .re = re,
                .match_data = match_data,
                .reputation = strtod(rep, NULL)
            };
        }
#else
        regex_t re;
        rc = regcomp(&re, regex, REG_EXTENDED | REG_ICASE);

        if (!rc) {
            re_node_t *node = reallocArray(reVector->data, reVector->size + 1, sizeof(*(reVector->data)));
            if (!node) {
                return -1;
            }

            reVector->data = node;
            reVector->data[reVector->size++] = (re_node_t){
                .re = re,
                .reputation = strtod(rep, NULL)
            };
        }
#endif
    }

    return rc;
}

static int parseASNReputation(asn_vector_t *asnVector, const char *asn, const char *rep) {
    int rc = 0;

    if (strlen(asn) != 0 && strlen(rep) != 0) {
        asn_node_t *node = reallocArray(asnVector->data, asnVector->size + 1, sizeof(*(asnVector->data)));
        if (!node) {
            return -1;
        }

        asnVector->data = node;
        asnVector->data[asnVector->size++] = (asn_node_t){
            .asn = strtol(asn, NULL, 10),
            .reputation = strtod(rep, NULL)
        };
    } else {
        rc = -2;
    }

    return rc;
}

static int parseCountryReputation(apr_pool_t *p, country_vector_t *countryVector, const char *code, const char *rep) {
    int rc = 0;

    if (strlen(code) != 0 && strlen(rep) != 0) {
        country_node_t *node = reallocArray(countryVector->data, countryVector->size + 1,
                                            sizeof(*(countryVector->data)));
        if (!node) {
            return -1;
        }

        countryVector->data = node;
        countryVector->data[countryVector->size++] = (country_node_t){
            .code = apr_pstrdup(p, code),
            .reputation = strtod(rep, NULL)
        };
    } else {
        rc = -2;
    }

    return rc;
}

static int parseStatusReputation(status_vector_t *statusVector, const char *ret, const char *rep) {
    int rc = 0;

    if (strlen(ret) != 0 && strlen(rep) != 0) {
        uint32_t status = strtol(ret, NULL, 10);
        if (status < 99 || status > 599) {
            rc = -2;
        } else {
            status_node_t *node = reallocArray(statusVector->data, statusVector->size + 1,
                                               sizeof(*(statusVector->data)));
            if (!node) {
                return -1;
            }

            statusVector->data = node;
            statusVector->data[statusVector->size++] = (status_node_t){
                .status = status,
                .reputation = strtod(rep, NULL)
            };
        }
    } else {
        rc = -2;
    }

    return rc;
}

double calcIPReputation(const ip_vector_t *ipReputation, const ip_node_t *ipNode) {
    double rc = 0.0;
    for (size_t i = 0; i < ipReputation->size; ++i) {
        const ip_node_t *node = &ipReputation->data[i];
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

double calcRegexReputation(const re_vector_t *reVector, const char *str) {
    double ret = 0.0;
    if (str != NULL && strlen(str) != 0) {
        for (size_t i = 0; i < reVector->size; ++i) {
            const re_node_t *node = &reVector->data[i];
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

double calcASNReputation(const asn_vector_t *asnVector, const u_int32_t asn) {
    const asn_node_t *wnode = NULL;
    for (size_t i = 0; i < asnVector->size; ++i) {
        const asn_node_t *node = &asnVector->data[i];
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

double calcCountryReputation(const country_vector_t *countryVector, const char *code) {
    for (size_t i = 0; i < countryVector->size; ++i) {
        const country_node_t *node = &countryVector->data[i];
        if (code != NULL && node->code != NULL && strcasecmp(node->code, code) == 0) {
            return node->reputation;
        }
    }

    return 0.0;
}

double calcStatusReputation(const status_vector_t *statusVector, const u_int32_t status) {
    for (size_t i = 0; i < statusVector->size; ++i) {
        const status_node_t *node = &statusVector->data[i];
        if (node->status == status) {
            return node->reputation;
        }
    }
    return 0.0;
}

uint32_t lookupIPInfo(const MMDB_s *mmdb, ip_node_t *node) {
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

                const char **lookup_path = calloc(1, sizeof(*lookup_path));
                if (lookup_path == NULL) {
                    return 0;
                }
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

char *lookupCountryInfo(const MMDB_s *mmdb, const ip_node_t *node) {
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

                const char **lookup_path = calloc(2, sizeof(*lookup_path));
                if (lookup_path == NULL) {
                    return NULL;
                }
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

long findRequest(const req_vector_t *requests, const ip_node_t *ip) {
    long idx = -1;
    for (size_t i = 0; i < requests->size; ++i) {
        const req_node_t *node = &requests->data[i];
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

req_node_t *addRequest(repudiator_config_t *cfg, const ip_node_t *ip, const uint32_t asn,
                       const char *countryCode, const char *userAgent,
                       const char *uri, const time_t timestamp) {
    if (cfg == NULL || ip == NULL) {
        return NULL;
    }

    const long idx = findRequest(&cfg->requests, ip);
    if (idx == -1) {
        req_node_t *node = reallocArray(cfg->requests.data, cfg->requests.size + 1, sizeof(*(cfg->requests.data)));
        if (node == NULL) {
            return NULL;
        }

        cfg->requests.data = node;
        cfg->requests.data[cfg->requests.size++] = (req_node_t){
            .asn = asn,
            .countryCode = countryCode != NULL ? apr_pstrdup(cfg->pool, countryCode) : NULL,
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

    req_node_t *node = &cfg->requests.data[idx];

    if (node->lastSeen > timestamp - cfg->scanTime) {
        if (node->count == SIZE_MAX) {
            return NULL;
        }
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

int removeRequest(req_vector_t *requests, const size_t idx) {
    if (requests == NULL || idx >= requests->size || requests->data == NULL) {
        return -1;
    }

    requests->data[idx].countryCode = NULL;
    for (size_t i = idx; i + 1 < requests->size; ++i) {
        requests->data[i] = requests->data[i + 1];
    }
    --requests->size;
    if (requests->size == 0) {
        free(requests->data);
        requests->data = NULL;
        return 0;
    }

    /* Shrinking is an optimization only; failure must not corrupt the live vector. */
    void *tmp = reallocArray(requests->data, requests->size, sizeof(*(requests->data)));
    if (tmp != NULL) {
        requests->data = tmp;
    }
    return 0;
}

static void cleanRequests(req_vector_t *requests, const time_t before) {
    size_t idx = 0;
    while (idx < requests->size) {
        const req_node_t *node = &requests->data[idx];
        if (node->lastSeen < before) {
            removeRequest(requests, idx);
        } else {
            idx++;
        }
    }
}

long findNetwork(const nw_count_vector_t *networks, const ip_node_t *addr) {
    long idx = -1;

    for (size_t i = 0; i < networks->size; ++i) {
        const nw_count_t *node = &networks->data[i];
        if (isInRange(&node->addr, addr)) {
            idx = (long) i;
            break;
        }
    }

    return idx;
}

int removeNetwork(nw_count_vector_t *networks, const size_t idx) {
    if (networks == NULL || idx >= networks->size || networks->data == NULL) {
        return -1;
    }
    for (size_t i = idx; i + 1 < networks->size; ++i) {
        networks->data[i] = networks->data[i + 1];
    }
    --networks->size;
    if (networks->size == 0) {
        free(networks->data);
        networks->data = NULL;
        return 0;
    }

    /* Shrinking is an optimization only; failure must not corrupt the live vector. */
    void *tmp = reallocArray(networks->data, networks->size, sizeof(*(networks->data)));
    if (tmp != NULL) {
        networks->data = tmp;
    }
    return 0;
}

int incNetworkCount(nw_count_vector_t *networks, const ip_node_t *addr, const time_t update,
                    const time_t scanTime) {
    long idx = findNetwork(networks, addr);
    if (idx != -1) {
        nw_count_t *node = &networks->data[idx];
        if (node->lastSeen < update - scanTime)
            node->count = 1;
        else
            node->count++;
        node->lastSeen = update;
    } else {
        nw_count_t *node = reallocArray(networks->data, networks->size + 1, sizeof(*(networks->data)));
        if (node == NULL) {
            return -1;
        }

        networks->data = node;
        networks->data[networks->size++] = (nw_count_t){
            .addr = *addr,
            .count = 1,
            .lastSeen = update
        };
    }

    return 0;
}

void cleanNetworks(nw_count_vector_t *networks, const time_t before) {
    size_t idx = 0;
    while (idx < networks->size) {
        const nw_count_t *node = &networks->data[idx];
        if (node->lastSeen < before) {
            removeNetwork(networks, idx);
        } else {
            idx++;
        }
    }
}

long findASN(const asn_count_vector_t *asns, const u_int32_t asn) {
    long idx = -1;

    for (size_t i = 0; i < asns->size; ++i) {
        const asn_count_t *node = &asns->data[i];
        if (node->asn == asn) {
            idx = (long) i;
            break;
        }
    }

    return idx;
}

int removeASN(asn_count_vector_t *asns, const size_t idx) {
    if (asns == NULL || idx >= asns->size || asns->data == NULL) {
        return -1;
    }
    for (size_t i = idx; i + 1 < asns->size; ++i) {
        asns->data[i] = asns->data[i + 1];
    }
    --asns->size;
    if (asns->size == 0) {
        free(asns->data);
        asns->data = NULL;
        return 0;
    }

    /* Shrinking is an optimization only; failure must not corrupt the live vector. */
    void *tmp = reallocArray(asns->data, asns->size, sizeof(*(asns->data)));
    if (tmp != NULL) {
        asns->data = tmp;
    }
    return 0;
}

int incASNCount(asn_count_vector_t *asns, const u_int32_t asn, const time_t update, const time_t scanTime) {
    const long idx = findASN(asns, asn);
    if (idx != -1) {
        asn_count_t *node = &asns->data[idx];
        if (node->lastSeen < update - scanTime)
            node->count = 1;
        else
            node->count++;
        node->lastSeen = update;
    } else {
        asn_count_t *node = reallocArray(asns->data, asns->size + 1, sizeof(*(asns->data)));
        if (node == NULL) {
            return -1;
        }

        asns->data = node;
        asns->data[asns->size++] = (asn_count_t){
            .asn = asn,
            .count = 1,
            .lastSeen = update
        };
    }

    return 0;
}

void cleanASNs(asn_count_vector_t *asns, const time_t before) {
    size_t idx = 0;
    while (idx < asns->size) {
        const asn_count_t *node = &asns->data[idx];
        if (node->lastSeen < before) {
            removeASN(asns, idx);
        } else {
            idx++;
        }
    }
}

int reputationState(const repudiator_config_t *cfg, const double reputation) {
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

double calcReputation(const repudiator_config_t *cfg, const req_node_t *reqNode, const int type) {
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

static int accessChecker(request_rec *r) {
    repudiator_config_t *cfg = (repudiator_config_t *) ap_get_module_config(r->per_dir_config, &repudiator_module);

    int ret = OK;

    if (cfg->enabled && r->prev == NULL && r->main == NULL) {
        incNumRequests();

        apr_time_t t = r->request_time / 1000 / 1000;

        ip_node_t addr;
        if (convertAddress(getClientIp(r), &addr) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Couldn't parse ip address");
            return OK;
        }

        const uint32_t asn = lookupIPInfo(cfg->mmdbASN, &addr);
        const char *countryCode = lookupCountryInfo(cfg->mmdbCountry, &addr);
        const char *userAgent = apr_table_get(r->headers_in, "user-agent");

        incASNCount(&cfg->asns, asn, t, cfg->scanTime);
        incNetworkCount(&cfg->networks, &addr, t, cfg->scanTime);

        req_node_t *req = addRequest(cfg, &addr, asn, countryCode, userAgent, r->unparsed_uri, t);
        if (req == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Couldn't add request: OOM");
            return OK;
        }

        double basicRep = calcReputation(cfg, req, 0);
        double perIPRep = calcReputation(cfg, req, 1);
        double perNetRep = calcReputation(cfg, req, 2);
        double perASNRep = calcReputation(cfg, req, 3);

        req->reputation = basicRep + perIPRep + perNetRep + perASNRep + req->statusReputation;

        int repState = reputationState(cfg, req->reputation);

        if (req->reputation < cfg->powAboveReputation && req->reputation >= cfg->powBelowReputation) {
            if (powCookieHandler(r) != OK) {
                ap_cookie_remove(r, POW_PASSED_COOKIE, NULL, r->headers_out, r->err_headers_out, NULL);

                char location[HUGE_STRING_LEN] = {0};
                snprintf(location, sizeof(location), "%s?%s=%s", cfg->powURI, POW_REDIRECT_URI, r->unparsed_uri);
                apr_table_setn(r->headers_out, "Location", location);
                return r->method_number == M_POST || r->method_number == M_PUT
                           ? HTTP_SEE_OTHER
                           : HTTP_MOVED_TEMPORARILY;
            }

            req->uaReputation = 0;
            req->uriReputation = 0;
            req->statusReputation = 0;
            req->countryReputation = 0;
            req->asnReputation = 0;

            basicRep = calcReputation(cfg, req, 0);
            perIPRep = calcReputation(cfg, req, 1);
            perNetRep = calcReputation(cfg, req, 2);
            perASNRep = calcReputation(cfg, req, 3);

            req->reputation = basicRep + perIPRep + perNetRep + perASNRep + req->statusReputation;

            repState = reputationState(cfg, req->reputation);
        }

#ifdef REP_DEBUG
        long idx = findNetwork(&cfg->networks, &addr);
        const size_t nwCount = idx != -1 ? cfg->networks.data[idx].count : 0;

        idx = findASN(&cfg->asns, req->asn);
        const size_t asnCount = idx != -1 ? cfg->asns.data[idx].count : 0;
#endif

        cleanASNs(&cfg->asns, t - cfg->scanTime * 2);
        cleanNetworks(&cfg->networks, t - cfg->scanTime * 2);
        cleanRequests(&cfg->requests, t - cfg->scanTime * 2);

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

            snprintf(asnStr, sizeof(asnStr), "AS%x", asn);
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

            if (repState == REP_WARN) {
                incNumWarned();
            } else if (repState == REP_BLOCK) {
                incNumBlocked();
            }

#ifdef REP_DEBUG
            if (repState != REP_OK) { 
#endif

            if (cfg->stateTemplate != NULL && !r->header_only) {
                char json[MAX_BUF_LEN + 1] = {0};

                snprintf(
                    json,
                    sizeof(json),
                    "{\"state\": \"%s\", \"warn\": %4.2f, \"block\": %4.2f, \"ip\": %4.2f, \"asn\": %4.2f, \"ua\": %4.2f, \"uri\": %4.2f, \"country\": %4.2f, \"status\": %4.2f, \"perIp\": %4.2f, \"perNet\": %4.2f, \"perASN\": %4.2f}",
                    repState == REP_WARN ? "warn" : "block",
                    cfg->warnReputation,
                    cfg->blockReputation,
                    req->ipReputation / req->count,
                    req->asnReputation / req->count,
                    req->uaReputation / req->count,
                    req->uriReputation / req->count,
                    req->countryReputation / req->count,
                    req->statusReputation,
                    perIPRep,
                    perNetRep,
                    perASNRep
                );

                ap_set_content_type(r, "text/html");
                char *res = strReplace(cfg->stateTemplate, "{JSON}", json);
                ap_rputs(res, r);
                free(res);

                r->status = repState == REP_WARN ? cfg->warnHttpReply : cfg->blockHttpReply;

                updateStats();

                return DONE;
            }

            updateStats();

            return repState == REP_WARN ? cfg->warnHttpReply : cfg->blockHttpReply;
        }

        updateStats();
    }

    return ret;
}

int doHeaders(const repudiator_config_t *cfg, request_rec *r, apr_table_t *headers) {
    if (cfg->enabled) {
        ip_node_t addr;
        if (convertAddress(getClientIp(r), &addr) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Couldn't parse ip address");
            return DECLINED;
        }

        const long idx = findRequest(&cfg->requests, &addr);
        if (idx != -1) {
            const req_node_t *req = &cfg->requests.data[idx];

            const int repState = reputationState(cfg, req->reputation);

            char repStr[50] = {0};
            snprintf(repStr, sizeof(repStr), "%s (%4.2f)",
                     repState == REP_OK ? "OK" : repState == REP_WARN ? "WARN" : "BLOCK", req->reputation);

            if (apr_table_get(headers, X_HEADER_REPUTATION) != NULL) {
                apr_table_unset(headers, X_HEADER_REPUTATION);
            }

            apr_table_add(headers, X_HEADER_REPUTATION, apr_pstrdup(r->pool, repStr));
        }
    }

    return OK;
}

int handleStatusCode(const repudiator_config_t *cfg, request_rec *r) {
    if (cfg->enabled) {
        ip_node_t addr;
        if (convertAddress(getClientIp(r), &addr) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Couldn't parse ip address");
            return DECLINED;
        }

        const long idx = findRequest(&cfg->requests, &addr);
        if (idx != -1) {
            req_node_t *req = &cfg->requests.data[idx];
            req->statusReputation += calcStatusReputation(&cfg->statusReputation, r->status);
        }
    }

    return OK;
}

static apr_status_t headersOutputFilter(ap_filter_t *f, apr_bucket_brigade *in) {
    const repudiator_config_t *cfg = (repudiator_config_t *) ap_get_module_config(
        f->r->per_dir_config, &repudiator_module);

    doHeaders(cfg, f->r, f->r->headers_out);

    handleStatusCode(cfg, f->r);

    ap_remove_output_filter(f);

    return ap_pass_brigade(f->next, in);
}

static apr_status_t headersErrorFilter(ap_filter_t *f, apr_bucket_brigade *in) {
    const repudiator_config_t *cfg = (repudiator_config_t *) ap_get_module_config(
        f->r->per_dir_config, &repudiator_module);

    doHeaders(cfg, f->r, f->r->err_headers_out);

    handleStatusCode(cfg, f->r);

    ap_remove_output_filter(f);

    return ap_pass_brigade(f->next, in);
}

// --------------------------------------------------------------------------------------------------------------------
// POW Challenge
// --------------------------------------------------------------------------------------------------------------------

int countLeadingZeroBits(const uint8_t *hash, size_t nbytes) {
    int zeroBits = 0;

    for (int i = 0; i < nbytes; i++) {
        if (hash[i] == 0) {
            zeroBits += 8;
        } else {
            uint8_t byte = hash[i];
            while (byte < 128) {
                zeroBits++;
                byte <<= 1;
            }
            break;
        }
    }

    return zeroBits;
}

static void xorCrypt(char *data, const size_t length, const char *key, const size_t key_length) {
    size_t i;

    if (data == NULL || key == NULL || key_length == 0) {
        return;
    }

    for (i = 0; i < length; ++i) {
        data[i] ^= key[i % key_length];
    }
}

static char *xorEncrypt(const char *data, const char *passphrase) {
    const size_t len = strlen(data);
    char *tmp = strdup(data);

    xorCrypt(tmp, len, passphrase, strlen(passphrase));
    char *hex = bin_to_hex((unsigned char *) tmp, len);
    free(tmp);

    return hex;
}

static char *xorDecrypt(const char *data, const char *passphrase) {
    size_t outlen;
    const size_t len = strlen(data);

    char *decoded = (char *) hex_to_bin(data, len, &outlen);
    xorCrypt(decoded, outlen, passphrase, strlen(passphrase));

    return decoded;
}

static void powGenerateRandomChallenge(char *challenge, const size_t bytes) {
    if (challenge == NULL || bytes == 0) {
        return;
    }

    srand((unsigned int) time(NULL));

    for (size_t i = 0; i < bytes - 1; i++) {
        challenge[i] = (char) rand();
    }
    challenge[bytes - 1] = '\0';
}

static int powValidateClientInfo(const char *ci) {
    if (ci == NULL) return DECLINED;

    JsonValue *cijson = readValue(&ci);
    if (cijson != NULL) {
        const JsonValue *webdriver = getValue(cijson, "webdriver");
        if (webdriver != NULL &&
            webdriver->type == TYPE_BOOL && webdriver->boolValue == 1) {
            return DECLINED;
        }

        const JsonValue *headless = getValue(cijson, "headless");
        if (headless != NULL &&
            headless->type == TYPE_BOOL && headless->boolValue == 1) {
            return DECLINED;
        }

        const JsonValue *cookieEnabled = getValue(cijson, "cookieEnabled");
        if (cookieEnabled != NULL &&
            cookieEnabled->type == TYPE_BOOL && cookieEnabled->boolValue == 0) {
            return DECLINED;
        }

        const JsonValue *hardwareConcurrency = getValue(cijson, "hardwareConcurrency");
        if (hardwareConcurrency != NULL &&
            hardwareConcurrency->type == TYPE_NUMBER && hardwareConcurrency->numberValue == 0) {
            return DECLINED;
        }

        const JsonValue *screenResolution = getValue(cijson, "screenResolution");
        if (screenResolution != NULL &&
            screenResolution->type == TYPE_STRING && strcmp("0x0", screenResolution->stringValue) == 0) {
            return DECLINED;
        }

        const JsonValue *colorDepth = getValue(cijson, "colorDepth");
        if (colorDepth != NULL &&
            colorDepth->type == TYPE_NUMBER && colorDepth->numberValue == 0) {
            return DECLINED;
        }

        const JsonValue *languages = getValue(cijson, "languages");
        if (languages != NULL &&
            languages->type == TYPE_ARRAY && languages->arrayValue.count == 0) {
            return DECLINED;
        }
    }

    return OK;
}

static int powCookieHandler(request_rec *r) {
    int ret = DECLINED;
    const char *cookie_value = NULL;

    const repudiator_config_t *cfg = (repudiator_config_t *)
            ap_get_module_config(r->per_dir_config, &repudiator_module);

    apr_status_t status = ap_cookie_read(r, POW_PASSED_COOKIE, &cookie_value, 0);
    if (status == APR_SUCCESS && cookie_value != NULL) {
        const char *token = cfg->powCookiePassphrase != NULL
                                ? xorDecrypt(ap_pbase64decode(r->pool, cookie_value), cfg->powCookiePassphrase)
                                : ap_pbase64decode(r->pool, cookie_value);

        if (token != NULL) {
            JsonValue *tjson = readValue(&token);
            if (tjson != NULL) {
                const JsonValue *ip = getValue(tjson, "ip");
                const JsonValue *expire = getValue(tjson, "expire");
                if (ip != NULL && ip->type == TYPE_STRING && expire != NULL && expire->type == TYPE_NUMBER) {
                    if (strcmp(ip->stringValue, getClientIp(r)) == 0 &&
                        (unsigned long) expire->numberValue > time(NULL)) {
                        ret = OK;
                    }
                }
            }
        }
    }

    return ret;
}

static int powChallenge(request_rec *r) {
    repudiator_config_t *cfg = (repudiator_config_t *) ap_get_module_config(r->per_dir_config, &repudiator_module);

    if (!r->uri || startsWith(r->uri, cfg->powURI) == 0) return (DECLINED);

    if (r->method_number == M_GET) {
        if (cfg->powTemplate != NULL) {
            char challenge[17] = {};
            powGenerateRandomChallenge(challenge, sizeof(challenge));

            apr_table_t *tbl = apr_table_make(r->pool, 10);
            qsToTable(r->parsed_uri.query, tbl, r->pool);
            const char *uri = apr_table_get(tbl, POW_REDIRECT_URI);

            char json[HUGE_STRING_LEN] = {0};

            snprintf(
                json,
                sizeof(json),
                "{\"challenge\": \"%s\", \"difficulty\": %d, \"powURI\": \"%s\", \"uri\": \"%s\"}",
                ap_pbase64encode(r->pool, challenge),
                cfg->powDifficulty,
                cfg->powURI,
                uri == NULL ? "/" : uri
            );

            ap_set_content_type(r, "text/html");
            char *res = strReplace(cfg->powTemplate, "{TOKEN}", ap_pbase64encode(r->pool, json));
            ap_rputs(res, r);
            free(res);

            incNumPOWRequests();

            return DONE;
        }
    } else if (r->method_number == M_POST) {
        const apr_table_t *formData = parseFormData(r);

        if (formData != NULL) {
            const char *et = apr_table_get(formData, "pow_challenge_token");
            const char *ps = apr_table_get(formData, "pow_solution");
            const char *ci = apr_table_get(formData, "information");

            if (et != NULL && ps != NULL && ci != NULL) {
                if (powValidateClientInfo(ci) != OK) {
                    incNumPOWCIFailed();
                    return (DECLINED);
                }

                const char *token = ap_pbase64decode(r->pool, et);
                JsonValue *tjson = readValue(&token);
                if (tjson != NULL) {
                    char location[HUGE_STRING_LEN] = {0};
                    const JsonValue *challenge = getValue(tjson, "challenge");
                    const JsonValue *difficulty = getValue(tjson, "difficulty");
                    const JsonValue *uri = getValue(tjson, "uri");

                    if (challenge != NULL && difficulty != NULL
                        && challenge->type == TYPE_STRING && difficulty->type == TYPE_NUMBER) {
                        char input[SHA256_BYTES_SIZE] = {};
                        snprintf(input, sizeof(input), "%s%d", ap_pbase64decode(r->pool, challenge->stringValue),
                                 (int) strtol(ps, NULL, 10));

                        uint8_t hex[SHA256_BYTES_SIZE];
                        sha256_bytes(input, strlen(input), hex);

                        const int zeroBits = countLeadingZeroBits(hex, SHA256_BYTES_SIZE);
                        if (zeroBits >= difficulty->numberValue) {
                            char cookie_val[HUGE_STRING_LEN] = {0};

                            snprintf(
                                cookie_val,
                                sizeof(cookie_val),
                                "{\"ip\": \"%s\", \"expire\": %lu}",
                                getClientIp(r),
                                time(NULL) + cfg->powCookieMaxAge
                            );

                            ap_cookie_write(r, POW_PASSED_COOKIE,
                                            ap_pbase64encode(
                                                r->pool, cfg->powCookiePassphrase != NULL
                                                             ? xorEncrypt(cookie_val, cfg->powCookiePassphrase)
                                                             : cookie_val),
                                            "Path=/; HttpOnly; SameSite=lax;",
                                            cfg->powCookieMaxAge, r->headers_out, r->err_headers_out,
                                            NULL);

                            if (uri != NULL && uri->type == TYPE_STRING
                                && startsWith(uri->stringValue, cfg->powURI) == 0) {
                                snprintf(location, sizeof(location), "%s", uri->stringValue);
                            } else {
                                snprintf(location, sizeof(location), "%s", "/");
                            }

                            incNumPOWCompleted();
                        } else {
                            snprintf(location, sizeof(location), "%s?%s=%s", cfg->powURI, POW_REDIRECT_URI,
                                     uri->stringValue);
                        }

                        apr_table_setn(r->headers_out, "Location", location);
                        return HTTP_MOVED_TEMPORARILY;
                    }
                }
            }
        }
    }

    return (DECLINED);
}

// --------------------------------------------------------------------------------------------------------------------
// Counters
// --------------------------------------------------------------------------------------------------------------------
static const char *statsFilename(apr_pool_t *pool) {
    const char *fname = ap_runtime_dir_relative(pool, "repudiator_stats");
    return fname;
}

static apr_status_t statsEnabled(apr_pool_t *pool) {
    apr_status_t rv = APR_SUCCESS;
    apr_file_t *f;

    const char *fname = statsFilename(pool);
    const apr_int32_t flags = APR_FOPEN_CREATE | APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_BINARY |
                              APR_FOPEN_XTHREAD;
    if ((rv = apr_file_open(&f, fname, flags, APR_FPROT_OS_DEFAULT, pool)) == APR_SUCCESS) {
        apr_file_close(f);
        apr_file_perms_set(fname, APR_FPROT_UREAD | APR_FPROT_UWRITE |
                                  APR_FPROT_GREAD | APR_FPROT_GWRITE |
                                  APR_FPROT_WREAD | APR_FPROT_WWRITE);
    }

    return rv;
}

static apr_status_t readStats(apr_pool_t *pool, counters_t *counters) {
    apr_file_t *f;
    apr_status_t rv = APR_SUCCESS;

    if (repudiator_counters != NULL && repudiator_counters->enabled == APR_SUCCESS) {
        const apr_int32_t flags = APR_FOPEN_CREATE | APR_FOPEN_READ | APR_FOPEN_BINARY | APR_FOPEN_XTHREAD;
        if ((rv = apr_file_open(&f, statsFilename(pool), flags, APR_FPROT_OS_DEFAULT, pool)) != APR_SUCCESS) {
            return rv;
        }

        rv = apr_file_lock(f, APR_FLOCK_SHARED);
        if (rv != APR_SUCCESS) {
            apr_file_close(f);
            return rv;
        }

        apr_size_t size = sizeof(counters_t);
        apr_file_read(f, counters, &size);

        apr_file_unlock(f);

        apr_file_close(f);
    }

    return rv;
}

static apr_status_t writeStats(apr_pool_t *pool, const counters_t *counters) {
    apr_file_t *f;
    apr_status_t rv = APR_SUCCESS;

    if (repudiator_counters != NULL && repudiator_counters->enabled == APR_SUCCESS) {
        const apr_int32_t flags = APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_BINARY | APR_FOPEN_XTHREAD;
        if ((rv = apr_file_open(&f, statsFilename(pool), flags, APR_FPROT_OS_DEFAULT, pool)) != APR_SUCCESS) {
            return rv;
        }

        rv = apr_file_lock(f, APR_FLOCK_EXCLUSIVE);
        if (rv != APR_SUCCESS) {
            apr_file_close(f);
            return rv;
        }

        apr_size_t size = sizeof(counters_t);
        apr_file_write(f, counters, &size);

        apr_file_unlock(f);

        apr_file_close(f);
    }

    return rv;
}

static apr_status_t updateStats() {
    apr_status_t rv = APR_SUCCESS;

    if (repudiator_counters != NULL && repudiator_counters->enabled == APR_SUCCESS
        && (repudiator_counters->lastUpdate == 0 || apr_time_now() - repudiator_counters->lastUpdate > 1000 * 1000)) {
        apr_pool_t *pool;
        apr_pool_create(&pool, repudiator_counters->pool);

        counters_t *counters = apr_palloc(pool, sizeof(counters_t));
        if (counters == NULL) {
            return APR_ENOMEM;
        }

        *counters = (counters_t){
            .requests = 0,
            .blocked = 0,
            .warned = 0,
            .powRequests = 0,
            .powCIFailed = 0,
            .powCompleted = 0
        };

        if ((rv = readStats(pool, counters)) != APR_SUCCESS) {
            apr_pool_destroy(pool);
            return rv;
        }

        counters->requests += repudiator_counters->counter->requests;
        counters->blocked += repudiator_counters->counter->blocked;
        counters->warned += repudiator_counters->counter->warned;
        counters->powRequests += repudiator_counters->counter->powRequests;
        counters->powCIFailed += repudiator_counters->counter->powCIFailed;
        counters->powCompleted += repudiator_counters->counter->powCompleted;
        counters->updated = time(NULL);

        if ((rv = writeStats(pool, counters)) == APR_SUCCESS) {
            *repudiator_counters->counter = (counters_t){
                .requests = 0,
                .blocked = 0,
                .warned = 0,
                .powRequests = 0,
                .powCIFailed = 0,
                .powCompleted = 0
            };

            repudiator_counters->lastUpdate = apr_time_now();
        }

        apr_pool_destroy(pool);
    }

    return rv;
}

static void incNumRequests() {
    if (repudiator_counters != NULL) {
        repudiator_counters->counter->requests++;
    }
}

static void incNumBlocked() {
    if (repudiator_counters != NULL) {
        repudiator_counters->counter->blocked++;
    }
}

static void incNumWarned() {
    if (repudiator_counters != NULL) {
        repudiator_counters->counter->warned++;
    }
}

static void incNumPOWRequests() {
    if (repudiator_counters != NULL) {
        repudiator_counters->counter->powRequests++;
    }
}

static void incNumPOWCIFailed() {
    if (repudiator_counters != NULL) {
        repudiator_counters->counter->powCIFailed++;
    }
}

static void incNumPOWCompleted() {
    if (repudiator_counters != NULL) {
        repudiator_counters->counter->powCompleted++;
    }
}

static int counterStats(request_rec *r) {
    if (strcmp(r->handler, REP_STATS_MAGIC_TYPE) && strcmp(r->handler, REP_STATS)) {
        return DECLINED;
    }

    if (repudiator_counters->enabled != APR_SUCCESS) {
        return HTTP_NOT_FOUND;
    }

    if (r->method_number != M_GET) {
        return DECLINED;
    }

    ap_set_content_type(r, "application/json");

    counters_t *counters = apr_palloc(repudiator_counters->pool, sizeof(counters_t));
    readStats(repudiator_counters->pool, counters);

    char *version = strReplace(STR(REP_VERSION), "\"", "");

    ap_rprintf(r,
               "{\"version\": \"%s\", \"requests\": %lu, \"blocked\": %lu, \"warned\": %lu, \"powRequests\": %lu, \"powCIFailed\": %lu, \"powCompleted\": %lu, \"updated\": %lu}\n",
               version, counters->requests, counters->blocked, counters->warned, counters->powRequests,
               counters->powCIFailed, counters->powCompleted, counters->updated
    );

    return DONE;
}

// --------------------------------------------------------------------------------------------------------------------
// Module
// --------------------------------------------------------------------------------------------------------------------

static int preConfigHook(apr_pool_t *mp, apr_pool_t *mp_log, apr_pool_t *mp_temp) {
    void *data = NULL;
    const char *key = "repudiator-pre-config-init-flag";
    int first_time = 0;

    apr_pool_userdata_get(&data, key, mp);
    if (data == NULL) {
        apr_pool_userdata_set((const void *) 1, key, apr_pool_cleanup_null, mp);
        first_time = 1;
    }

    if (!first_time) {
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, "ModRepudiator version %s", STR(REP_VERSION));

    return OK;
}

static int postConfigHook(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    const char *pk = "repudiator_init_module_tag";
    apr_pool_t *pproc = s->process->pool;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    apr_pool_userdata_get((void *) &repudiator_counters, pk, pproc);
    if (!repudiator_counters) {
        if (!(repudiator_counters = apr_pcalloc(pproc, sizeof(repudiator_counters_t))))
            return APR_ENOMEM;

        if (!(repudiator_counters->counter = apr_pcalloc(pproc, sizeof(counters_t))))
            return APR_ENOMEM;

        apr_pool_create(&repudiator_counters->pool, pproc);

        repudiator_counters->enabled = statsEnabled(repudiator_counters->pool);
        if (repudiator_counters->enabled != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                         "Couldn't access repudiator stats file '%s'. Create it manual.",
                         statsFilename(repudiator_counters->pool));
        }

        apr_pool_userdata_set(repudiator_counters, pk, apr_pool_cleanup_null, pproc);
    }
    repudiator_counters->s = s;

    return OK;
}

static void headersInsertOutputFilter(request_rec *r) {
    ap_add_output_filter(FIXUP_HEADERS_OUT_FILTER, NULL, r, r->connection);
}

static void headersInsertErrorFilter(request_rec *r) {
    ap_add_output_filter(FIXUP_HEADERS_ERR_FILTER, NULL, r, r->connection);
}

static void destroyREVector(const re_vector_t *vec) {
#ifdef PCRE2
    for (size_t i = 0; i < vec->size; i++) {
        re_node_t *node = &vec->data[i];
        pcre2_code_free(node->re);
        pcre2_match_data_free(node->match_data);
    }
#else
    for (size_t i = 0; i < vec->size; i++) {
        regfree(&vec->data[i].re);
    }
#endif
    free(vec->data);
}

static apr_status_t destroyConfig(void *dconfig) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

    if (cfg != NULL) {
        free(cfg->ipReputation.data);
        destroyREVector(&cfg->uaReputation);
        destroyREVector(&cfg->uriReputation);
        free(cfg->asnReputation.data);
        free(cfg->statusReputation.data);
        free(cfg->countryReputation.data);
        free(cfg->requests.data);
        free(cfg->networks.data);
        free(cfg->asns.data);
    }
    return APR_SUCCESS;
}

static void *createDirConf(apr_pool_t *p, __attribute__((unused)) char *context) {
    repudiator_config_t *cfg = apr_palloc(p, sizeof(repudiator_config_t));
    if (!cfg) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Failed to allocate configuration");
        return NULL;
    }

    *cfg = (repudiator_config_t){
        .pool = p,
        .enabled = 0,
        .asnDBPath = NULL,
        .countryDBPath = NULL,
        .ipReputation = (ip_vector_t){.data = NULL, .size = 0},
        .uaReputation = (re_vector_t){.data = NULL, .size = 0},
        .uriReputation = (re_vector_t){.data = NULL, .size = 0},
        .asnReputation = (asn_vector_t){.data = NULL, .size = 0},
        .countryReputation = (country_vector_t){.data = NULL, .size = 0},
        .warnReputation = DEFAULT_WARN_REPUTATION,
        .blockReputation = DEFAULT_BLOCK_REPUTATION,
        .perIPReputation = DEFAULT_PER_IP_REPUTATION,
        .perNetworkReputation = DEFAULT_PER_NET_REPUTATION,
        .perASNReputation = DEFAULT_PER_ASN_REPUTATION,
        .scanTime = DEFAULT_SCAN_TIME,
        .warnHttpReply = DEFAULT_WARN_HTTP_REPLY,
        .blockHttpReply = DEFAULT_BLOCK_HTTP_REPLY,
        .asns = (asn_count_vector_t){.data = NULL, .size = 0},
        .networks = (nw_count_vector_t){.data = NULL, .size = 0},
        .requests = (req_vector_t){.data = NULL, .size = 0},
        .stateTemplate = apr_pstrdup(p, (const char *) state_html_file),
        .powTemplate = apr_pstrdup(p, (const char *) pow_html_file),
        .powURI = apr_pstrdup(p, DEFAULT_POW_URI),
        .powCookiePassphrase = NULL,
        .powDifficulty = DEFAULT_POW_DIFFICULTY,
        .powCookieMaxAge = DEFAULT_POW_COOKIE_MAXAGE,
        .powAboveReputation = DEFAULT_POW_ABOVE_REPUTATION,
        .powBelowReputation = DEFAULT_POW_BELOW_REPUTATION
    };

    apr_pool_cleanup_register(p, cfg, apr_pool_cleanup_null, destroyConfig);

    return cfg;
}

static const char *setEnabled(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

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

static apr_status_t cleanupDatabase(void *mmdb) {
    MMDB_close((MMDB_s *) mmdb);
    return APR_SUCCESS;
}

static const char *setASNDatabase(cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

    cfg->asnDBPath = apr_pstrdup(cfg->pool, value);

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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

    cfg->countryDBPath = apr_pstrdup(cfg->pool, value);

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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

    const int rc = parseCountryReputation(cfg->pool, &cfg->countryReputation, value, value2);

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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || n < 1) {
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
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
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
        cfg->warnHttpReply = (int) n;
    }

    return NULL;
}

static const char *setBlocHttpReply(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
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
        cfg->blockHttpReply = (int) n;
    }

    return NULL;
}

static const char *setStateTemplateFile(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

    FILE *fp = fopen(value, "r");

    if (fp != NULL) {
        char source[MAX_BUF_LEN + 1];
        size_t newLen = fread(source, sizeof(char), MAX_BUF_LEN, fp);
        if (ferror(fp) != 0) {
            fputs("Error reading file", stderr);
        } else {
            source[newLen++] = '\0';
        }
        fclose(fp);

        cfg->stateTemplate = apr_pstrdup(cfg->pool, source);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Couldn't open RepudiatorStateTemplateFile for value '%s'",
                     value);
    }

    return NULL;
}

static const char *setPOWUri(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

    if (value != NULL && *value != '\0' && value[0] != '/') {
        cfg->powURI = apr_pstrdup(cfg->pool, value);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorPOWUri value '%s', using default %s.",
                     value, DEFAULT_POW_URI);
        cfg->powURI = apr_pstrdup(cfg->pool, DEFAULT_POW_URI);
    }

    return NULL;
}

static const char *setPOWTemplateFile(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

    FILE *fp = fopen(value, "r");

    if (fp != NULL) {
        char source[MAX_BUF_LEN + 1];
        size_t newLen = fread(source, sizeof(char), MAX_BUF_LEN, fp);
        if (ferror(fp) != 0) {
            fputs("Error reading file", stderr);
        } else {
            source[newLen++] = '\0';
        }
        fclose(fp);

        cfg->powTemplate = apr_pstrdup(cfg->pool, source);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Couldn't open RepudiatorPOWTemplateFile for value '%s'",
                     value);
    }

    return NULL;
}

static const char *setPOWCookiePassphrase(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;

    if (value != NULL && *value != '\0') {
        cfg->powCookiePassphrase = apr_pstrdup(cfg->pool, value);
    }

    return NULL;
}

static const char *setPOWDifficulty(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || n < 1 || n > 32) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorPOWDifficulty value '%s', using default %d.",
                     value, DEFAULT_POW_DIFFICULTY);
        cfg->powDifficulty = DEFAULT_POW_DIFFICULTY;
    } else {
        cfg->powDifficulty = (int) n;
    }

    return NULL;
}

static const char *setPOWCookieMaxAge(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorPOWCookieMaxAge value '%s', using default %d.",
                     value, DEFAULT_POW_COOKIE_MAXAGE);
        cfg->powCookieMaxAge = DEFAULT_POW_COOKIE_MAXAGE;
    } else {
        cfg->powCookieMaxAge = (int) n;
    }

    return NULL;
}

static const char *setPOWAboveReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
    char *endptr;
    double n;

    errno = 0;
    n = strtod(value, &endptr);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorPOWAboveReputation value '%s', using default %4.2f.",
                     value, DEFAULT_POW_ABOVE_REPUTATION);
        cfg->powAboveReputation = DEFAULT_POW_ABOVE_REPUTATION;
    } else {
        cfg->powAboveReputation = n;
    }

    return NULL;
}

static const char *setPOWBelowReputation(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    repudiator_config_t *cfg = (repudiator_config_t *) dconfig;
    char *endptr;
    double n;

    errno = 0;
    n = strtod(value, &endptr);
    if (errno || *endptr != '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                     "Invalid RepudiatorPOWBelowReputation value '%s', using default %4.2f.",
                     value, DEFAULT_POW_BELOW_REPUTATION);
        cfg->powBelowReputation = DEFAULT_POW_BELOW_REPUTATION;
    } else {
        cfg->powBelowReputation = n;
    }

    return NULL;
}

static const command_rec configCmds[] = {
    AP_INIT_TAKE1("RepudiatorEnabled", setEnabled, NULL, RSRC_CONF,
                  "Enable mod_repudiator (either globally or in the virtualhost where it is specified)"),

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

    AP_INIT_TAKE1("RepudiatorStateTemplateFile", setStateTemplateFile, NULL, RSRC_CONF, "State template file"),

    AP_INIT_TAKE1("RepudiatorPOWUri", setPOWUri, NULL, RSRC_CONF, "POW URI"),

    AP_INIT_TAKE1("RepudiatorPOWTemplateFile", setPOWTemplateFile, NULL, RSRC_CONF, "POW template file"),

    AP_INIT_TAKE1("RepudiatorPOWCookiePassphrase", setPOWCookiePassphrase, NULL, RSRC_CONF, "POW Cookie passphrase"),

    AP_INIT_TAKE1("RepudiatorPOWDifficulty", setPOWDifficulty, NULL, RSRC_CONF, "POW Challenge difficulty"),

    AP_INIT_TAKE1("RepudiatorPOWCookieMaxAge", setPOWCookieMaxAge, NULL, RSRC_CONF, "POW Cookie max age"),

    AP_INIT_TAKE1("RepudiatorPOWAboveReputation", setPOWAboveReputation, NULL, RSRC_CONF,
                  "POW challenge above reputation"),

    AP_INIT_TAKE1("RepudiatorPOWBelowReputation", setPOWBelowReputation, NULL, RSRC_CONF,
                  "POW challenge below reputation"),

    {NULL}
};

static void registerHooks(apr_pool_t *p) {
    ap_hook_pre_config(preConfigHook, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config(postConfigHook,NULL,NULL,APR_HOOK_LAST);

    ap_register_output_filter(FIXUP_HEADERS_OUT_FILTER, headersOutputFilter,NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter(FIXUP_HEADERS_ERR_FILTER, headersErrorFilter,NULL, AP_FTYPE_CONTENT_SET);

    ap_hook_insert_filter(headersInsertOutputFilter, NULL, NULL, APR_HOOK_LAST);
    ap_hook_insert_error_filter(headersInsertErrorFilter, NULL, NULL, APR_HOOK_LAST);

    ap_hook_handler(counterStats, NULL, NULL, APR_HOOK_REALLY_FIRST);

    ap_hook_access_checker(powChallenge, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_access_checker(accessChecker, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

AP_DECLARE_MODULE(repudiator) = {
    STANDARD20_MODULE_STUFF,
    createDirConf,
    NULL,
    NULL,
    NULL,
    configCmds,
    registerHooks,
    AP_MODULE_FLAG_NONE
};
