/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file resiliency.c
 * \brief Code to
 * Map client IP to ASN for resilience calculation
 **/

#include "or.h"
#include "config.h"
#include "routerlist.h"
#include "nodelist.h"
#include "hijack.h"
#include "resiliency.h"

static void clear_ipasn_db(void);

/** An entry from the ASN file: maps an IP range to a AS. */
typedef struct ipasn_entry_t {
    uint32_t ip_low; /**< The lowest IP in the range, in host order */
    uint32_t ip_high; /**< The highest IP in the range, in host order */
    uint32_t ip_asn; /**< AS Number */
} ipasn_entry_t;

static smartlist_t *ipasn_entries = NULL;

/** Add an entry to the IPTOASN table, mapping all IPs between <b>low</b> and
 * <b>high</b>, inclusive, to the <b>asn</b>.
 */
static void
ipasn_add_entry(uint32_t low, uint32_t high, uint32_t asn)
{
    ipasn_entry_t *ent;
    
    if (high < low)
        return;
    
    ent = tor_malloc_zero(sizeof(ipasn_entry_t));
    ent->ip_low = low;
    ent->ip_high = high;
    ent->ip_asn = asn;
    smartlist_add(ipasn_entries, ent);
}

/** Add an entry to the IPTOASN table, parsing it from <b>line</b>.  The
 * format is as for ipasn_load_file(). */
int
ipasn_parse_entry(const char *line)
{
    unsigned int low, high, asnum;
    if (!ipasn_entries)
        ipasn_entries = smartlist_new();
    
    while (*line == '\0')
        ++line;
    if (*line == '#')
        return 0;
    if (sscanf(line,"%u,%u,%u", &low, &high, &asnum) == 3) {
        ipasn_add_entry(low, high, asnum);
        return 0;
    } else if (sscanf(line,"\"%u\",\"%u\",\"%u\",", &low, &high, &asnum) == 3) {
        ipasn_add_entry(low, high, asnum);
        return 0;
    } else {
        log_warn(LD_GENERAL, "Unable to parse line from IPTOASN file: %s",
                 escaped(line));
        return -1;
    }
}

/** Sorting helper: return -1, 1, or 0 based on comparison of two
 * ipasn_entry_t */
static int
_ipasn_compare_entries(const void **_a, const void **_b)
{
    const ipasn_entry_t *a = *_a, *b = *_b;
    if (a->ip_low < b->ip_low)
        return -1;
    else if (a->ip_low > b->ip_low)
        return 1;
    else
        return 0;
}

/** bsearch helper: return -1, 1, or 0 based on comparison of an IP (a pointer
 * to a uint32_t in host order) to a ipasn_entry_t */
static int
_ipasn_compare_key_to_entry(const void *_key, const void **_member)
{
    /* No alignment issue here, since _key really is a pointer to uint32_t */
    const uint32_t addr = *(uint32_t *)_key;
    const ipasn_entry_t *entry = *_member;
    if (addr < entry->ip_low)
        return -1;
    else if (addr > entry->ip_high)
        return 1;
    else
        return 0;
}


/** Clear the IPTOASN database and reload it from the file
 * <b>filename</b>. Return 0 on success, -1 on failure.
 *
 * Recognized line formats are:
 *   INTIPLOW,INTIPHIGH,ASN
 * where INTIPLOW and INTIPHIGH are IPv4 addresses encoded as 4-byte unsigned
 * integers, and ASN is also an unsigned integer.
 *
 * It also recognizes, and skips over, blank lines and lines that start
 * with '#' (comments).
 */
int
ipasn_load_file(const char *filename)
{
    FILE *f;
    clear_ipasn_db();
    if (!(f = tor_fopen_cloexec(filename, "r"))) {
        log_warn(LD_GENERAL, "Fail to open file %s.", filename);
        return -1;
    }
    if (ipasn_entries) {
        SMARTLIST_FOREACH(ipasn_entries, ipasn_entry_t *, e, tor_free(e));
        smartlist_free(ipasn_entries);
    }
    ipasn_entries = smartlist_new();
    log_notice(LD_GENERAL, "Parsing IPTOASN file %s.", filename);
    while (!feof(f)) {
        char buf[512];
        if (fgets(buf, (int)sizeof(buf), f) == NULL)
            break;
        ipasn_parse_entry(buf);
    }
    /*XXXX abort and return -1 if no entries/illformed?*/
    fclose(f);
    
    smartlist_sort(ipasn_entries, _ipasn_compare_entries);
    
    return 0;
}

int
ipasn_get_asn_by_ip(uint32_t ipaddr)
{
    ipasn_entry_t *ent;
    if (!ipasn_entries)
        return 0;
    ent = smartlist_bsearch(ipasn_entries, &ipaddr, _ipasn_compare_key_to_entry);
    return ent ? (int)ent->ip_asn : 0;
}

/** Release all storage held by the GeoIP database. */
static void
clear_ipasn_db(void)
{
    if (ipasn_entries) {
        SMARTLIST_FOREACH(ipasn_entries, ipasn_entry_t *, ent, tor_free(ent));
        smartlist_free(ipasn_entries);
    }
    ipasn_entries = NULL;
}

/** Release all storage held in this file. */
void
ipasn_free_all(void)
{
    clear_ipasn_db();
}

/** Calculate Resiliency from node sl list */
int compute_node_as_resiliency(const smartlist_t *sl, double *resils)
{
    // extract IPs from node list to array
    uint32_t *ips;
    ips = tor_malloc_zero(sizeof(uint32_t)*smartlist_len(sl));

    SMARTLIST_FOREACH_BEGIN(sl, const node_t *, node) {
        uint32_t this_ip = node_get_prim_addr_ipv4h(node);
        ips[node_sl_idx] = this_ip;
    } SMARTLIST_FOREACH_END(node);
    
    uint32_t myip;
    const or_options_t *options = get_options();
    if (resolve_my_address(LOG_WARN, options, &myip, NULL, NULL) < 0) {
        log_debug(LD_GENERAL, "Failed to resolve IP address.");
        return -1;
    }    
    // map to ASN
    if (ipasn_load_file(options->IPASNFile) < 0) {
        log_warn(LD_GENERAL, "Failed to load ipasn file.");
        return -1;
    }
    
    unsigned char bytes[4];
    bytes[0] = myip &0xFF;
    bytes[1] = (myip >>8) & 0xFF;
    bytes[2] = (myip >>16) & 0xFF;
    bytes[3] = (myip >> 24) & 0xFF;
    log_debug(LD_GENERAL, "The IP address is %d.%d.%d.%d.", bytes[3],bytes[2],bytes[1],bytes[0]);

    int myasn;
    myasn = ipasn_get_asn_by_ip(myip);
    if (myasn == 0) {
        log_warn(LD_GENERAL, "Failed to resolve ASN.");
        return -1;
    }

    int *asns;
    asns = tor_malloc_zero(sizeof(int)*smartlist_len(sl));
    unsigned int i;
    for (i=0; i < (unsigned)smartlist_len(sl); i++) {
        asns[i] = ipasn_get_asn_by_ip(ips[i]);
    }
    
    clear_ipasn_db();
    
    if (compute_resil(resils, myasn, asns, smartlist_len(sl)) < 0) {
        log_debug(LD_GENERAL, "Failed to calculate resilience. Quit now.");
        tor_free(ips);
        tor_free(asns);
        return -1;
    }
    
    tor_free(ips);
    tor_free(asns);
    return 0;
}
