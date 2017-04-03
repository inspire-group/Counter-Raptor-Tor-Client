/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file resiliency.h
 * \brief Header file for resiliency.c.
 **/

#ifndef _TOR_RESILIENCY_H
#define _TOR_RESILIENCY_H

int ipasn_parse_entry(const char *line);
int ipasn_load_file(const char *filename);
int ipasn_get_asn_by_ip(uint32_t ipaddr); /* Get ASN given IP address*/
void ipasn_free_all(void);

int compute_node_as_resiliency(const smartlist_t *sl, double *resils); /* Compute AS resilience of nodes */

#endif
