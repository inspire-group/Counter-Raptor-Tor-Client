/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hijack.c
 * \brief Header file for hijack.c.
 **/

#ifndef _TOR_HIJACK_H
#define _TOR_HIJACK_H

#define true 1

typedef struct tor_buffer {
  int asn;
  int equal_paths;
} tor_buffer;

typedef struct asrel_entry_t {
  int asn;
  int pc_size;
  int* pc_array;
  int pp_size;
  int* pp_array;
  int cp_size;
  int* cp_array;
} asrel_entry_t;

typedef struct graph_entry_t {
  int asn;
  int weight;
  int equal_paths;
  int uphill;
} graph_entry_t;

typedef struct tor_entry_t {
  int asn;
  double resil;
} tor_entry_t;

typedef struct asrel_hashtable_t {
  struct asrel_entry_t **list;
  int num_used;
  int capacity;
  /** @} */
} asrel_hashtable_t;

typedef struct graph_hashtable_t {
  struct graph_entry_t **list;
  int num_used;
  int capacity;
  /** @} */
} graph_hashtable_t;

typedef struct tor_hashtable_t {
  struct tor_entry_t **list;
  int num_used;
  int capacity;
  /** @} */
} tor_hashtable_t;

int compute_resil(double *resiliencies, int myasn, int *torasns, int numasn);

#endif
