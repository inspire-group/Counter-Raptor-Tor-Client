/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hijack.c
 * \brief Code to
 * Calculate AS resilience for a list of relays from given client
 **/

#include "or.h"
#include "config.h"
#include "routerlist.h"
#include "queue.h"
#include "hijack.h"

static void clear_asrel_db(void);
static void clear_graph_db(void);
static void clear_tor_db(void);


int hash_fun(int key, int try, int max) {
  return (key + try) % max;
}

//=========================================================================================
//AS relationship hashtable

/** Allocate and return an empty hashtable.
 */
asrel_hashtable_t *
asrel_hashtable_new(int capacity)
{
  asrel_hashtable_t *tbl = tor_malloc(sizeof(asrel_hashtable_t));
  tbl->num_used = 0;
  tbl->capacity = capacity;
  tbl->list = tor_malloc_zero(sizeof(void *) * tbl->capacity);
  return tbl;
}

/** Deallocate a hashtable.  Does not release storage associated with the
 * list's elements.
 */
void
asrel_hashtable_free(asrel_hashtable_t *tbl)
{
  if (!tbl)
    return;
  tor_free(tbl->list);
  tor_free(tbl);
}

void asrel_hashtable_add(asrel_hashtable_t *tbl, struct asrel_entry_t *element, int key) {
  int try, hash;
  if(tbl->num_used < tbl->capacity) {
    for(try = 0; true; try++) {
      hash = hash_fun(key, try, tbl->capacity);
      if(tbl->list[hash] == 0) { // empty cell
	tbl->list[hash] = element;
	tbl->num_used++;
	break;
      }
    }
  } else {
    //printf("Hashtable is full\n");
    log_debug(LD_GENERAL, "Hashtable is full.");
  }
}

struct asrel_entry_t *asrel_hashtable_retrieve(asrel_hashtable_t *tbl, int key) {
  int try, hash;
  for(try = 0; true; try++) {
    hash = hash_fun(key, try, tbl->capacity);
    if(tbl->list[hash] == 0) {
      return NULL; // Nothing found
    }
    //        if (key == (uint32_t) &(tbl->list[hash])) {
    //            return tbl->list[hash];
    //        }
    if(tbl->list[hash]->asn == key) {
      return tbl->list[hash];
    }
  }
  return NULL;
}

//=========================================================================================
//Graph hashtable

/** Allocate and return an empty hashtable.
 */
graph_hashtable_t *
graph_hashtable_new(int capacity)
{
  graph_hashtable_t *tbl = tor_malloc(sizeof(graph_hashtable_t));
  tbl->num_used = 0;
  tbl->capacity = capacity;
  tbl->list = tor_malloc_zero(sizeof(void *) * tbl->capacity);
  return tbl;
}

/** Deallocate a hashtable.  Does not release storage associated with the
 * list's elements.
 */
void
graph_hashtable_free(graph_hashtable_t *tbl)
{
  if (!tbl)
    return;
  tor_free(tbl->list);
  tor_free(tbl);
}

void graph_hashtable_add(graph_hashtable_t *tbl, struct graph_entry_t *element, int key) {
  int try, hash;
  if(tbl->num_used < tbl->capacity) {
    for(try = 0; true; try++) {
      hash = hash_fun(key, try, tbl->capacity);
      if(tbl->list[hash] == 0) { // empty cell
	tbl->list[hash] = element;
	tbl->num_used++;
	break;
      }
    }
  } else {
    //printf("Hashtable is full\n");
    log_debug(LD_GENERAL, "Hashtable is full.");
  }
}

struct graph_entry_t *graph_hashtable_retrieve(graph_hashtable_t *tbl, int key) {
  int try, hash;
  for(try = 0; true; try++) {
    hash = hash_fun(key, try, tbl->capacity);
    if(tbl->list[hash] == 0) {
      return NULL; // Nothing found
    }
    //        if (key == (uint32_t) &(tbl->list[hash])) {
    //            return tbl->list[hash];
    //        }
    if(tbl->list[hash]->asn == key) {
      return tbl->list[hash];
    }
  }
  return NULL;
}

//=========================================================================================
//Tor hashtable

/** Allocate and return an empty hashtable.
 */
tor_hashtable_t *
tor_hashtable_new(int capacity)
{
  tor_hashtable_t *tbl = tor_malloc(sizeof(tor_hashtable_t));
  tbl->num_used = 0;
  tbl->capacity = capacity;
  tbl->list = tor_malloc_zero(sizeof(void *) * tbl->capacity);
  return tbl;
}

/** Deallocate a hashtable.  Does not release storage associated with the
 * list's elements.
 */
void
tor_hashtable_free(tor_hashtable_t *tbl)
{
  if (!tbl)
    return;
  tor_free(tbl->list);
  tor_free(tbl);
}

void tor_hashtable_add(tor_hashtable_t *tbl, struct tor_entry_t *element, int key) {
  int try, hash;
  if(tbl->num_used < tbl->capacity) {
    for(try = 0; true; try++) {
      hash = hash_fun(key, try, tbl->capacity);
      if(tbl->list[hash] == 0) { // empty cell
	tbl->list[hash] = element;
	tbl->num_used++;
	break;
      }
    }
  } else {
    //printf("Hashtable is full\n");
    log_debug(LD_GENERAL, "Hashtable is full.");
  }
}

struct tor_entry_t *tor_hashtable_retrieve(tor_hashtable_t *tbl, int key) {
  int try, hash;
  for(try = 0; true; try++) {
    hash = hash_fun(key, try, tbl->capacity);
    if(tbl->list[hash] == 0) {
      return NULL; // Nothing found
    }
    //        if (key == (uint32_t) &(tbl->list[hash])) {
    //            return tbl->list[hash];
    //        }
    if(tbl->list[hash]->asn == key) {
      return tbl->list[hash];
    }
  }
  return NULL;
}


static asrel_hashtable_t *asrel_entries = NULL; // 100,000
static graph_hashtable_t *graph_entries = NULL; // 100,000
static tor_hashtable_t *tor_entries = NULL; // 2,000


/** Add an entry to the asrel_entries table.
 * [provider ases],[peer ases],[customer ases]
 */
static void
asrel_add_entry(int asn1, int asn2, int relation)
{
  asrel_entry_t *ent;
  //ent = smartlist_bsearch(asrel_entries, &asn1, _asrel_compare_key_to_entry);
  ent = asrel_hashtable_retrieve(asrel_entries, asn1);
    
  if (ent) {
    if (relation == -1) {
      ent->pc_size++;
      ent->pc_array = tor_realloc(ent->pc_array, ent->pc_size*sizeof(int));
      ent->pc_array[(ent->pc_size-1)] = asn2;
    } else {
      ent->pp_size++;
      ent->pp_array = tor_realloc(ent->pp_array, ent->pp_size*sizeof(int));
      ent->pp_array[(ent->pp_size-1)] = asn2;
    }
  } else {
    ent = tor_malloc_zero(sizeof(asrel_entry_t));
    ent->asn = asn1;
    ent->pc_size = 0;
    ent->pp_size = 0;
    ent->cp_size = 0;
    ent->pc_array = NULL;
    ent->pp_array = NULL;
    ent->cp_array = NULL;
    if (relation == -1) {
      ent->pc_size = 1;
      ent->pc_array = tor_malloc_zero(sizeof(int));
      ent->pc_array[0] = asn2;
    } else {
      ent->pp_size = 1;
      ent->pp_array = tor_malloc_zero(sizeof(int));
      ent->pp_array[0] = asn2;
    }
    asrel_hashtable_add(asrel_entries, ent, asn1);
    //smartlist_sort(asrel_entries, _asrel_compare_entries);
  }
    
  //ent = smartlist_bsearch(asrel_entries, &asn2, _asrel_compare_key_to_entry);
  ent = asrel_hashtable_retrieve(asrel_entries, asn2);
    
  if (ent) {
    if (relation == -1) {
      ent->cp_size++;
      ent->cp_array = tor_realloc(ent->cp_array, ent->cp_size*sizeof(int));
      ent->cp_array[(ent->cp_size-1)] = asn1;
    } else {
      ent->pp_size++;
      ent->pp_array = tor_realloc(ent->pp_array, ent->pp_size*sizeof(int));
      ent->pp_array[(ent->pp_size-1)] = asn1;
    }
  } else {
    ent = tor_malloc_zero(sizeof(asrel_entry_t));
    ent->asn = asn2;
    ent->pc_size = 0;
    ent->pp_size = 0;
    ent->cp_size = 0;
    ent->pc_array = NULL;
    ent->pp_array = NULL;
    ent->cp_array = NULL;
    if (relation == -1) {
      ent->cp_size = 1;
      ent->cp_array = tor_malloc_zero(sizeof(int));
      ent->cp_array[0] = asn1;
    } else {
      ent->pp_size = 1;
      ent->pp_array = tor_malloc_zero(sizeof(int));
      ent->pp_array[0] = asn1;
    }
    asrel_hashtable_add(asrel_entries, ent, asn2);
    //smartlist_sort(asrel_entries, _asrel_compare_entries);
  }
}

/** Parse line for the asrel_entries table. */
int
asrel_parse_entry(const char *line)
{
  int relation;
  unsigned int asn1, asn2;
  if (!asrel_entries)
    asrel_entries = asrel_hashtable_new(100000);
    
  while (*line == '\0')
    ++line;
  if (*line == '#')
    return 0;
  //printf("%d", sscanf(line,"%u,%u,%s", &low, &high, b));
  //exit(0);
  if (sscanf(line,"%u|%u|%d", &asn1, &asn2, &relation) == 3) {
    asrel_add_entry(asn1, asn2, relation);
    return 0;
  } else {
    log_warn(LD_GENERAL, "Unable to parse line from ASREL file: %s",
	     escaped(line));
    return -1;
  }
}

/* load as-rel file */
int asrel_load_file(const char *filename)
{
  FILE *f;
  clear_asrel_db();
  if (!(f = tor_fopen_cloexec(filename, "r"))) {
    //printf("unable to open");
    log_warn(LD_GENERAL, "Fail to open file %s.", filename);
    return -1;
  }
  asrel_entries = asrel_hashtable_new(100000);
  log_notice(LD_GENERAL, "Parsing asrel file %s.", filename);
  while (!feof(f)) {
    char buf[512];
    if (fgets(buf, (int)sizeof(buf), f) == NULL)
      break;
    asrel_parse_entry(buf);
  }
  /*XXXX abort and return -1 if no entries/illformed?*/
  fclose(f);
    
  //smartlist_sort(asrel_entries, _asrel_compare_entries);
    
  //printf("%d\n",asrel_entries->num_used);
    
  return 0;
}

/** Release all storage held by the asrel database. */
static void
clear_asrel_db(void)
{
  if (asrel_entries) {
    int idx;
    for(idx = 0; idx < asrel_entries->num_used; idx++) {
      if(asrel_entries->list[idx] != 0) {
	asrel_entry_t *ent;
	ent = asrel_entries->list[idx];
	tor_free(ent->pc_array);
	tor_free(ent->pp_array);
	tor_free(ent->cp_array);
	tor_free(ent);
      }
    }
    //SMARTLIST_FOREACH(asrel_entries, asrel_entry_t *, ent, tor_free(ent));
    asrel_hashtable_free(asrel_entries);
  }
  asrel_entries = NULL;
}

/** Release all storage held by the graph database. */
static void
clear_graph_db(void)
{
  if (graph_entries) {
    int idx;
    for(idx = 0; idx < graph_entries->num_used; idx++) {
      if(graph_entries->list[idx] != 0) {
	graph_entry_t *ent;
	ent = graph_entries->list[idx];
	tor_free(ent);
      }
    }
    graph_hashtable_free(graph_entries);
  }
  graph_entries = NULL;
}

/** Release all storage held by the tor database. */
static void
clear_tor_db(void)
{
  if (tor_entries) {
    int idx;
    for(idx = 0; idx < tor_entries->num_used; idx++) {
      if(tor_entries->list[idx] != 0) {
	tor_entry_t *ent;
	ent = tor_entries->list[idx];
	tor_free(ent);
      }
    }
    tor_hashtable_free(tor_entries);
  }
  tor_entries = NULL;
}

/** Release all storage held in this file. */
void
hijack_free_all(void)
{
  clear_asrel_db();
  clear_graph_db();
  clear_tor_db();
}

/** Add an entry to the graph_entries table.
 * weight, equal_paths, uphill
 */
static void
graph_add_entry(int key, int weight, int equal_paths, int uphill) {
  graph_entry_t *ent = tor_malloc_zero(sizeof(graph_entry_t));
  ent->asn = key;
  ent->weight = weight;
  ent->equal_paths = equal_paths;
  ent->uphill = uphill;
  graph_hashtable_add(graph_entries, ent, key);
}

/** Add an entry to the tor_entries table.
 * resil
 */
static void
tor_add_entry(int key, double resil) {
  tor_entry_t *ent = tor_malloc_zero(sizeof(tor_entry_t));
  ent->asn = key;
  ent->resil = resil;
  tor_hashtable_add(tor_entries, ent, key);
}

/** Check if tor_entries has the key
 */
int
tor_check_entry(int key) {
  tor_entry_t *ent = tor_hashtable_retrieve(tor_entries, key);
  if (ent) {
    return 1;
  } else {
    return 0;
  }
}

/** Insert an asnlst into tor_entries hashtable.
 */
static void
tor_add_lst(int *asnlst, int numasn) {
  int i, key;
  for (i = 0; i < numasn; i++) {
    key = asnlst[i];
    if (!tor_check_entry(key)) {
      tor_add_entry(key, 0);
    }
  }
}


static void
graph_bfs_pc(int *qlst, int lst_size) {
  Queue *q = createQueue();
  int i, key, tmp;
  asrel_entry_t *neighbor;
  graph_entry_t *val, *tmp_graph;
  QNode *current;
  for (i = 0; i < lst_size; i++) {
    enQueue(q, qlst[i]);
  }
  while (!queue_empty(q)) {
    current = deQueue(q);
    if (current) {
      key = current->key;
      val = graph_hashtable_retrieve(graph_entries, key);
      neighbor = asrel_hashtable_retrieve(asrel_entries, key);
      if (val && neighbor) {
	for (i = 0; i < neighbor->pc_size; i++) {
	  tmp = neighbor->pc_array[i];
	  tmp_graph = graph_hashtable_retrieve(graph_entries, tmp);
	  if (tmp_graph == NULL) {
	    graph_add_entry(tmp, val->weight+1, val->equal_paths, val->uphill);
	    enQueue(q, tmp);
	    //printf("add ASN %d\n",tmp);
	  } else if (tmp_graph->weight == (val->weight + 1)) {
	    tmp_graph->equal_paths += val->equal_paths;
	  }
	}
      }
      tor_free(current);
    }
  }
  tor_free(q);
}

static void
graph_bfs_pp(int *qlst, int lst_size) {
  Queue *q = createQueue();
  int i, j, key, tmp;
  asrel_entry_t *neighbor;
  graph_entry_t *val, *tmp_graph;
  QNode *current;
  for (i = 0; i < lst_size; i++) {
    key = qlst[i];
    neighbor = asrel_hashtable_retrieve(asrel_entries, key);
    val = graph_hashtable_retrieve(graph_entries, key);
    if (val && neighbor) {
      for (j = 0; j < neighbor->pp_size; j++) {
	tmp = neighbor->pp_array[j];
	tmp_graph = graph_hashtable_retrieve(graph_entries, tmp);
	if (tmp_graph == NULL) {
	  graph_add_entry(tmp, (val->weight)+(asrel_entries->num_used), val->equal_paths, val->uphill);
	  enQueue(q, tmp);
	}
      }
    }
  }
  while (!queue_empty(q)) {
    current = deQueue(q);
    if (current) {
      key = current->key;
      val = graph_hashtable_retrieve(graph_entries, key);
      neighbor = asrel_hashtable_retrieve(asrel_entries, key);
      if (val && neighbor) {
	for (i = 0; i < neighbor->pc_size; i++) {
	  tmp = neighbor->pc_array[i];
	  tmp_graph = graph_hashtable_retrieve(graph_entries, tmp);
	  if (tmp_graph == NULL) {
	    graph_add_entry(tmp, val->weight+1, val->equal_paths, val->uphill);
	    enQueue(q, tmp);
	  } else if (tmp_graph->weight == (val->weight + 1)) {
	    tmp_graph->equal_paths += val->equal_paths;
	  }
	}
      }
      tor_free(current);
    }
  }
  tor_free(q);
}

static void
graph_bfs_cp(int root) {
  Queue *q = createQueue();
  enQueue(q, root);
  int i, key, tmp;
  int *curlst = NULL;
  int curlst_size = 0;
  int curlevel = 0;
  asrel_entry_t *neighbor;
  graph_entry_t *val, *tmp_graph;
  QNode *current;
  while (!queue_empty(q)) {
    current = deQueue(q);
    if (current) {
      key = current->key;
      val = graph_hashtable_retrieve(graph_entries, key);
      neighbor = asrel_hashtable_retrieve(asrel_entries, key);
      if (val && neighbor) {
	if (val->uphill > curlevel) {
	  graph_bfs_pc(curlst, curlst_size);
	  graph_bfs_pp(curlst, curlst_size);
	  tor_free(curlst);
	  curlst = NULL;
	  curlst_size = 0;
	  curlevel = val->uphill;
	}
	for (i = 0; i < neighbor->cp_size; i++) {
	  tmp = neighbor->cp_array[i];
	  tmp_graph = graph_hashtable_retrieve(graph_entries, tmp);
	  if (tmp_graph == NULL) {
	    graph_add_entry(tmp, val->weight, val->equal_paths, val->uphill + 1);
	    enQueue(q, tmp);
	    curlst_size++;
	    curlst = tor_realloc(curlst, curlst_size*sizeof(int));
	    curlst[curlst_size-1] = tmp;
	  } else if (tmp_graph->uphill == (val->uphill + 1)) {
	    tmp_graph->equal_paths += val->equal_paths;
	  }
	}
      }
      tor_free(current);
    }
  }
  tor_free(curlst);
  curlst = NULL;
  tor_free(q);
}

/** Sorting helper: return -1, 1, or 0 based on comparison of two
 * graph_entry_t */
static int
_graph_compare_entries(const void **_a, const void **_b)
{
  const graph_entry_t *a = *_a, *b = *_b;
  if (a->uphill < b->uphill)
    return 1;
  else if (a->uphill > b->uphill)
    return -1;
  else {
    if (a->weight < b->weight)
      return 1;
    else if (a->weight > b->weight)
      return -1;
    else
      return 0;
  }
}

/** Iterate through graph database and put resilience into tor_db. */
static void
update_resilience(int myasn) {
  smartlist_t *destlst = smartlist_new();
  int i;
  for (i=0; i < graph_entries->capacity; i++) {
    if (graph_entries->list[i] != 0) {
      graph_entry_t *current = graph_entries->list[i];
      if (current->asn != myasn) {
	smartlist_add(destlst, current);
      }
    }
  }
  smartlist_sort(destlst, _graph_compare_entries);
    
  //printf("%d\n",smartlist_len(destlst));
  //SMARTLIST_FOREACH(destlst, graph_entry_t *, e, printf("%d %d\n",e->uphill,e->weight));
    
  int unreachable = asrel_entries->num_used - 1 - smartlist_len(destlst);
    
  int nodes = 0;
  int prev[2] = {0, 0}; // [weight, uphill]
  int eq_path = 0;
  int eq_nodes = 0;
  int buffer_size = 0;
  tor_buffer *buffer = NULL;
  double value;
  tor_entry_t *tor_as;
  tor_buffer item;
    
  SMARTLIST_FOREACH_BEGIN(destlst, const graph_entry_t *, node) {
    if ((prev[0] == node->weight) && (prev[1] == node->uphill)) {
      eq_path += node->equal_paths;
      eq_nodes++;
      if (tor_check_entry(node->asn)) {
	tor_buffer buffer_item;
	buffer_item.asn = node->asn;
	buffer_item.equal_paths = node->equal_paths;
	buffer_size++;
	buffer = tor_realloc(buffer, buffer_size*sizeof(tor_buffer));
	buffer[buffer_size-1] = buffer_item;
      }
    } else {
      for (i=0; i < buffer_size; i++) {
	item = buffer[i];
	value = nodes + unreachable;
	if (eq_nodes > 1) {
	  value += (double)(item.equal_paths) / (double)eq_path;
	}
	tor_as = tor_hashtable_retrieve(tor_entries, item.asn);
	if (tor_as) {
	  tor_as->resil = value;
	}
      }
      tor_free(buffer);
      buffer = NULL;
      buffer_size = 0;
      nodes += eq_nodes;
      eq_path = node->equal_paths;
      eq_nodes = 1;
      prev[0] = node->weight;
      prev[1] = node->uphill;
      if (tor_check_entry(node->asn)) {
	tor_buffer buffer_item;
	buffer_item.asn = node->asn;
	buffer_item.equal_paths = node->equal_paths;
	buffer_size = 1;
	buffer = tor_malloc_zero(sizeof(tor_buffer));
	buffer[0] = buffer_item;
      }
    }
  } SMARTLIST_FOREACH_END(node);
    
  // leftover nodes in buffer
  for (i=0; i < buffer_size; i++) {
    item = buffer[i];
    value = nodes + unreachable;
    if (eq_nodes > 1) {
      value += (double)(item.equal_paths) / (double)eq_path;
    }
    tor_as = tor_hashtable_retrieve(tor_entries, item.asn);
    if (tor_as) {
      tor_as->resil = value;
    }
  }
    
  tor_free(buffer);
  buffer = NULL;
    
  //SMARTLIST_FOREACH(destlst, graph_entry_t *, e, tor_free(e));
  smartlist_free(destlst);
}


int compute_resil(double *resiliences, int myasn, int *torasns, int numasn) {
    
  hijack_free_all();

  const or_options_t *options = get_options();
    
  if (asrel_load_file(options->ASTopoFile) < 0) {
    log_warn(LD_GENERAL, "Failed to load as-rel.txt file.");
    return -1;
  }
    
  graph_entries = graph_hashtable_new(100000);
  graph_add_entry(myasn,0,1,0);
  int *qlst = tor_malloc(sizeof(int));
  qlst[0] = myasn;
    
  log_debug(LD_GENERAL, "Start running BFS.");

  graph_bfs_pc(qlst,1);
  graph_bfs_pp(qlst,1);
  graph_bfs_cp(myasn);
    
  log_debug(LD_GENERAL, "BFS done. Now starting resilience calc.");
    
  tor_entries = tor_hashtable_new(2000);
  tor_add_lst(torasns, numasn);
    
  update_resilience(myasn);
    
  log_debug(LD_GENERAL, "Coping results into resilience array.");
    
  int i, key;
  tor_entry_t *ent;
  for (i = 0; i < numasn; i++) {
    key = torasns[i];
    ent = tor_hashtable_retrieve(tor_entries, key);
    resiliences[i] = (ent->resil) / (double)(asrel_entries->num_used - 2);
  }
    
  hijack_free_all();
    
  return 0;
}
