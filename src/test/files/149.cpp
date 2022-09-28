void comps_mrtree_unite(COMPS_MRTree *rt1, COMPS_MRTree *rt2) {
COMPS_HSList *tmplist, *tmp_subnodes;
COMPS_HSListItem *it, *it2;
struct Pair {
COMPS_HSList * subnodes;
char * key;
        char added;
} *pair, *parent_pair;

pair = malloc(sizeof(struct Pair));
pair->subnodes = rt2->subnodes;
pair->key = NULL;

tmplist = comps_hslist_create();
comps_hslist_init(tmplist, NULL, NULL, &free);
comps_hslist_append(tmplist, pair, 0);

while (tmplist->first != NULL) {
it = tmplist->first;
comps_hslist_remove(tmplist, tmplist->first);
tmp_subnodes = ((struct Pair*)it->data)->subnodes;
parent_pair = (struct Pair*) it->data;
free(it);

        pair->added = 0;
for (it = tmp_subnodes->first; it != NULL; it=it->next) {
pair = malloc(sizeof(struct Pair));
pair->subnodes = ((COMPS_MRTreeData*)it->data)->subnodes;

if (parent_pair->key != NULL) {
pair->key =
malloc(sizeof(char)
* (strlen(((COMPS_MRTreeData*)it->data)->key)
+ strlen(parent_pair->key) + 1));
memcpy(pair->key, parent_pair->key,
sizeof(char) * strlen(parent_pair->key));
memcpy(pair->key+strlen(parent_pair->key),
((COMPS_MRTreeData*)it->data)->key,
sizeof(char)*(strlen(((COMPS_MRTreeData*)it->data)->key)+1));
} else {
pair->key = malloc(sizeof(char)*
(strlen(((COMPS_MRTreeData*)it->data)->key) +
1));
memcpy(pair->key, ((COMPS_MRTreeData*)it->data)->key,
sizeof(char)*(strlen(((COMPS_MRTreeData*)it->data)->key)+1));
}
/* current node has data */
if (((COMPS_MRTreeData*)it->data)->data->first != NULL) {
for (it2 = ((COMPS_MRTreeData*)it->data)->data->first;
it2 != NULL; it2 = it2->next) {
comps_mrtree_set(rt1, pair->key, it2->data);
}

if (((COMPS_MRTreeData*)it->data)->subnodes->first) {
comps_hslist_append(tmplist, pair, 0);
} else {
free(pair->key);
free(pair);
}
/* current node hasn't data */
} else {
if (((COMPS_MRTreeData*)it->data)->subnodes->first) {
comps_hslist_append(tmplist, pair, 0);
} else {
free(pair->key);
free(pair);
}
}
}
free(parent_pair->key);
free(parent_pair);
}
comps_hslist_destroy(&tmplist);
}


// Correct Vulnerability Detection
// BigVul Row No: 4692
// BigVul ID (big_vul_while.csv): 3782
// CppCheck ID: 149
// CWE-ID: CWE-416
