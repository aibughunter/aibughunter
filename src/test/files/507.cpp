static noinline void key_gc_unused_keys(struct list_head *keys)
{
while (!list_empty(keys)) {
struct key *key =
list_entry(keys->next, struct key, graveyard_link);
list_del(&key->graveyard_link);

kdebug("- %u", key->serial);
key_check(key);

security_key_free(key);

/* deal with the user's key tracking and quota */
if (test_bit(KEY_FLAG_IN_QUOTA, &key->flags)) {
spin_lock(&key->user->lock);
key->user->qnkeys--;
key->user->qnbytes -= key->quotalen;
spin_unlock(&key->user->lock);
}

atomic_dec(&key->user->nkeys);
if (test_bit(KEY_FLAG_INSTANTIATED, &key->flags))
atomic_dec(&key->user->nikeys);

		key_user_put(key->user);
/* now throw away the key memory */
if (key->type->destroy)
key->type->destroy(key);

kfree(key->description);

#ifdef KEY_DEBUGGING
key->magic = KEY_DEBUG_MAGIC_X;
#endif
kmem_cache_free(key_jar, key);
}
}

// Vulnerability Detection Working
// BigVul Row No: 1797
// BigVul ID (big_vul_while.csv): 3479
// CppCheck ID: 507
// CWE-ID: CWE-20 (Top 4, Improper input validation)