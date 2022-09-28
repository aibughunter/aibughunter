php_http_url_t *php_http_url_parse(const char *str, size_t len, unsigned flags TSRMLS_DC)
{
size_t maxlen = 3 * len;
struct parse_state *state = ecalloc(1, sizeof(*state) + maxlen);

state->end = str + len;
state->ptr = str;
state->flags = flags;
state->maxlen = maxlen;
TSRMLS_SET_CTX(state->ts);

if (!parse_scheme(state)) {
php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to parse URL scheme: '%s'", state->ptr);
efree(state);
return NULL;
}

if (!parse_hier(state)) {
efree(state);
return NULL;
}

if (!parse_query(state)) {
php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to parse URL query: '%s'", state->ptr);
efree(state);
return NULL;
}

if (!parse_fragment(state)) {
php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to parse URL fragment: '%s'", state->ptr);
efree(state);
return NULL;
}

return (php_http_url_t *) state;
}

// CWE-ID Detection: Working
// Line Detection: Not Working (Should be line 3)

// BigVul Row No: 3886
// BigVul ID (big_vul_while.csv): 780
// CppCheck ID: 175
// CWE-ID: CWE-119 (Top-19, Improper restriction of operations within the bounds of a memory buffer)