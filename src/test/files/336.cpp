print_bacp_config_options(netdissect_options *ndo,
const u_char *p, int length)
{
int len, opt;

if (length < 2)
return 0;
ND_TCHECK2(*p, 2);
len = p[1];
opt = p[0];
if (length < len)
return 0;
if (len < 2) {
ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u (length bogus, should be >= 2)",
tok2str(bacconfopts_values, "Unknown", opt),
opt,
len));
return 0;
}

ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u",
tok2str(bacconfopts_values, "Unknown", opt),
opt,
len));

switch (opt) {
case BACPOPT_FPEER:
if (len != 6) {
ND_PRINT((ndo, " (length bogus, should be = 6)"));
return len;
}
		ND_TCHECK2(*(p + 2), 4);
ND_PRINT((ndo, ": Magic-Num 0x%08x", EXTRACT_32BITS(p + 2)));
break;
default:
/*
* Unknown option; dump it as raw bytes now if we're
* not going to do so below.
*/
if (ndo->ndo_vflag < 2)
print_unknown_data(ndo, &p[2], "\n\t    ", len - 2);
break;
}
if (ndo->ndo_vflag > 1)
print_unknown_data(ndo, &p[2], "\n\t    ", len - 2); /* exclude TLV header */

return len;

trunc:
ND_PRINT((ndo, "[|bacp]"));
return 0;
}

// Vulnerability Detection Working with correct CWE code
// BigVul Row No: 2960
// BigVul ID (big_vul_while.csv): 2329
// CppCheck ID: 336
// CWE-ID: CWE-125 (Top-5, Out-of-bounds read)