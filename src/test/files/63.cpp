frag6_print(netdissect_options *ndo, register const u_char *bp, register const u_char *bp2)
{
register const struct ip6_frag *dp;
register const struct ip6_hdr *ip6;

dp = (const struct ip6_frag *)bp;
ip6 = (const struct ip6_hdr *)bp2;

	ND_TCHECK(dp->ip6f_offlg);

if (ndo->ndo_vflag) {
ND_PRINT((ndo, "frag (0x%08x:%d|%ld)",
EXTRACT_32BITS(&dp->ip6f_ident),
EXTRACT_16BITS(&dp->ip6f_offlg) & IP6F_OFF_MASK,
sizeof(struct ip6_hdr) + EXTRACT_16BITS(&ip6->ip6_plen) -
(long)(bp - bp2) - sizeof(struct ip6_frag)));
} else {
ND_PRINT((ndo, "frag (%d|%ld)",
EXTRACT_16BITS(&dp->ip6f_offlg) & IP6F_OFF_MASK,
sizeof(struct ip6_hdr) + EXTRACT_16BITS(&ip6->ip6_plen) -
(long)(bp - bp2) - sizeof(struct ip6_frag)));
}

/* it is meaningless to decode non-first fragment */
if ((EXTRACT_16BITS(&dp->ip6f_offlg) & IP6F_OFF_MASK) != 0)
return -1;
else
{
ND_PRINT((ndo, " "));
return sizeof(struct ip6_frag);
}
trunc:
ND_PRINT((ndo, "[|frag]"));
return -1;
}

// CWE Detection: Working
// Line Detection: Not Working (Should be line 9)

// Orig:
// ND_TCHECK(dp->ip6f_offlg);
// To:
// ND_TCHECK(*dp);


// BigVul Row No: 2953
// BigVul ID (big_vul_while.csv): 635
// CppCheck ID: 63
// CWE-ID: CWE-125 (Top-5, Out-of-bounds read)