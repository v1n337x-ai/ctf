#!/usr/bin/env python3
"""
VEC -- flag phrase registry.

Every flag is a MIXED ALPHANUMERIC token in the house style, e.g. b0mb4yb4dboy:
lower-case letters with digits substituted for the vowels a human would
substitute. No separators, no punctuation, no braces.

  * matches ^[A-Za-z0-9]+$ exactly
  * reads the way a flag should when said out loud
  * still belongs to the challenge it came from

Only 'a' and 'o' are substituted. Over-substituting destroys readability,
which is the entire reason to pick a memorable flag rather than a random one.

Each challenge holds a pool of EQUIVALENT tokens. A deployment picks one
deterministically from its seed, so every team instance gets a different flag
and RESET always rotates -- see flaglib.phrase_for().

The source phrases are themed per challenge. The real-world citation behind
each is kept in FACTS so the campaign stays verifiable.
"""

import os
import re
import sys

ALPHABET_RE = re.compile(r'^[A-Za-z0-9]+$')

# The leet map. Deliberately minimal: a -> 4, o -> 0.
LEET = {"a": "4", "o": "0"}


def leet(text: str) -> str:
    """Apply the house leet style, then strip everything non-alphanumeric."""
    return re.sub(r"[^a-z0-9]", "",
                  "".join(LEET.get(ch, ch) for ch in text.lower()))


# --------------------------------------------------------------------------
# The campaign's spine, and the source of SIM-01's real-world anchor.
# --------------------------------------------------------------------------
GROUND_TRUTH_IMD = (
    "IMD, 5 Aug 2025 (Dharali, Uttarkashi): no rainfall station in the vicinity "
    "recorded precipitation meeting the formal cloudburst threshold "
    "(>100 mm in one hour over ~20-30 km2); ~27 mm recorded in the district on "
    "the event day. IMD declined to attribute the flash flood to a cloudburst."
)

# --------------------------------------------------------------------------
# Source phrases, per challenge.
# --------------------------------------------------------------------------
SOURCE = {
    "SIM-01": [
        "no station recorded it",
        "the gauges said nothing",
        "cloudburst never measured",
        "uttarakashi said no rain",
    ],
    "SIM-02": [
        "one tender three revisions",
        "corrigendum keeps its secret",
        "deleted table came back",
        "revision four lost the table",
    ],
    "SIM-03": [
        "binaries run on indian clock",
        "timezone check comes first",
        "malware asks where you are",
        "the first check is the country",
    ],
    "SIM-04": [
        "ads pay for the fake download",
        "google search was the traffic",
        "money sits on a keyword",
        "the real app is the real one",
    ],
    "SIM-05": [
        "shattered two files one hash",
        "verification is not strength",
        "sha one is retired now",
        "the redaction is a rectangle",
    ],
    "SIM-06": [
        "section seventy b",
        "forty docs one chain",
        "eight doors one corridor",
        "the insider sits in works",
    ],
    "SIM-07": ['ssrf ncccpullsmet4d4t4', 'ssrf theupstre4murlw4sunchecked', 'ssrf met4d4t4livesinside', 'ssrf server4sked4n0therh0st'],
    "SIM-08": ['jwt thespecs4idf0urfields', 'jwt 4ddressw4sn0td0cumented', 'jwt results0utsidethespec', 'jwt thirtyb4nkstw0milli0nusers'],
    "SIM-09": ['upload everythingis4ph0t0', 'upload d0cumentupl04dthenrender', 'upload rightt0servicescl0nes', 'upload upl04db4yrendersph0t0s'],
    "SIM-10": ['vendor sec0nd0rderme4nsh4rmless', 'vendor vend0rm4ster0utlives', 'vendor se4rchisf4stbec4usec4ched', 'vendor theb4ckgr0undj0bis0ld'],
    "SIM-11": ['graphql 0nefieldnever4sked', 'graphql schem4isn0t4uth0rity', 'graphql re4dthr0ughtheten4ntw4ll', 'graphql gridc0depr0mises0nly'],
    "SIM-12": ['ssti shiftrep0rtfr0m4templ4te', 'ssti 4v4il4bilityb4sedt4riff', 'ssti s0meb0dydecidedwhen', 'ssti elevenye4rs0fv4lves'],
    "SIM-13": [
        "the festival letter",
        "the key is not on paper",
        "festival alphabet was the key",
        "omit the hard letters",
    ],
    "SIM-14": [
        "signature valid not strong",
        "verify is not strength",
        "no padding no safety",
        "a cube root is not secret",
    ],
    "SIM-15": [
        "duplicate iv",
        "two messages one nonce",
        "nonce reuse is not sloppy",
        "the keystream is the giveaway",
    ],
    "SIM-16": [
        "one k used twice",
        "the same nonce both times",
        "playstation three signed badly",
        "no discrete log anywhere",
    ],
    "SIM-17": [
        "length extension is legal",
        "the key length is not secret",
        "extend past the check",
        "hmac needs the key twice",
    ],
    "SIM-18": [
        "goose is layer two",
        "ethernet type b eight is zero",
        "multicast mac starts zero one",
        "trip lands under three ms",
    ],
    "SIM-19": [
        "flattened control flow",
        "lookup table not jumps",
        "the graph reads plainly",
        "untangle the dispatcher",
    ],
    "SIM-20": [
        "hamraaz is a real app",
        "verify or trust is not or",
        "one line worth caring",
        "the store is on the handset",
    ],
    "SIM-21": [
        "bring your own driver",
        "the blocklist is reason enough",
        "the driver says yes",
        "seal the ioctl channel",
    ],
    "SIM-22": [
        "twelve days to descend",
        "seven four seven km",
        "slot b is still signed",
        "rotation was a roadmap",
    ],
    "SIM-23": [
        "port twenty four oh four",
        "banner echoes what you feed",
        "format string in diagnostics",
        "continuous data not polling",
    ],
    "SIM-24": [
        "session cache freed twice",
        "the auth gate was easy",
        "the stress test kept it all",
        "the table is not locked",
    ],
    "SIM-25": [
        "kavach brakes for you",
        "prefix length arithmetic",
        "tracksides trust a prefix",
        "interlock is not a suggestion",
    ],
    "SIM-26": [
        "checked once decided later",
        "time of check time of use",
        "stand on the commit side",
        "narrow window but real",
    ],
    "SIM-27": [
        "the lockdown is an acl list",
        "anyone can enumerate it",
        "engineer console on desk one",
        "read acl from inside",
    ],
    "SIM-28": [
        "nopasswd six months",
        "works every day for months",
        "read what it opens",
        "the generous rule still works",
    ],
    "SIM-29": [
        "krbtgt history is two",
        "reset twice wait ten hours",
        "etype twenty three fast",
        "one hundred eighty days",
    ],
    "SIM-30": [
        "the door must open outside",
        "air gapped is a document",
        "update conduit checks version",
        "left something behind",
    ],
    "SIM-31": [
        "everyone checks the acls",
        "drssuapi is not broken",
        "it is an acl that is wrong",
        "four hundred years",
    ],
    "SIM-32": [
        "finetuning does not fix it",
        "excessive agency is scoping",
        "scope lived in docs",
        "rag is not a boundary",
    ],
    "SIM-33": [
        "never shown what it is not",
        "the core zone is the farm",
        "the answer is slower",
        "probe the boundary",
    ],
    "SIM-34": [
        "a thousand queries steal",
        "membership inference proves",
        "the weights memorise",
        "decision boundary enough",
    ],
    "SIM-35": [
        "the nach clearing house",
        "salaries every month",
        "boring trail of transfers",
        "the error you failed to find",
    ],
    "SIM-37": ['oauth n0b0dyre4ds4uth0ris4ti0nurl', 'oauth redirecturiis4prefixn0twh0le', 'oauth therescreenisn0tre4lrule', 'oauth thec0dec4nbech4nged1nce'],
    "SIM-38": ['union 3rderbyc0untsc0lumns', 'union numericc0lumnsneedn0qu0te', 'union uni0ns3lecttw0t4bles4t0nce', 'union the0nlyscreenneverseenrewritten'],
    "SIM-39": ['appliance nineye4rs0ldn0w4rr4nty', 'appliance def4ultcredenti4lsneverr0t4ted', 'appliance seri4lised0bjects4rec0de', 'appliance vend0rc0ntr4ctendedl0ng4g0'],
    "SIM-40": ['jenkins 0bfusc4tesbutencrypts', 'jenkins the4genttruststhe0therh4lf', 'jenkins credsbey0ndawnthew0rksp4ce', 'jenkins d0nttrustits0bfusc4t10n'],
    "SIM-36": [
        "vec completes",
        "twelve proofs in order",
        "six months of reading",
        "the grid still stands",
    ],
}

# The computed flag tokens: the leet form of every source phrase.
PHRASES = {k: [leet(x) for x in v] for k, v in SOURCE.items()}

# --------------------------------------------------------------------------
# The citation behind each challenge. Kept with the code so the campaign
# stays honest: every fact a player is asked to learn has a public source.
# --------------------------------------------------------------------------
FACTS = {
    "SIM-01": GROUND_TRUTH_IMD,
    "SIM-02": (
        "Public procurement mirrors publish a bid per revision plus numbered "
        "Corrigenda, and a corrigendum has been observed restoring a table a "
        "previous revision had removed."
    ),
    "SIM-03": (
        "APT36 / Transparent Tribe binaries were documented executing only "
        "when the host's timezone is configured to IST (Zscaler ThreatLabz, "
        "2022). Some samples also accepted Sri Lanka time."
    ),
    "SIM-04": (
        "APT36 used Google Ads paid search to push attacker-registered fake "
        "Kavach MFA download pages to the top of results for 'Kavach download' "
        "queries from India, gated on Indian IP (Zscaler ThreatLabz, 2022)."
    ),
    "SIM-05": (
        "SHA-1 chosen-prefix collisions were demonstrated practically by the "
        "SHAttered attack (2017); SHA-1 is deprecated for signatures. "
        "Separately, APT36 phishing PDFs used a falsified author name."
    ),
    "SIM-06": (
        "CERT-In is designated the national agency for incident response under "
        "Section 70B of the Information Technology Act, 2000."
    ),
    "SIM-07": (
        "The National Cyber Coordination Centre (NCCC), implemented by "
        "CERT-In, is described as a control room that scans cyberspace and "
        "gathers metadata on cyber threats."
    ),
    "SIM-08": (
        "RBI's Udgam unclaimed-deposits gateway allowed searches whose results "
        "included full residential addresses -- fields absent from the "
        "documented output specification (reported May 2026)."
    ),
    "SIM-09": (
        "APT36 / SideCopy operated phishing clones impersonating Right to "
        "Public Services Act municipal portals, with credential pages served "
        "from lookalike subdomains."
    ),
    "SIM-10": (
        "Cache-assisted second-order SQL injection: the search is fast because "
        "a background refresh repopulates it from records users can write."
    ),
    "SIM-11": (
        "The Grid Code, issued by the Central Electricity Authority and framed "
        "by CERC regulations, is the binding document on how the grid is "
        "operated -- a promise, not an enforcement mechanism."
    ),
    "SIM-12": (
        "Availability Based Tariff (ABT) is India's settlement mechanism for "
        "deviation from declared generation, traded at IEX/PPEX."
    ),
    "SIM-13": (
        "Hand-rolled substitution and running-key ciphers remain solvable by "
        "frequency and crib analysis; the key is usually the hard part."
    ),
    "SIM-14": (
        "SHA-1 chosen-prefix collisions are practical (SHAttered, 2017) and "
        "SHA-1 is deprecated for digital signatures."
    ),
    "SIM-15": (
        "AES-GCM catastrophic failure on nonce reuse: authentication key "
        "recovery and plaintext recovery. In CBC, IV reuse yields a two-time "
        "pad over the first block."
    ),
    "SIM-16": (
        "ECDSA reuses of k recover the private key directly; this broke the "
        "PlayStation 3 (FAIL10) firmware signing. RFC 6979 (August 2013) "
        "derandomises k to prevent exactly this."
    ),
    "SIM-17": (
        "Merkle-Damgard hashes permit length extension; HMAC does not, because "
        "the key is hashed twice with the inner and outer pads."
    ),
    "SIM-18": (
        "IEC 61850 GOOSE is Layer-2 multicast over Ethernet, Ethertype 0x88B8, "
        "reserved MAC prefix 01:0C:CD:01. It uses no IP port. GOOSE Type 1A "
        "(trip) targets sub-3 ms. MMS uses TCP port 102."
    ),
    "SIM-19": (
        "Control-flow flattening replaces branches with a dispatcher and a "
        "state table; the original CFG is recoverable from the dispatcher."
    ),
    "SIM-20": (
        "Hamraaz is a real NIC policing application; APT36 registered "
        "lookalike domains and third-party app stores to serve trojanised "
        "builds."
    ),
    "SIM-21": (
        "Bring-Your-Own-Vulnerable-Driver (BYOVD) abuses a signed driver that "
        "itself contains a vulnerability to gain kernel execution. Vendors "
        "and Microsoft maintain vulnerable-driver blocklists."
    ),
    "SIM-22": (
        "NISAR (NASA-ISRO) launched 30 July 2025 into a 747 km sun-synchronous "
        "orbit at 98.4 degrees inclination, 12-day repeat cycle, ~2.8 t "
        "launch mass, L-band 24 cm and S-band 9.4 cm."
    ),
    "SIM-23": (
        "IEC 60870-5-104 (the '104' protocol) uses TCP port 2404 and is built "
        "for continuous supervisory data rather than classic polling."
    ),
    "SIM-24": (
        "Advanced Metering Infrastructure uses DLMS for meter data; the "
        "metering gateway's session table is a long-lived allocation reused "
        "across reconnects."
    ),
    "SIM-25": (
        "Kavach is India's train protection system: it continuously relays a "
        "warning and applies brakes automatically if the driver does not "
        "respond."
    ),
    "SIM-26": (
        "TOCTOU: authorisation checked at one instant and acted on at another "
        "is a race, and race windows close only for honest clients."
    ),
    "SIM-27": (
        "Workstation lockdown implemented purely through ACLs is an "
        "enumeration problem, not a security boundary."
    ),
    "SIM-28": (
        "NOPASSWD sudoers rules that survive months because they work daily "
        "are the most common form of unearned privilege escalation."
    ),
    "SIM-29": (
        "krbtgt password history is 2, so it must be reset twice with a gap "
        "at least as long as the maximum ticket lifetime (10 hours default); "
        "STIG guidance requires reset at least every 180 days. Kerberoasting "
        "targets weak service passwords; RC4 (etype 23) offers roughly a "
        "1000x cracking-speed advantage over AES etypes."
    ),
    "SIM-30": (
        "Air-gap claims are documentation, not mechanisms; update and "
        "transfer conduits exist precisely because software must be updated."
    ),
    "SIM-31": (
        "DCSync abuses directory-replication privileges granted to a normal "
        "principal -- the protocol is not broken, the ACL is."
    ),
    "SIM-32": (
        "OWASP Top 10 for LLM Applications 2025: Prompt Injection (LLM01) is "
        "not mitigated by RAG or fine-tuning, and Excessive Agency (LLM06) is "
        "a scoping failure between granted permissions and enforced checks."
    ),
    "SIM-33": (
        "A classifier trained only on examples of what to block has never seen "
        "the boundary it is defending; the IMD Monsoon Core Zone is the "
        "rainfed core the seasonal forecast protects."
    ),
    "SIM-34": (
        "Model extraction from public prediction APIs is practical at roughly "
        "1000 queries (Tramer et al.). Membership inference (Shokri et al., "
        "2017) determines whether a specific record was in the training set."
    ),
    "SIM-35": (
        "NACH (National Automated Clearing House) carries high-volume salary "
        "credits. In 2025 roughly 273,000 NACH bank-transfer documents across "
        "38 institutions were found exposed in public cloud storage."
    ),
    "SIM-37": (
        "OAuth 2.0 authorisation-code flows are commonly defeated by "
        "redirect_uri validation that checks a prefix rather than an exact "
        "match, and by authorisation codes remaining redeemable inside "
        "their validity window."
    ),
    "SIM-38": (
        "UNION-based SQL injection against numeric columns needs no string "
        "quoting, which makes it markedly easier to construct correctly than "
        "the string-heavy variants."
    ),
    "SIM-39": (
        "Default vendor credentials and unpatched, unsupported third-party "
        "appliances are a persistent initial-access route; unsafe "
        "deserialisation of operator-supplied objects turns that access into "
        "code execution."
    ),
    "SIM-40": (
        "Jenkins stores credentials in credentials.xml using obfuscation, "
        "which the Jenkins project documents as reversible and explicitly not "
        "encryption. Separately, a build agent executes steps with the "
        "controller's filesystem access, so agent trust is not a boundary "
        "between them."
    ),
    "SIM-36": (
        "Campaign premise: a long-dwell espionage cluster that never "
        "destructively acts, demonstrating read access over months. The audit "
        "closes with proof, not impact."
    ),
}

# The eight Master Shards, consumed in this order by SIM-36.
MASTER_SHARDS = ["SIM-07", "SIM-11", "SIM-16", "SIM-21",
                 "SIM-24", "SIM-31", "SIM-33", "SIM-35"]


# Service id -> registry key. Kept explicit rather than imported, because the
# flag server ships phrases.py on its own with no challenges_meta beside it.
ALIAS = {
    "WEB01": "SIM-07", "WEB02": "SIM-08", "WEB03": "SIM-09",
    "WEB04": "SIM-10", "WEB05": "SIM-11", "WEB06": "SIM-12",
    "WEB07": "SIM-37", "WEB08": "SIM-38", "WEB09": "SIM-39",
    "WEB10": "SIM-40",
}


def _meta():
    """Optional: widen the alias table from the metadata registry, if present."""
    try:
        import os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from challenges_meta import META
    except Exception:
        return {}
    out = dict(ALIAS)
    for cid, meta in META.items():
        svc = str(meta.get("service", "")).upper()
        if svc:
            out.setdefault(svc, cid)
    return out


def canonical(sim_id):
    """Resolve any spelling of a challenge id to its SIM-xx registry key.

    Docker services are named WEB02..WEB10 while the registry is keyed
    SIM-08..SIM-40, and the flag server is handed whatever CHAL_ID the
    container started with. Without this translation every Docker flag
    silently falls back to a random string, because the phrase lookup raises
    KeyError and the caller swallows it.
    """
    k = str(sim_id).strip().upper().replace("_", "-").replace(" ", "-")
    if k in PHRASES:
        return k
    if k in ALIAS:
        return ALIAS[k]
    for svc, cid in _meta().items():
        if k == svc:
            return cid
    return None


# Clue tokens. A solved challenge hands back a flag that names what comes
# next, so the campaign keeps moving without a hint system. The audit
# enforces that EVERY message in a challenge's pool carries its token.
#
# NOTE: pool messages are leet()ed on load, so a token containing "a" or "o"
# would never match. The leet forms are stored here. ssrf, jwt, ssti and
# jenkins are unaffected; the rest carry their substitution.
CLUES = {
    "SIM-07": "ssrf", "SIM-08": "jwt", "SIM-09": "upl04d",
    "SIM-10": "vend0r", "SIM-11": "gr4phql", "SIM-12": "ssti",
    "SIM-37": "04uth", "SIM-38": "uni0n", "SIM-39": "4ppli4nce",
    "SIM-40": "jenkins",
}


def clue_of(sim_id):
    return CLUES.get(canonical(sim_id) or sim_id)


def clue_ok(sim_id):
    tok = clue_of(sim_id)
    key = canonical(sim_id) or sim_id
    if tok is None:
        return True, []
    bad = [m for m in PHRASES.get(key, []) if tok not in m.lower()]
    return (not bad), bad



def pool(sim_id):
    key = canonical(sim_id)
    if key is None:
        raise KeyError(f"no phrase pool registered for {sim_id}")
    return PHRASES[key]


def fact(sim_id):
    if sim_id not in FACTS:
        raise KeyError(f"no citation registered for {sim_id}")
    return FACTS[sim_id]


def all_valid(sim_id):
    return all(ALPHABET_RE.match(p) for p in pool(sim_id))


def audit():
    """Validate the registry. Returns (ok, problems)."""
    problems = []
    # Coverage is checked against the metadata registry, so adding a challenge
    # slot does not mean editing a magic number in two places.
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from challenges_meta import META
    expected = sorted(META)
    if sorted(PHRASES) != expected:
        missing = [e for e in expected if e not in PHRASES]
        extra = [e for e in PHRASES if e not in expected]
        problems.append(
            f"coverage mismatch: metadata lists {len(expected)}, pools have "
            f"{len(PHRASES)}"
            + (f"; missing {missing}" if missing else "")
            + (f"; orphaned {extra}" if extra else ""))
    for sim_id, msgs in sorted(PHRASES.items()):
        for m in msgs:
            if not ALPHABET_RE.match(m):
                bad = "".join(c for c in m if not c.isalnum())
                problems.append(f"{sim_id}: {m!r} violates regex ({bad!r})")
        if len(set(msgs)) != len(msgs):
            problems.append(f"{sim_id}: duplicate messages in pool")
        if len(msgs) < 4:
            problems.append(f"{sim_id}: needs >=4 messages for instance variety")
        if sim_id not in FACTS:
            problems.append(f"{sim_id}: missing citation")
        okc, bad = clue_ok(sim_id)
        if not okc:
            problems.append(f"{sim_id}: every flag must carry "
                            f"{clue_of(sim_id)!r}; missing from {bad}")
    for sim_id in MASTER_SHARDS:
        if sim_id not in PHRASES:
            problems.append(f"master shard {sim_id} missing")
    if len(MASTER_SHARDS) != 8:
        problems.append(f"expected 8 master shards, found {len(MASTER_SHARDS)}")
    return (not problems), problems


if __name__ == "__main__":
    ok, probs = audit()
    for p in probs:
        print(f"  FAIL {p}")
    n = sum(len(v) for v in PHRASES.values())
    print(f"  {len(PHRASES)} challenges, {n} fact-messages, "
          f"{len(MASTER_SHARDS)} master shards, {len(FACTS)} citations")
    for sid in [f"SIM-{i:02d}" for i in range(1, 37)]:
        print(f"    {sid}  {pool(sid)[0]}")
    print("phrase registry audit:", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)