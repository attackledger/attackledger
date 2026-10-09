"""Recon module registry: the single definition of every job kind.

The API gates, the worker's dispatch and the UI's pipeline steps are all derived
from this table. Adding a module means one entry here plus one runner in the
worker. The worker refuses to start if the two disagree.

Fields
  kind       job kind, also the runner key in the worker
  title      what the operator sees
  summary    one sentence on what it does
  input      "roots"  wildcard roots from scope (*.example.com -> example.com)
             "hosts"  in-scope hosts
             "urls"   in-scope URLs
  traffic    "passive" third-party sources only
             "dns"     DNS lookups only
             "target"  sends requests to the target (needs research identification)
  http       sends HTTP requests, so it must carry the research identification
             (a port scan is target traffic but has no headers to carry)
  opt_in     must be enabled per engagement because many programs forbid it
  after      kinds whose output this module normally consumes (ordering hint for the UI)
  produces   which tables it writes: observations, endpoints, leads
  max_targets  per-run ceiling; targets beyond it are listed as remaining and the run is
               partial, never silently dropped
  pipeline   original pipeline module it corresponds to
  tools      the programs it runs, as the operator knows them

PHASES groups the modules into the steps the UI shows, in pipeline order (D-026).
Every module belongs to exactly one phase.
"""
from dataclasses import dataclass, field

INPUTS = {"roots", "hosts", "urls"}
TRAFFIC = {"passive", "dns", "target"}


@dataclass(frozen=True)
class Module:
    kind: str
    title: str
    summary: str
    input: str
    traffic: str
    http: bool = False
    opt_in: bool = False
    after: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    pipeline: str = ""
    caution: str = ""  # shown next to the opt-in switch
    max_targets: int | None = None
    tools: tuple[str, ...] = ()
    min_rps: int = 1      # lowest engagement rate limit the module can keep to

    def __post_init__(self):
        assert self.input in INPUTS, self.kind
        assert self.traffic in TRAFFIC, self.kind
        assert not self.http or self.traffic == "target", self.kind

    @property
    def needs_identification(self) -> bool:
        return self.http


MODULES: tuple[Module, ...] = (
    Module("subdomains", "Find subdomains",
           "subfinder (all sources), assetfinder and certificate transparency for each wildcard in scope; "
           "names outside scope are dropped before anything is resolved.",
           input="roots", traffic="passive", produces=("observations",), pipeline="M1",
           tools=("subfinder", "assetfinder", "crt.sh")),
    Module("resolve", "Resolve hosts", "A, AAAA and CNAME records for in-scope hosts.",
           input="hosts", traffic="dns", after=("subdomains",), produces=("observations",), pipeline="M1",
           tools=("dnsx",)),
    Module("ports", "Scan ports",
           "Top 100 TCP ports per host (connect scan, port 25 skipped), within the engagement rate limit.",
           input="hosts", traffic="target", opt_in=True, after=("resolve",), produces=("observations",),
           pipeline="M2", caution="Many programs forbid port scanning. Enable only if the policy allows it.",
           tools=("naabu",)),
    Module("probe", "Find live web servers",
           "One request per host and open port, with your research identification; records status, title, "
           "stack and CDN, and scores each host.",
           input="hosts", traffic="target", http=True, after=("ports", "resolve"), produces=("observations",),
           pipeline="M2", tools=("httpx",)),
    Module("crawl", "Crawl golden hosts",
           "Crawls the highest-scoring hosts on the same host only, parsing JavaScript; logout, delete and "
           "similar paths are never followed.",
           input="urls", traffic="target", http=True, after=("probe",), produces=("endpoints",), pipeline="M4",
           tools=("katana",)),
    Module("archive", "Collect archived URLs",
           "Historical URLs from public archives (gau, Wayback Machine); nothing is sent to the target.",
           input="roots", traffic="passive", produces=("endpoints",), pipeline="M4",
           tools=("gau", "waybackurls")),
    Module("content", "Discover content",
           "feroxbuster over golden hosts (up to 10 per run), one at a time, common.txt wordlist, no recursion. Skips hosts that "
           "answer every path the same way, never follows redirects or extracted links, never requests "
           "logout, delete or similar paths, and stays within the rate limit in total.",
           input="urls", traffic="target", http=True, opt_in=True, after=("probe",), produces=("endpoints",),
           pipeline="M3", max_targets=10, min_rps=3,
           caution="Brute-forces paths: thousands of requests per host. Enable only if the program allows "
                   "content discovery.", tools=("feroxbuster",)),
    Module("jsanalyze", "Analyse JavaScript",
           "Downloads in-scope JS files, highest-scoring hosts first (250 per run; the rest can be resumed), and extracts endpoints, GraphQL operations, sourcemaps and "
           "secret candidates; secrets are stored masked and are never tested.",
           input="urls", traffic="target", http=True, after=("crawl", "archive"), produces=("endpoints", "leads"),
           pipeline="M8", max_targets=250, tools=("AttackLedger JS analyser",)),
    Module("params", "Discover hidden parameters",
           "Arjun on dynamic endpoints (query strings, script extensions, API paths), up to 20 per run, "
           "highest-scoring hosts first. Records the parameters each endpoint accepts as leads.",
           input="urls", traffic="target", http=True, opt_in=True, after=("crawl", "archive", "content"),
           produces=("leads",), pipeline="M5", max_targets=20,
           caution="Sends hundreds of requests per endpoint. Enable only if the program allows it.",
           tools=("Arjun",)),
    Module("paramclass", "Route parameters to hunt lanes",
           "Sorts every known parameter (from URLs and hidden-parameter discovery) into gf-style classes, "
           "ssrf, redirect, idor, sqli, lfi, xss and rce, and points each at the lane that tests it. Nothing is sent.",
           input="urls", traffic="passive", after=("crawl", "archive", "params"), produces=("leads",),
           pipeline="M6", tools=("gf-style patterns",)),
    Module("nuclei", "Scan for known issues",
           "nuclei over live web services: takeover checks on every host; exposures, misconfigurations and "
           "templates matching the detected stack on one host per cluster; panels, vulnerabilities and CVEs "
           "on golden hosts. Medium severity and up. Runs only templates that provably send GET, HEAD or "
           "OPTIONS requests to the target with no body; never runs DoS, fuzzing, brute-force or "
           "default-login templates, follows no redirects and makes no out-of-band callbacks.",
           input="urls", traffic="target", http=True, opt_in=True, after=("probe",), produces=("leads",),
           pipeline="M7", min_rps=2, caution="Automated vulnerability scanning: many programs forbid it or require "
                                  "a lower rate. Enable only if the policy allows scanners.",
           tools=("nuclei",)),
    Module("dorks", "Dork checklist",
           "Writes click-ready Google dorks for each wildcard root as manual checks. Dorks cannot be "
           "automated, so nothing is sent.",
           input="roots", traffic="passive", produces=("leads",), pipeline="M10",
           tools=("Google dorks, manual",)),
)

BY_KIND: dict[str, Module] = {m.kind: m for m in MODULES}
assert len(BY_KIND) == len(MODULES), "duplicate module kind"


@dataclass(frozen=True)
class Phase:
    key: str
    title: str
    summary: str
    help: str        # how the step works and why it comes here, for "How this step works"
    kinds: tuple[str, ...]


PHASES: tuple[Phase, ...] = (
    Phase("subdomains", "Find subdomains",
          "Collect host names under each wildcard in scope from passive sources.",
          "Passive sources (certificate transparency, search engines, DNS datasets) list names that were seen "
          "for a domain. Nothing is sent to the target. Names outside the scope rules are dropped before "
          "anything else happens, so later steps never see them.",
          ("subdomains",)),
    Phase("live", "Resolve and find live web servers",
          "Keep the names that resolve, then find which answer on the web and score them.",
          "Many collected names no longer exist, so only names with an address go on. Port scanning, if the "
          "program allows it, finds web services on unusual ports. One request per host and port then records "
          "status, title and technology, and each host gets a score. The highest-scoring hosts are the golden "
          "targets that the next steps focus on.",
          ("resolve", "ports", "probe")),
    Phase("urls", "Collect URLs",
          "Build the list of known URLs for the golden hosts.",
          "Crawling follows links on the same host and parses JavaScript for paths; logout and delete paths are "
          "skipped. Public archives add URLs that are no longer linked. Content discovery, if allowed, guesses "
          "common paths. URLs are cleaned: static files and URLs that differ only in parameter values are "
          "dropped.",
          ("crawl", "archive", "content")),
    Phase("js", "JavaScript and parameters",
          "Read JavaScript and parameters for endpoints, secrets and inputs worth testing.",
          "JavaScript files often name API endpoints, GraphQL operations and sourcemaps, and sometimes leak keys; "
          "secret candidates are stored masked and are never tested. Parameter discovery, if allowed, finds "
          "inputs that pages accept but do not show. Every parameter is then sorted into classes such as ssrf, "
          "redirect or idor and pointed at the hunt lane that tests it.",
          ("jsanalyze", "params", "paramclass")),
    Phase("issues", "Known issues",
          "Check live services for takeovers, exposures and known vulnerabilities.",
          "Takeover checks run on every live service. Exposure and misconfiguration templates run on one host "
          "per cluster of identical services, and CVE templates on golden hosts. Only templates that provably "
          "send nothing but GET, HEAD or OPTIONS requests run; DoS, fuzzing, brute force, default logins and "
          "out-of-band callbacks never do.",
          ("nuclei",)),
    Phase("manual", "Manual checks",
          "Searches only you can run.",
          "Search engines block automated dorking, so AttackLedger writes the queries for each root domain and "
          "you open them yourself. Anything you find goes into a lane as evidence.",
          ("dorks",)),
)
_phased = [k for p in PHASES for k in p.kinds]
assert sorted(_phased) == sorted(BY_KIND), "every module belongs to exactly one phase"
assert _phased == [m.kind for m in MODULES], "phases follow pipeline (registry) order"
PHASE_OF = {k: p.key for p in PHASES for k in p.kinds}
OPT_IN_KINDS = frozenset(m.kind for m in MODULES if m.opt_in)


def get(kind: str) -> Module | None:
    return BY_KIND.get(kind)


def as_dict(m: Module) -> dict:
    return {"kind": m.kind, "title": m.title, "summary": m.summary, "input": m.input,
            "traffic": m.traffic, "http": m.http, "opt_in": m.opt_in, "after": list(m.after),
            "produces": list(m.produces), "pipeline": m.pipeline, "caution": m.caution,
            "needs_identification": m.needs_identification, "max_targets": m.max_targets,
            "tools": list(m.tools), "phase": PHASE_OF[m.kind], "min_rps": m.min_rps}


def phase_dict(p: Phase) -> dict:
    return {"key": p.key, "title": p.title, "summary": p.summary, "help": p.help, "kinds": list(p.kinds)}
