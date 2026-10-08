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
           input="roots", traffic="passive", produces=("observations",), pipeline="M1"),
    Module("resolve", "Resolve hosts", "A, AAAA and CNAME records for in-scope hosts.",
           input="hosts", traffic="dns", after=("subdomains",), produces=("observations",), pipeline="M1"),
    Module("ports", "Scan ports",
           "Top 100 TCP ports per host (connect scan, port 25 skipped), within the engagement rate limit.",
           input="hosts", traffic="target", opt_in=True, after=("resolve",), produces=("observations",),
           pipeline="M2", caution="Many programs forbid port scanning. Enable only if the policy allows it."),
    Module("probe", "Find live web servers",
           "One request per host and open port, with your research identification; records status, title, "
           "stack and CDN, and scores each host.",
           input="hosts", traffic="target", http=True, after=("ports", "resolve"), produces=("observations",),
           pipeline="M2"),
    Module("crawl", "Crawl golden hosts",
           "Crawls the highest-scoring hosts on the same host only, parsing JavaScript; logout, delete and "
           "similar paths are never followed.",
           input="urls", traffic="target", http=True, after=("probe",), produces=("endpoints",), pipeline="M4"),
    Module("archive", "Collect archived URLs",
           "Historical URLs from public archives (gau, Wayback Machine); nothing is sent to the target.",
           input="roots", traffic="passive", produces=("endpoints",), pipeline="M4"),
    Module("jsanalyze", "Analyse JavaScript",
           "Downloads in-scope JS files, highest-scoring hosts first (250 per run; the rest can be resumed), and extracts endpoints, GraphQL operations, sourcemaps and "
           "secret candidates; secrets are stored masked and are never tested.",
           input="urls", traffic="target", http=True, after=("crawl", "archive"), produces=("endpoints", "leads"),
           pipeline="M8", max_targets=250),
    Module("content", "Discover content",
           "feroxbuster over golden hosts (up to 10 per run), one at a time, common.txt wordlist, no recursion. Skips hosts that "
           "answer every path the same way, never follows redirects or extracted links, never requests "
           "logout, delete or similar paths, and stays within the rate limit in total.",
           input="urls", traffic="target", http=True, opt_in=True, after=("probe",), produces=("endpoints",),
           pipeline="M3", max_targets=10,
           caution="Brute-forces paths: thousands of requests per host. Enable only if the program allows "
                   "content discovery."),
    Module("nuclei", "Scan for known issues",
           "nuclei over live web services: takeover checks on every host; exposures, misconfigurations and "
           "templates matching the detected stack on one host per cluster; panels, vulnerabilities and CVEs "
           "on golden hosts. Medium severity and up. Never runs DoS, fuzzing, brute-force or default-login "
           "templates, follows no redirects and makes no out-of-band callbacks.",
           input="urls", traffic="target", http=True, opt_in=True, after=("probe",), produces=("leads",),
           pipeline="M7", caution="Automated vulnerability scanning: many programs forbid it or require "
                                  "a lower rate. Enable only if the policy allows scanners."),
)

BY_KIND: dict[str, Module] = {m.kind: m for m in MODULES}
assert len(BY_KIND) == len(MODULES), "duplicate module kind"
OPT_IN_KINDS = frozenset(m.kind for m in MODULES if m.opt_in)


def get(kind: str) -> Module | None:
    return BY_KIND.get(kind)


def as_dict(m: Module) -> dict:
    return {"kind": m.kind, "title": m.title, "summary": m.summary, "input": m.input,
            "traffic": m.traffic, "http": m.http, "opt_in": m.opt_in, "after": list(m.after),
            "produces": list(m.produces), "pipeline": m.pipeline, "caution": m.caution,
            "needs_identification": m.needs_identification, "max_targets": m.max_targets}
