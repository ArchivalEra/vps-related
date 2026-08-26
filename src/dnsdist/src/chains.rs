// Chain-group routing engine: the generalization of split routing.
//
// A config may declare any number of named chains; each chain is an ordered
// sequence of GROUPS, and each group holds unlimited member sources with a
// mode:
//   balance  — round-robin across members (spreads load while healthy)
//   priority — always the first alive member (serial drain semantics)
//
// Failure semantics (operator decision N4): when the chosen member of a
// group times out, errors, truncates, or answers SERVFAIL/REFUSED, the WHOLE
// group is skipped and the next group in the chain takes over — members do
// not retry each other. NXDOMAIN and empty NOERROR are legitimate answers.
//
// SPLITS map a query to its chain: first split whose domain set and source
// subnets both match wins; unmatched queries use the default chain. This
// replaces ad-hoc CN branching — "cn" becomes just another split.
use crate::app::App;
use crate::cfg::RoutingCfg;
use crate::dnsmsg;
use crate::stats::Stats;
use crate::upstream::{Health, Source};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupMode {
    Balance,
    Priority,
}

/// One member source inside a group: transport + health, built once at
/// generation construction so reload rebuilds transports wholesale.
pub struct Member {
    pub spec: crate::cfg::SourceSpec,
    pub source: Arc<Source>,
}

impl Member {
    fn build(
        spec: crate::cfg::SourceSpec,
        cfg: &crate::cfg::Cfg,
        roots: rustls::RootCertStore,
    ) -> Result<Self, String> {
        // Reuse the box's transport zoo through Source::build so every leg
        // speaks the same protocol stack as the legacy chains.
        let source = Source::build(spec.clone(), cfg, roots, Arc::new(Stats::default()))?;
        Ok(Member { spec, source })
    }
}

pub struct Group {
    pub mode: GroupMode,
    pub members: Vec<Member>,
    pub healths: Vec<Health>,
    pub rr: AtomicUsize,
}

impl Group {
    /// Pick the member this mode selects right now.
    fn pick(&self) -> Option<usize> {
        match self.mode {
            GroupMode::Balance => {
                if self.members.is_empty() {
                    None
                } else {
                    Some(self.rr.fetch_add(1, Ordering::Relaxed) % self.members.len())
                }
            }
            GroupMode::Priority => self
                .healths
                .iter()
                .position(|h| h.alive(crate::app::unix_ms())),
        }
    }
}

/// A resolved answer that must travel back to the caller untouched.
pub type Answer = Vec<u8>;

#[derive(Debug)]
pub enum StepError {
    /// this group failed as a whole — try the next one
    Skip,
    /// no group answered within budget
    Timeout,
}

pub struct Chain {
    pub name: String,
    pub groups: Vec<Group>,
}

impl Chain {
    /// Walk groups in order; each gets ONE member attempt per operator
    /// semantics (no intra-group retries). Returns the first answer whose
    /// rcode is not a failure, or the last failure if every group fails.
    pub async fn execute(
        &self,
        app: &Arc<App>,
        query: &[u8],
        _peer_ip: std::net::IpAddr,
        deadline: Instant,
    ) -> Result<Answer, StepError> {
        let mut last_fail: Option<Answer> = None;
        for group in &self.groups {
            let Some(idx) = group.pick() else { continue };
            let member = &group.members[idx];
            Stats::bump(&app.stats.fallback);
            let attempt_deadline = Instant::now()
                .checked_add(std::time::Duration::from_millis(
                    app.cfg.attempt_timeout_ms.max(200),
                ))
                .unwrap_or(deadline)
                .min(deadline);
            match member.source.attempt(query, attempt_deadline).await {
                Ok(v) => {
                    member.source.health.record_success();
                    match dnsmsg::rcode(&v) {
                        // NXDOMAIN / NOERROR-empty are real answers
                        0 | 3 => return Ok(v),
                        // SERVFAIL / REFUSED mean "this authority gave up"
                        2 | 5 => {
                            last_fail = Some(v);
                            continue;
                        }
                        _ => {
                            last_fail = Some(v);
                            continue;
                        }
                    }
                }
                Err(_e) => {
                    member
                        .source
                        .health
                        .record_failure(crate::app::unix_ms(), 10_000);
                    if Instant::now() >= deadline {
                        return Err(StepError::Timeout);
                    }
                    continue;
                }
            }
        }
        match last_fail {
            Some(v) => Ok(v),
            None => Err(StepError::Timeout),
        }
    }
}

pub struct Split {
    pub name: String,
    /// lowercase wire-format suffix trie built from file + inline domains
    pub domains: Option<crate::router::Router>,
    /// route id used by Router::resolve for this split's domain set
    pub route_id: usize,
    /// source subnets (AND with domains); empty = matches any source
    pub source_subnets: Vec<(std::net::IpAddr, u8)>,
    pub chain_index: usize,
}

impl Split {
    pub fn matches(&self, qname_lower: &str, source_ip: std::net::IpAddr) -> bool {
        if self.domains.is_none() && self.source_subnets.is_empty() {
            // a split with no matchers matches everything (default override)
        } else if let Some(r) = &self.domains {
            if r.resolve(qname_lower).is_none() {
                return false;
            }
        }
        self.source_subnets.is_empty()
            || self
                .source_subnets
                .iter()
                .any(|(net, prefix)| subnet_contains(*net, *prefix, source_ip))
    }
}

/// CIDR containment for the ingress/split subnet tables (v4+v6).
pub fn subnet_contains(net: std::net::IpAddr, prefix: u8, ip: std::net::IpAddr) -> bool {
    match (net, ip) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(i)) => {
            let p = prefix.min(32);
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) => {
            let p = prefix.min(128);
            let seg = |addr: &std::net::Ipv6Addr| -> Vec<u16> { addr.segments().to_vec() };
            let (n, i) = (seg(&n), seg(&i));
            let mut remaining = p;
            for k in 0..8 {
                if remaining == 0 {
                    return true;
                }
                let take = remaining.min(16);
                let mask = if take == 0 {
                    0
                } else {
                    u16::MAX << (16 - take)
                };
                if n[k] & mask != i[k] & mask {
                    return false;
                }
                remaining -= take;
            }
            true
        }
        _ => false,
    }
}

/// The whole engine: named chains plus ordered splits plus the fallback.
pub struct Engine {
    pub chains: Vec<Chain>,
    pub splits: Vec<Split>,
    pub default_chain: String,
}

impl Engine {
    pub fn build(routing: &RoutingCfg, cfg: &crate::cfg::Cfg) -> Result<Self, String> {
        let roots = crate::tlsconf::root_store(cfg.extra_ca.as_deref())?;
        let mut chains: Vec<Chain> = Vec::new();
        for (name, groups_cfg) in &routing.chains {
            let mut groups = Vec::new();
            for g in groups_cfg {
                let mut members = Vec::new();
                let mut healths = Vec::new();
                for m in &g.members {
                    let spec = crate::cfg::spec_from_member(m)?;
                    healths.push(Health::new());
                    members.push(Member {
                        spec: spec.clone(),
                        source: Source::build(
                            spec,
                            cfg,
                            roots.clone(),
                            Arc::new(Stats::default()),
                        )?,
                    });
                }
                groups.push(Group {
                    mode: match g.mode.as_str() {
                        "priority" => GroupMode::Priority,
                        _ => GroupMode::Balance,
                    },
                    members,
                    healths,
                    rr: AtomicUsize::new(0),
                });
            }
            chains.push(Chain {
                name: name.clone(),
                groups,
            });
        }

        let mut splits = Vec::new();
        for sp in &routing.splits {
            let chain_index = chains
                .iter()
                .position(|c| c.name == sp.chain)
                .ok_or_else(|| format!("split `{}`: unknown chain `{}`", sp.name, sp.chain))?;
            let (router, route_id) = match (&sp.domains_file, sp.domains.is_empty()) {
                (None, true) => (None, usize::MAX),
                _ => {
                    let mut r = crate::router::Router::new(vec![crate::router::Route {
                        name: sp.name.clone(),
                        upstreams: vec![],
                        cache_enabled: false,
                        ecs_enabled: false,
                    }]);
                    let mut count = 0usize;
                    if let Some(f) = &sp.domains_file {
                        let content = std::fs::read_to_string(f)
                            .map_err(|e| format!("split `{}`: read {f}: {e}", sp.name))?;
                        count = r.load_domain_list(&content, 0);
                    }
                    for d in &sp.domains {
                        let lower = d
                            .trim_start_matches("+.")
                            .trim_start_matches('.')
                            .to_lowercase();
                        count += r.load_domain_list(&format!(".{lower}"), 0);
                    }
                    eprintln!("magdns: split `{}` loaded {count} domains", sp.name);
                    (Some(r), 0)
                }
            };
            let mut source_subnets = Vec::with_capacity(sp.source_subnets.len());
            for cidr in &sp.source_subnets {
                match parse_cidr(cidr) {
                    Some(pair) => source_subnets.push(pair),
                    None => return Err(format!("split `{}`: malformed CIDR `{cidr}`", sp.name)),
                }
            }
            splits.push(Split {
                name: sp.name.clone(),
                domains: router,
                route_id,
                source_subnets,
                chain_index,
            });
        }

        Ok(Engine {
            chains,
            splits,
            default_chain: routing.default_chain.clone(),
        })
    }

    fn resolve_chain(&self, qname_lower: &str, source_ip: std::net::IpAddr) -> Option<&Chain> {
        for sp in &self.splits {
            if sp.matches(qname_lower, source_ip) {
                return self.chains.get(sp.chain_index);
            }
        }
        let idx = self
            .chains
            .iter()
            .position(|c| c.name == self.default_chain)?;
        self.chains.get(idx)
    }

    /// Full decision: pick chain by splits, execute, return raw answer.
    pub async fn resolve(
        &self,
        app: &Arc<App>,
        qname_lower: &str,
        query: &[u8],
        peer_ip: std::net::IpAddr,
        deadline: Instant,
    ) -> Result<Answer, StepError> {
        match self.resolve_chain(qname_lower, peer_ip) {
            Some(chain) => chain.execute(app, query, peer_ip, deadline).await,
            None => Err(StepError::Timeout),
        }
    }
}

fn parse_cidr(cidr: &str) -> Option<(std::net::IpAddr, u8)> {
    let (ip_s, p_s) = cidr.split_once('/')?;
    let ip: std::net::IpAddr = ip_s.parse().ok()?;
    let prefix: u8 = p_s.parse().ok()?;
    Some((ip, prefix))
}
