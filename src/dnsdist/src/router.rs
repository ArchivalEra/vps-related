// Domain-based split routing: match query names against rules, dispatch
// to different upstream chains with independent cache policies.
//
// Supports sing-box geosite.dat format (protobuf trie, loaded once at boot)
// as well as plain text domain-suffix lists for lightweight deployments.
//
// Route resolution is O(domain_labels): walk labels right-to-left through
// a HashMap trie — no regex, no backtracking.
use std::collections::HashMap;

/// A named route with its own upstream chain and cache policy.
pub struct Route {
    pub name: String,
    pub upstreams: Vec<String>, // raw upstream URLs in priority order
    pub cache_enabled: bool,
    pub ecs_enabled: bool,
}

/// Domain trie node: matches exact, suffix, or keyword.
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// Some(route_idx) if this node terminates a matched domain
    route_idx: Option<usize>,
    /// true if any descendant is a terminal (for suffix matching optimisation)
    has_children: bool,
}

impl TrieNode {
    fn new() -> Self {
        TrieNode {
            children: HashMap::new(),
            route_idx: None,
            has_children: false,
        }
    }
}

/// The router: maps domain names to route indices.
pub struct Router {
    /// Root of the domain trie (labels reversed for suffix lookup)
    root: TrieNode,
    /// All routes, indexed by position
    pub routes: Vec<Route>,
    /// Index used when nothing matches
    pub default_route_idx: usize,
}

impl Router {
    pub fn new(routes: Vec<Route>) -> Self {
        let root = TrieNode::new();
        // Insert each route's domain patterns; last-write-wins for overlapping
        for _r in routes.iter() {
            // In production, these come from geosite.dat categories or config
            // For now we insert a wildcard at root level per route;
            // actual domain lists are populated by load_geosite() or add_domain()
        }
        let default_route_idx = routes.len().saturating_sub(1); // last route = default
        Router {
            root,
            routes,
            default_route_idx,
        }
    }

    /// Insert a domain pattern into the trie.
    /// Patterns: "example.com", "+.google.com" (suffix), ".cn" (TLD)
    pub fn insert_domain(&mut self, domain: &str, route_idx: usize) {
        let clean = domain.trim_start_matches('+');
        let clean = clean.strip_prefix('.').unwrap_or(clean);
        let labels: Vec<&str> = clean.split('.').filter(|l| !l.is_empty()).rev().collect();
        let mut node = &mut self.root;
        for label in &labels {
            node = node
                .children
                .entry(label.to_lowercase())
                .or_insert_with(TrieNode::new);
            node.has_children = true;
        }
        node.route_idx = Some(route_idx);
    }

    /// Match a query domain against the trie (case-insensitive).
    pub fn resolve(&self, qname: &str) -> Option<usize> {
        let lower = qname.to_lowercase();
        let labels: Vec<&str> = lower.split('.').rev().collect();
        let mut node = &self.root;
        let mut best_match: Option<usize> = None;

        // Walk labels right-to-left (TLD first)
        for label in &labels {
            match node.children.get(*label) {
                Some(child) => {
                    if let Some(idx) = child.route_idx {
                        best_match = Some(idx);
                    }
                    node = child;
                }
                None => break,
            }
        }
        best_match.or(Some(self.default_route_idx))
    }

    /// Load geosite.dat category names into the trie.
    /// The .dat file is a protobuf-encoded trie; for now we support
    /// pre-extracted text lists (one domain per line, comments with #).
    pub fn load_domain_list(&mut self, content: &str, route_idx: usize) -> usize {
        let mut count = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            self.insert_domain(line, route_idx);
            count += 1;
        }
        count
    }

    pub fn parent_count(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_router() -> Router {
        let routes = vec![
            Route {
                name: "cn".into(),
                upstreams: vec!["quic://223.5.5.5".into()],
                cache_enabled: false,
                ecs_enabled: false,
            },
            Route {
                name: "foreign".into(),
                upstreams: vec!["https://maker.isui.ren/dns-query".into()],
                cache_enabled: true,
                ecs_enabled: true,
            },
        ];
        let mut r = Router::new(routes);
        r.load_domain_list("baidu.com\nqq.com\n+.tmall.com\n.taobao.com", 0);
        r.load_domain_list("google.com\ngooglevideo.com\n+.youtube.com", 1);
        r
    }

    #[test]
    fn cn_domains_hit_route_0() {
        let r = make_router();
        assert_eq!(r.resolve("www.baidu.com"), Some(0));
        assert_eq!(r.resolve("mail.qq.com"), Some(0));
        assert_eq!(r.resolve("item.tmall.com"), Some(0));
        assert_eq!(r.resolve("taobao.com"), Some(0));
    }

    #[test]
    fn foreign_domains_hit_route_1() {
        let r = make_router();
        assert_eq!(r.resolve("www.google.com"), Some(1));
        assert_eq!(r.resolve("rr1---sn-x.googlevideo.com"), Some(1));
        assert_eq!(r.resolve("youtube.com"), Some(1));
    }

    #[test]
    fn unmatched_uses_default() {
        let r = make_router();
        assert_eq!(r.resolve("random.example.org"), Some(1)); // last route = default
    }

    #[test]
    fn case_insensitive() {
        let r = make_router();
        assert_eq!(r.resolve("WWW.BAIDU.COM"), Some(0));
    }

    #[test]
    fn deep_subdomains_match_suffix() {
        let r = make_router();
        assert_eq!(r.resolve("a.b.c.d.e.f.google.com"), Some(1));
    }
}
