// GeoIP tables: registration-geography country ranges, ASN-based hosting
// inference, and an explicit datacenter CIDR overlay — the three-table
// stack from docs/geoip-design.md. Pure parsing + binary search; the
// update pipeline (download/verify/swap) is a systemd timer's job.
//
// Privacy invariant: nothing here touches user query data. The tables are
// public registry artifacts; the only local state magdns keeps is its
// answer cache.
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone)]
struct V4Range {
    start: u32,
    end: u32, // inclusive
    /// delegated: ISO country code; x4bnet: "dc"; iptoasn: empty
    tag: String,
    /// IPtoASN AS name (empty for other tables)
    as_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct GeoTables {
    v4: Vec<V4Range>,       // sorted by start; ranges assumed disjoint per table merge
    dc_v4: Vec<(u32, u32)>, // explicit datacenter overlay
}

const HOSTING_KEYWORDS: &[&str] = &[
    "OVH",
    "HETZNER",
    "AWS",
    "AMAZON",
    "GOOGLE CLOUD",
    "MICROSOFT",
    "AZURE",
    "ORACLE",
    "ALIBABA",
    "DIGITALOCEAN",
    "LINODE",
    "VULTR",
    "CHOOPA",
    "SCALEWAY",
    "LEASEWEB",
    "M247",
    "DATACAMP",
];

impl GeoTables {
    /// Load all three tables from `dir` (delegated-extended text,
    /// ip2asn-v4.tsv already gunzipped, x4bnet ipv4.txt). Missing overlay
    /// files are non-fatal; the country table is required.
    pub fn load(dir: &Path) -> Result<Self, String> {
        let delegated = std::fs::read_to_string(dir.join("delegated-extended-latest"))
            .map_err(|e| format!("geo: country table: {e}"))?;
        let mut v4 = parse_delegated(&delegated)?;

        if let Ok(tsv) = std::fs::read_to_string(dir.join("ip2asn-v4.tsv")) {
            v4.extend(parse_iptoasn(&tsv));
        }
        let mut dc_v4 = Vec::new();
        if let Ok(txt) = std::fs::read_to_string(dir.join("x4bnet-dc-v4.txt")) {
            dc_v4 = parse_x4bnet(&txt);
        }
        v4.sort_by_key(|r| r.start);
        dc_v4.sort_unstable();
        Ok(GeoTables { v4, dc_v4 })
    }

    fn probe(&self, ip: std::net::Ipv4Addr) -> Option<(&V4Range, bool)> {
        let o = u32::from(ip);
        let idx = self.v4.partition_point(|r| r.start <= o).checked_sub(1)?;
        let r = self.v4.get(idx)?;
        (o >= r.start && o <= r.end).then_some((r, true))
    }

    /// Registration country code of the address, e.g. "CN".
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        // v6 has no table in v1: no ECS decision can be geo-informed,
        // callers treat None as "skip ECS"
        let v4 = match ip {
            IpAddr::V4(v4) => v4,
            _ => return None,
        };
        let (r, hit) = self.probe(v4)?;
        if !hit || r.tag.is_empty() {
            return None;
        }
        Some(r.tag.clone())
    }

    /// Hosting classification: datacenter overlay first (explicit beats
    /// inference), then AS-name keywords.
    pub fn is_hosting(&self, ip: IpAddr) -> bool {
        // v6 overlay not carried in v1
        let v4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return false,
        };
        let o = u32::from(v4);
        if self
            .dc_v4
            .binary_search_by(|(s, e)| {
                if o < *s {
                    std::cmp::Ordering::Greater
                } else if o > *e {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
        {
            return true;
        }
        let Some((r, hit)) = self.probe(v4) else {
            return false;
        };
        if !hit || r.as_name.is_empty() {
            return false;
        }
        let name_upper = r.as_name.to_uppercase();
        HOSTING_KEYWORDS.iter().any(|kw| name_upper.contains(kw))
    }

    /// Largest real prefix registered to `cc` that is NOT classified as
    /// hosting — the country's biggest residential-looking ISP range. This
    /// is both the consolidation representative and the masquerade target:
    /// public registry data only, zero user-derived state.
    pub fn biggest_residential_prefix(&self, cc: &str, max_prefix: u8) -> Option<(IpAddr, u8)> {
        let cc_upper = cc.to_uppercase();
        self.v4
            .iter()
            .filter(|r| r.tag.eq_ignore_ascii_case(&cc_upper))
            .filter(|r| {
                let o_start = r.start;
                let o_end = r.end;
                let mid = o_start.wrapping_add(o_end.wrapping_sub(o_start) / 2);
                let mid_ip = std::net::Ipv4Addr::from(mid);
                !self.is_hosting(IpAddr::V4(mid_ip))
            })
            .map(|r| {
                let span = r.end - r.start + 1;
                // log2 of the span gives the natural prefix length
                let host_bits = 32 - span.next_power_of_two().trailing_zeros().min(32);
                let pfx = (host_bits as u8).clamp(0, max_prefix.min(24));
                (std::net::IpAddr::V4(std::net::Ipv4Addr::from(r.start)), pfx)
            })
            .max_by_key(|(_, pfx)| *pfx) // largest prefix = smallest block = most specific ISP range
    }

    /// Consolidation representative for ECS reporting: same as the biggest
    /// residential prefix but floored at /24 so we never report something
    /// longer than consumers act on.
    pub fn representative(&self, cc: &str) -> Option<(IpAddr, u8)> {
        self.biggest_residential_prefix(cc, 24)
    }
}

/// `delegated-extended` line shape:
/// `apnic|CN|ipv4|1.2.3.0|16777216|20240101|allocated`
fn parse_delegated(text: &str) -> Result<Vec<V4Range>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('|') || line.trim().is_empty() {
            continue; // version/summary headers
        }
        let f: Vec<&str> = line.split('|').collect();
        if f.len() < 7 || f[2] != "ipv4" {
            continue;
        }
        let Ok(start) = f[3].parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        let Ok(count) = f[4].parse::<u64>() else {
            continue;
        };
        if count == 0 || count > (1u64 << 32) {
            continue;
        }
        let end = u32::from(start) + (count as u32 - 1);
        out.push(V4Range {
            start: u32::from(start),
            end,
            tag: f[1].to_string(),
            as_name: String::new(),
        });
    }
    if out.is_empty() {
        return Err("geo: delegated table parsed to zero ipv4 rows".into());
    }
    Ok(out)
}

/// IPtoASN TSV: `start\tend\tasn\tcountry\tasname`
fn parse_iptoasn(text: &str) -> Vec<V4Range> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 || !f[0].contains('.') {
            continue; // v6 rows skipped in v1
        }
        let (Ok(start), Ok(end)) = (
            f[0].parse::<std::net::Ipv4Addr>(),
            f[1].parse::<std::net::Ipv4Addr>(),
        ) else {
            continue;
        };
        out.push(V4Range {
            start: u32::from(start),
            end: u32::from(end),
            tag: f[3].to_string(),
            as_name: f[4].to_string(),
        });
    }
    out
}

/// X4BNet lists_vpn ipv4.txt: one CIDR per line (`1.2.3.0/24`),
/// optionally with a trailing comment after whitespace/#.
fn parse_x4bnet(text: &str) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cidr = line.split_whitespace().next().unwrap_or("");
        let Some((ip_s, p_s)) = cidr.split_once('/') else {
            continue;
        };
        let (Ok(ip), Ok(p)) = (ip_s.parse::<std::net::Ipv4Addr>(), p_s.parse::<u8>()) else {
            continue;
        };
        if p == 0 {
            continue;
        }
        let mask = u32::MAX << (32 - p as u32);
        let start = u32::from(ip) & mask;
        out.push((start, start | (!mask)));
    }
    out
}

/// Load-gated consolidation switch (GeoIP design §Behavior-1): a five-bucket
/// sliding window over outbound query counters. Enters at the watermark,
/// exits at half of it — hysteresis against threshold flapping.
pub struct ConsolidationGate {
    window: Mutex<[AtomicU64; 5]>,
    slot: AtomicUsize,
    entered: AtomicBool,
    watermark: u64,
}

impl ConsolidationGate {
    pub fn new(watermark: u64) -> Self {
        ConsolidationGate {
            window: Mutex::new([
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ]),
            slot: AtomicUsize::new(0),
            entered: AtomicBool::new(false),
            watermark: watermark.max(1),
        }
    }

    /// Count one outbound query in the current second-bucket.
    pub fn bump(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as usize)
            .unwrap_or(0)
            % 5;
        let cur = self.slot.swap(now, Ordering::Relaxed);
        if cur != now {
            self.window.lock().unwrap()[cur].store(0, Ordering::Relaxed);
        }
        self.window.lock().unwrap()[now].fetch_add(1, Ordering::Relaxed);
    }

    pub fn engaged(&self) -> bool {
        let rate: u64 = self
            .window
            .lock()
            .unwrap()
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .sum::<u64>()
            / 5;
        match self.entered.load(Ordering::Relaxed) {
            true => {
                if rate < self.watermark / 2 {
                    self.entered.store(false, Ordering::Relaxed);
                    false
                } else {
                    true
                }
            }
            false => {
                if rate >= self.watermark {
                    self.entered.store(true, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DELEGATED: &str = "version|20240101|000000
apnic|CN|ipv4|1.2.3.0|1024|20240101|allocated
ripencc|DE|ipv4|5.9.0.0|16384|20240101|allocated
apnic|JP|ipv4|126.0.0.0|1048576|20240101|allocated
";

    const IPTOASN: &str = "3.5.140.0\t3.5.141.255\t16550\tUS\tGOOGLE-CLOUD-PLATFORM, US\n\
8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE, US\n\
5.9.0.0\t5.9.255.255\t24940\tDE\tHETZNER-RZ-NBG-GERMANY, DE\n";

    const X4BNET: &str = "3.5.128.0/17\n203.0.113.0/24\n";

    fn tables() -> GeoTables {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("magdns-geo-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("delegated-extended-latest"), DELEGATED).unwrap();
        std::fs::write(dir.join("ip2asn-v4.tsv"), IPTOASN).unwrap();
        std::fs::write(dir.join("x4bnet-dc-v4.txt"), X4BNET).unwrap();
        let t = GeoTables::load(&dir).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        t
    }

    #[test]
    fn country_lookup_binary_search() {
        let t = tables();
        assert_eq!(
            t.country("1.2.3.99".parse().unwrap()).as_deref(),
            Some("CN")
        );
        assert_eq!(
            t.country("5.9.200.1".parse().unwrap()).as_deref(),
            Some("DE")
        );
        assert_eq!(
            t.country("126.5.0.1".parse().unwrap()).as_deref(),
            Some("JP")
        );
        assert_eq!(
            t.country("9.9.9.9".parse().unwrap()),
            None,
            "unallocated gap"
        );
    }

    #[test]
    fn hosting_overlay_beats_and_keyword_infers() {
        let t = tables();
        // 3.5.140.x is inside Google's range AND the X4BNet overlay — overlay wins
        assert!(t.is_hosting("3.5.140.10".parse().unwrap()));
        // Hetzner AS name keyword inference
        assert!(t.is_hosting("5.9.100.7".parse().unwrap()));
        // CN residential block is clean
        assert!(!t.is_hosting("1.2.3.99".parse().unwrap()));
    }

    #[test]
    fn biggest_residential_prefers_non_hosting_largest_block() {
        let t = tables();
        // DE's only delegated block is Hetzner-classified -> no residential
        assert_eq!(t.biggest_residential_prefix("DE", 24), None);
        // CN's 1.2.3.0/22-ish block is residential -> representative exists
        let rep = t.biggest_residential_prefix("CN", 24).unwrap();
        assert_eq!(rep.0, "1.2.3.0".parse::<std::net::Ipv4Addr>().unwrap());
        assert!(rep.1 <= 24);
    }
}
