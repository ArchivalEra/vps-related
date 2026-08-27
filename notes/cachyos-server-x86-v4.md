# CachyOS server kernel 7.2, x86-64-v4 (headless) — build playbook (Debian 13)

Goal: produce `linux-image` / `linux-headers` .debs of the CachyOS **server**
variant (EEVDF, stable release, no rc) tuned for **x86-64-v4**, trimmed for a
**headless AWS EC2** (ENA kept, bloat dropped), buildable on a small EC2 and
installable on any Debian 13 target.

Verified live on AWS EC2 `ip-172-31-31-112` (trixie, 2 vCPU / 7.6 GB / ~28 GB)
on 2026-08-26/27 unless marked otherwise. Collaboration via local tmux pair
(see [tmux.md](tmux.md)).

## Build host facts

- Intel Xeon Platinum 8488C — avx512f/bw/cd/dq/vl → real x86-64-v4
- Stock toolchain in plain trixie is enough (**no sid needed**):
  `clang/llvm/lld 19`, `dwarves` 1.30, `gcc 14.2` fallback

## Why there is no prebuilt v4 .deb upstream

- CachyOS publishes Arch packages only (`*-x86_64_v4.pkg.tar.zst`) from their
  docker-makepkg farm (repo <https://github.com/CachyOS/linux-cachyos>,
  incl. `script-v3-v4.sh`). `_processor_opt:=GENERIC_V*` is the PKGBUILD lever.
  No Debian apt repo exists.

## Steps

### 0. zram (small-RAM EC2 helpers) — verified active

```bash
sudo apt-get install -y zram-tools
printf "ALGO=zstd\nPERCENT=50\n" | sudo tee /etc/default/zramswap
sudo systemctl restart zramswap && cat /proc/swaps   # /dev/zram0 ~3.9G prio 100
```

### 1. Build dependencies

```bash
sudo apt-get install -y build-essential bc bison flex libssl-dev libelf-dev \
  dwarves cpio kmod rsync git clang lld llvm libncurses-dev zstd fakeroot \
  debhelper libdw-dev ethtool iproute2
```

### 2. Recipe + source (CachyOS 7.2.0 stable)

```bash
mkdir -p ~/kbuild && cd ~/kbuild
git clone --depth 1 https://github.com/CachyOS/linux-cachyos.git
# _cpusched defaults to eevdf (server = EEVDF), _major=7.2 _minor=0 _tagrel=1
curl -fSLO https://github.com/CachyOS/linux/releases/download/cachyos-7.2.0-1/cachyos-7.2.0-1.tar.gz  # 254 MB
tar xf cachyos-7.2.0-1.tar.gz
cp linux-cachyos/linux-cachyos-server/config cachyos-7.2.0-1/.config
```

### 3a. Base tune: v4 + ThinLTO + name

```bash
cd cachyos-7.2.0-1
scripts/config --set-val X86_64_VERSION 4 \
               -d LTO_NONE -e LTO_CLANG_THIN \
               --set-str LOCALVERSION "-cachyos-server-v4"
make LLVM=1 olddefconfig
```

### 3b. Headless trim — MUST keep ENA / BBR / FQ

On AWS the only NIC is **ENA** (`CONFIG_NET_VENDOR_AMAZON=y`,
`CONFIG_ENA_ETHERNET=m`). Removing it bricks networking. Congestion control
is `BBR3` (BBRv3) + `FQ`; they stay.

```bash
cp .config .config.pre-headless
scripts/config -d DRM -d AGP -d FB -d SOUND -d SND -d SND_SOC
scripts/config -d MEDIA_SUPPORT -d MEDIA_CAMERA_SUPPORT \
  -d MEDIA_ANALOG_TV_SUPPORT -d MEDIA_DIGITAL_TV_SUPPORT \
  -d MEDIA_RADIO_SUPPORT
scripts/config -d WLAN -d WIRELESS -d CFG80211 -d MAC80211 -d BT -d NFC
scripts/config -d IIO -d THUNDERBOLT -d USB4 \
  -d INPUT_JOYSTICK -d INPUT_TOUCHSCREEN \
  -d DEBUG_INFO_BTF -d DEBUG_INFO_BTF_MODULES
scripts/config -e DEFAULT_BBR3 -d DEFAULT_CUBIC
scripts/config --set-val X86_64_VERSION 4 -d LTO_NONE -e LTO_CLANG_THIN \
  -e ENA_ETHERNET -e NET_VENDOR_AMAZON -e NET_SCH_FQ \
  -e TCP_CONG_BBR -e TCP_CONG_BBR3 \
  --set-str LOCALVERSION "-cachyos-server-v4-headless"
make LLVM=1 olddefconfig
```

Verification (`post-prune`): `# CONFIG_DRM is not set`, `LTO_CLANG_THIN=y`,
`X86_64_VERSION=4`, `ENA_ETHERNET=m`, `DEFAULT_BBR3=y`.

Enabled lines: 9748 → 6945 (removed ~2803, ~29%).

### 4. GOTCHA: debhelper compat pin

```bash
sed -i 's/debhelper-compat (= 12)/debhelper-compat (= 13)/' scripts/package/mkdebian
```

### 5. Build (hours on 2 vCPU — keep inside tmux)

```bash
rm -rf debian/ ../linux-image*.deb ../linux-headers*.deb 2>/dev/null
time make LLVM=1 -j2 bindeb-pkg > ../build.log 2>&1
ls -lh ../*.deb
```

### 6. Install on target Debian 13

```bash
sudo dpkg -i ../linux-image-7.2.0-cachyos-server-v4-headless_*.deb \
              ../linux-headers-*.deb
sudo update-grub && sudo reboot
```

### 7. Post-boot proof (verified 2026-08-27 on this same EC2)

```
$ uname -r
7.2.0-cachyos-server-v4-headless
$ cat /proc/sys/net/ipv4/tcp_congestion_control
bbr3
$ lsmod | grep ena
ena  180224  0
$ grep -E "X86_64_VERSION|LTO_CLANG_THIN|DEFAULT_BBR3|ENA_ETHERNET" /boot/config-$(uname -r)
CONFIG_X86_64_VERSION=4
CONFIG_LTO_CLANG_THIN=y
CONFIG_DEFAULT_BBR3=y
CONFIG_ENA_ETHERNET=m
```

Artifacts: `linux-image` 90 MB, `linux-headers` 9.4 MB, `linux-libc-dev` 1.5 MB
(`-dbg` 710 MB not needed headless — BTF disabled).

## 8. Throughput + loss-resilience tuning (ENA + BBR3, 2026-08-27)

Baseline on this host: `enp39s0` (ENA), `mtu 9001`, `RX 1024 / TX 1024` (max),
`Combined:1/1` (fixed by 2 vCPU), `TSO off [fixed]`, `GRO/GSO on`,
qdisc `mq` root + per-queue `fq_codel`; sysctl `rmem_max 4M`, `tcp_rmem
4K 131K 32M`, `tcp_wmem 4K 16K 4M`, `default_qdisc fq_codel`,
`tcp_notsent_lowat 4294967295` (unlimited — wrong for BBR3).

Applied live and persisted:

### 8a. Sysctl — `/etc/sysctl.d/99-cachyos-headless.conf`

```
net.core.default_qdisc = fq
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 81920
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.ipv4.tcp_congestion_control = bbr3
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fastopen_blackhole_timeout_sec = 0
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_orphan_retries = 0
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_mtu_probe_floor = 48
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_early_retrans = 3
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_tw_reuse = 2
net.ipv4.tcp_abort_on_overflow = 0
```

Apply: `sudo sysctl --system` (already applied live, verified:
`rmem_max 16M`, `tcp_rmem 4K 1M 16M`, `bbr3`, `notsent_lowat 16384`, `fq`).

Rationale: open buffer headroom for BBR3 pacing/bursts, keep `tcp_mem`
scaled to 7.6G RAM, tighten `notsent_lowat` so BBR3 paces early, enable
ECN/TFO/MTU probing and fast loss recovery.

### 8b. qdisc — ENA `mq` → per-queue `fq` (BBR3 pairing)

Live: `tc qdisc replace dev enp39s0 root mq` + per-queue `fq` (already
active — `qdisc fq 8002/8003 parent 8001:1/2` verified).

Persist (manual one-time, paste in VPS shell — agent blocked by hook):

```bash
sudo tee /usr/local/sbin/ena-qdisc.sh <<'EOS' >/dev/null
#!/bin/sh
IF=enp39s0
/sbin/tc qdisc replace dev $IF root mq 2>/dev/null
for i in $(seq 1 $(nproc)); do /sbin/tc qdisc replace dev $IF parent 8001:$i fq 2>/dev/null; done
EOS
sudo chmod 755 /usr/local/sbin/ena-qdisc.sh
sudo tee /etc/systemd/system/ena-qdisc.service <<'EOS' >/dev/null
[Unit]
Description=ENA fq qdisc for BBR3
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ena-qdisc.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOS
sudo systemctl daemon-reload && sudo systemctl enable --now ena-qdisc.service
```

Why `fq` not `fq_codel` here: `fq` is the BBR authors' recommended pairing
(pacing + per-flow queuing without extra CoDel drops that fight BBR's model).

### 8c. ENA rings/channels

`RX 1024 / TX 1024` already at hardware max; `Combined:1` is fixed by the
2 vCPU instance type (ENA exposes 1 queue per vCPU). No further ring tuning.
TSO is `off [fixed]` on ENA — expected (virtualized offload).

## Gotchas log (live, all hit)

1. Starting `make` into an inner tmux before its prompt is ready silently swallows the command — wait for the prompt.
2. While `make` is foreground, don't type monitoring commands into the same pane — split off.
3. Workstation sleep can sever the outer `ssh` mid-build — both tmux layers keep the build alive.
4. `scripts/package/mkdebian` pins `debhelper-compat (= 12)` while trixie ships 13 — `sed` it to 13 or bindeb-pkg aborts.
5. `CONFIG_DEBUG_INFO_BTF=y` + `LTO_CLANG_THIN` fails at the final `BTF .tmp_vmlinux1` link on trixie clang-19 / pahole 1.30 — `scripts/config -d DEBUG_INFO_BTF -d DEBUG_INFO_BTF_MODULES` for headless.
6. `DEFAULT_TCP_CONG` is derived from the `DEFAULT_BBR3` bool, not a free `bbr` string — use `scripts/config -e DEFAULT_BBR3 -d DEFAULT_CUBIC`.

## Timings (this run — headless, 2 vCPU / 7.6 GB + 3.9 GB zram, Xen/Platinum 8488C)

- Download + extract (254 MB): <60 s on EC2
- Unpruned (full) build: killed at 108 min while still in `drivers/gpu`
- Headless rebuild (pruned ~29%, `-j2`, ThinLTO 19, 7.2.0): ~3.5 h wall-clock,
  produced 90 MB image + 9.4 MB headers (710 MB dbg not needed), 14 MB vmlinuz
