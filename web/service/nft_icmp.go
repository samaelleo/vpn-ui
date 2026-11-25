package service

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/goccy/go-json"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// vpnIcmpDirectMark tags ICMP packets explicitly permitted to leave via a
	// bare `freedom` (direct) outbound so nat_post only masquerades approved WAN
	// ICMP. Its value sits outside byte 0 so it never overlaps TPROXY fwmark 0x1
	// or Xray SO_MARK 0xff.
	vpnIcmpDirectMark uint32 = 0x100

	// ICMP fwmark ip rules live in priority band [5000, 10000), below
	// vpnoutvia's exclude/steer bands [10000, 30000) and above local (0).
	vpnIcmpRuleBase  = 5000
	vpnIcmpRuleSpan  = 5000
	vpnIcmpRuleProto = 148
)

var vpnIcmpGeoIPPrivate = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// icmpRuleKind classifies the prerouting/routing verdict for one ICMP rule.
type icmpRuleKind int

const (
	icmpActionDrop icmpRuleKind = iota
	icmpActionMark
	icmpActionDirect
)

type icmpTarget struct {
	kind   icmpRuleKind
	table  int
	iface  string
	mark   uint32
	snatIP string
}

type icmpNatRule struct {
	iface  string
	snatIP string
}

type icmpRuleSpec struct {
	saddrs []netip.Prefix
	daddrs []netip.Prefix
	target icmpTarget
}

type icmpPlan struct {
	rules     []icmpRuleSpec
	tables    []int
	nats      []icmpNatRule
	directNat bool
}

func (p icmpPlan) needNat() bool {
	return p.directNat || len(p.nats) > 0
}

// vpnIcmpMarkForTable encodes a routing table ID into a deterministic 32-bit
// fwmark whose low byte is always 0 (never colliding with 0x1 or 0xff).
func vpnIcmpMarkForTable(table int) uint32 {
	if table < vpnOutRouteTableBase || table > 0xffffff {
		return 0
	}
	return uint32(table) << 8
}

// isVpnIcmpNetlinkRule is the strict ownership predicate guarding ip-rule
// deletion and de-duplication, mirroring isVpnPolicyNetlinkRule.
func isVpnIcmpNetlinkRule(r netlink.Rule) bool {
	return r.Protocol == vpnIcmpRuleProto &&
		r.Priority >= vpnIcmpRuleBase && r.Priority < vpnIcmpRuleBase+vpnIcmpRuleSpan &&
		r.Table >= vpnOutRouteTableBase && r.Table <= 0xffffff &&
		r.Mark == vpnIcmpMarkForTable(r.Table) &&
		(r.Mask == nil || *r.Mask == 0xffffffff) &&
		r.Src == nil && r.Dst == nil &&
		r.IifName == "" && r.OifName == "" &&
		!r.Invert &&
		r.SuppressPrefixlen < 0 && r.SuppressIfgroup < 0 &&
		r.Goto < 0 && r.Flow < 0 &&
		r.Tos == 0 && r.TunID == 0 && r.IPProto == 0 &&
		r.Dport == nil && r.Sport == nil && r.UIDRange == nil
}

// Hooks replaced in unit tests so planning, rule reconciliation, and tunnel
// sync run cleanly without a live kernel or SQLite handle.
var (
	icmpListNetlinkRules = func() ([]netlink.Rule, error) {
		return netlink.RuleList(netlink.FAMILY_V4)
	}
	icmpAddNetlinkRule = func(prio int, mark uint32, table int) error {
		rule := netlink.NewRule()
		rule.Priority = prio
		rule.Family = netlink.FAMILY_V4
		rule.Table = table
		rule.Mark = mark
		rule.Protocol = vpnIcmpRuleProto
		return netlink.RuleAdd(rule)
	}
	icmpDelNetlinkRule = func(r netlink.Rule) error {
		return netlink.RuleDel(&r)
	}
	icmpEnsurePinnedTable = ensurePinnedFreedomTable
	syncVpnIcmpNft        = defaultSyncVpnIcmpNft
)

func defaultSyncVpnIcmpNft() {
	if database.GetDB() == nil {
		return
	}
	if err := (&NftService{}).ApplyNftRules(); err != nil {
		logger.Warning("icmp routing: failed to refresh nftables rules:", err)
	}
}

// ensurePinnedFreedomTable ensures an operator-pinned freedom interface (not
// managed by VpnOutboundService) has an egress routing table at 30000+ifindex.
func ensurePinnedFreedomTable(iface string, table int) bool {
	if strings.TrimSpace(iface) == "" || table < vpnOutRouteTableBase {
		return false
	}
	existing, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err == nil {
		for _, r := range existing {
			if r.Type != unix.RTN_BLACKHOLE && (r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero)) {
				return true
			}
		}
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return false
	}
	idx := link.Attrs().Index

	// Check main table for an existing default route via this device (e.g. a
	// multi-homed Ethernet NIC with a gateway).
	mainRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_MAIN, LinkIndex: idx}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err == nil {
		for _, mr := range mainRoutes {
			if mr.Dst != nil && !mr.Dst.IP.Equal(net.IPv4zero) {
				continue
			}
			bh := &netlink.Route{
				Table:    table,
				Dst:      &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
				Type:     unix.RTN_BLACKHOLE,
				Priority: vpnOutBlackholeMetric,
			}
			def := &netlink.Route{
				LinkIndex: idx,
				Table:     table,
				Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
				Gw:        mr.Gw,
				Src:       mr.Src,
				Scope:     mr.Scope,
			}
			if vpnOutReplaceRoute(bh) == nil && vpnOutReplaceRoute(def) == nil {
				return true
			}
			return false
		}
	}

	// Point-to-point / NOARP devices (e.g. manually created wg0 or tun0) route
	// on-link without a gateway.
	flags := link.Attrs().Flags
	rawFlags := link.Attrs().RawFlags
	if flags&net.FlagPointToPoint != 0 || rawFlags&unix.IFF_NOARP != 0 {
		for _, r := range vpnOutEgressRoutes(table, idx) {
			if vpnOutReplaceRoute(r) != nil {
				return false
			}
		}
		return true
	}
	return false
}

// ensureVpnIcmpRules installs any missing `fwmark -> table` rules before nft
// starts marking packets so marked traffic never leaks through `main`.
func ensureVpnIcmpRules(wantTables []int) {
	if len(wantTables) == 0 {
		return
	}
	rules, err := icmpListNetlinkRules()
	if err != nil {
		logger.Warning("icmp routing: could not list ip rules:", err)
		return
	}
	have := make(map[int]bool, len(wantTables))
	usedPrio := make(map[int]bool, len(rules))
	for _, r := range rules {
		usedPrio[r.Priority] = true
		if isVpnIcmpNetlinkRule(r) {
			have[r.Table] = true
		}
	}
	nextPrio := vpnIcmpRuleBase
	for _, table := range sortedUniqueInts(wantTables) {
		if have[table] {
			continue
		}
		mark := vpnIcmpMarkForTable(table)
		if mark == 0 {
			continue
		}
		for nextPrio < vpnIcmpRuleBase+vpnIcmpRuleSpan && usedPrio[nextPrio] {
			nextPrio++
		}
		if nextPrio >= vpnIcmpRuleBase+vpnIcmpRuleSpan {
			logger.Warning("icmp routing: exhausted ip rule priority band for table", table)
			return
		}
		if err := icmpAddNetlinkRule(nextPrio, mark, table); err != nil {
			logger.Warningf("icmp routing: failed adding rule pref %d fwmark 0x%x lookup %d: %v", nextPrio, mark, table, err)
			continue
		}
		usedPrio[nextPrio] = true
		nextPrio++
	}
}

// reconcileVpnIcmpRules adds missing rules, keeps the lowest-priority copy of
// each active rule, and deletes stale or duplicate ICMP rules.
func reconcileVpnIcmpRules(wantTables []int) {
	ensureVpnIcmpRules(wantTables)
	rules, err := icmpListNetlinkRules()
	if err != nil {
		return
	}
	want := make(map[int]bool, len(wantTables))
	for _, t := range wantTables {
		if t >= vpnOutRouteTableBase {
			want[t] = true
		}
	}
	bestIdxByTable := make(map[int]int)
	var mineIdx []int
	for i, r := range rules {
		if !isVpnIcmpNetlinkRule(r) {
			continue
		}
		mineIdx = append(mineIdx, i)
		if !want[r.Table] {
			continue
		}
		prevIdx, ok := bestIdxByTable[r.Table]
		if !ok || r.Priority < rules[prevIdx].Priority {
			bestIdxByTable[r.Table] = i
		}
	}
	for _, idx := range mineIdx {
		r := rules[idx]
		if bestIdx, keep := bestIdxByTable[r.Table]; keep && bestIdx == idx {
			continue
		}
		if err := icmpDelNetlinkRule(r); err != nil {
			logger.Warningf("icmp routing: failed deleting stale rule pref %d table %d: %v", r.Priority, r.Table, err)
		}
	}
}

// clearVpnIcmpRules removes all panel-owned ICMP policy rules (used on zero VPN
// inbounds and host uninstall).
func clearVpnIcmpRules() {
	reconcileVpnIcmpRules(nil)
}

// vpnOutSweepIcmpRules deletes any panel-owned ICMP policy rule steering into
// `table` before the table's routes are flushed on tunnel teardown.
func vpnOutSweepIcmpRules(table int) {
	if table < vpnOutRouteTableBase {
		return
	}
	rules, err := icmpListNetlinkRules()
	if err != nil {
		return
	}
	for _, r := range rules {
		if isVpnIcmpNetlinkRule(r) && r.Table == table {
			if err := icmpDelNetlinkRule(r); err != nil {
				logger.Warningf("icmp routing: failed sweeping rule pref %d table %d: %v", r.Priority, table, err)
			}
		}
	}
}

// buildLiveIcmpPlan derives the ICMP routing & NAT plan from live panel config.
// When Xray config cannot be built, it degrades fail-closed (drops client ICMP).
func buildLiveIcmpPlan(nets []vpnNet, cfg *xray.Config) icmpPlan {
	if len(nets) == 0 {
		return icmpPlan{}
	}
	tunnels := (&VpnOutboundService{}).List()
	vpnMap := BuildVpnEmailToIPMap()
	var validIPs []string
	for _, ips := range vpnMap {
		validIPs = append(validIPs, ips...)
	}

	if cfg == nil {
		var err error
		cfg, err = (&XrayService{}).GetXrayConfig()
		if err != nil {
			logger.Warning("icmp routing: could not read Xray config, dropping non-local ICMP fail-closed:", err)
			return icmpPlan{}
		}
	}
	return buildVpnIcmpPlan(nets, cfg.RouterConfig, cfg.OutboundConfigs, tunnels, validIPs)
}

// buildVpnIcmpPlan is the pure planner turning active VPN inbound subnets,
// Xray routing rules, Xray outbounds, and VPN Outbound tunnels into ordered
// nftables ICMP verdicts and kernel table/NAT dependencies.
func buildVpnIcmpPlan(nets []vpnNet, routerJSON, outboundsJSON []byte, tunnels []VpnOutboundConfig, validClientIPs []string) icmpPlan {
	var plan icmpPlan
	if len(nets) == 0 {
		return plan
	}

	allSubnets := allVpnNetPrefixes(nets)
	if len(allSubnets) == 0 {
		return plan
	}

	var obsList []map[string]any
	if len(outboundsJSON) > 0 {
		if err := json.Unmarshal(outboundsJSON, &obsList); err != nil {
			logger.Warning("icmp routing: invalid Xray outbounds JSON, failing closed:", err)
			return plan
		}
	}
	obsByTag := make(map[string]map[string]any, len(obsList))
	defaultTag := ""
	hasBlackhole := false
	for i, ob := range obsList {
		tag, _ := ob["tag"].(string)
		if i == 0 && tag != "" {
			defaultTag = tag
		}
		if p, _ := ob["protocol"].(string); p == "blackhole" && tag != "" {
			hasBlackhole = true
		}
		if tag != "" {
			obsByTag[tag] = ob
		}
	}

	tunnelsByTag := make(map[string]VpnOutboundConfig, len(tunnels))
	for _, t := range tunnels {
		if t.Tag != "" {
			tunnelsByTag[t.Tag] = t
		}
	}

	var routing struct {
		Rules     []map[string]any `json:"rules"`
		Balancers []struct {
			Tag      string   `json:"tag"`
			Selector []string `json:"selector"`
		} `json:"balancers"`
	}
	if len(routerJSON) > 0 {
		if err := json.Unmarshal(routerJSON, &routing); err != nil {
			logger.Warning("icmp routing: invalid Xray routing JSON, failing closed:", err)
			return plan
		}
	}
	balancersByTag := make(map[string][]string, len(routing.Balancers))
	for _, b := range routing.Balancers {
		if b.Tag != "" {
			balancersByTag[b.Tag] = b.Selector
		}
	}

	tableSeen := make(map[int]bool)
	natByIface := make(map[string]icmpNatRule)
	recordTarget := func(t icmpTarget) {
		switch t.kind {
		case icmpActionDirect:
			plan.directNat = true
		case icmpActionMark:
			if t.table >= vpnOutRouteTableBase && !tableSeen[t.table] {
				tableSeen[t.table] = true
				plan.tables = append(plan.tables, t.table)
			}
			if t.iface != "" {
				prev, exists := natByIface[t.iface]
				if !exists {
					natByIface[t.iface] = icmpNatRule{iface: t.iface, snatIP: t.snatIP}
				} else if prev.snatIP != t.snatIP {
					// Mixed sendThrough and masquerade on the same device: fall back to masquerade.
					natByIface[t.iface] = icmpNatRule{iface: t.iface}
				}
			}
		}
	}

	for _, rule := range routing.Rules {
		if rule == nil {
			continue
		}
		if enabled, ok := rule["enabled"].(bool); ok && !enabled {
			continue
		}
		if !isIcmpApplicableRule(rule) {
			continue
		}

		saddrs, ok := resolveRuleSources(rule, nets, allSubnets)
		if !ok || len(saddrs) == 0 {
			continue
		}

		daddrs, ok := resolveRuleDestinations(rule)
		if !ok {
			continue
		}

		target, hasTarget := resolveRuleTarget(rule, obsList, obsByTag, tunnelsByTag, balancersByTag)
		if !hasTarget {
			continue
		}

		recordTarget(target)
		plan.rules = append(plan.rules, icmpRuleSpec{
			saddrs: saddrs,
			daddrs: daddrs,
			target: target,
		})
	}

	// Match Xray's implicit default outbound for active VPN clients when no
	// backstop was appended (for example when the template deleted its blackhole
	// outbound so translateVpnRoutingRules skipped adding validIPs -> defaultTag).
	if !hasBlackhole && defaultTag != "" {
		validPrefixes := parseXrayIPList(validClientIPs)
		if len(validPrefixes) == 0 {
			validPrefixes = allSubnets
		} else {
			validPrefixes = intersectPrefixLists(allSubnets, validPrefixes)
		}
		if len(validPrefixes) > 0 {
			target := resolveVpnIcmpTarget(defaultTag, obsByTag, tunnelsByTag)
			recordTarget(target)
			plan.rules = append(plan.rules, icmpRuleSpec{
				saddrs: validPrefixes,
				target: target,
			})
		}
	}

	sort.Ints(plan.tables)
	ifaces := make([]string, 0, len(natByIface))
	for iface := range natByIface {
		ifaces = append(ifaces, iface)
	}
	sort.Strings(ifaces)
	for _, iface := range ifaces {
		plan.nats = append(plan.nats, natByIface[iface])
	}
	return plan
}

// isIcmpApplicableRule filters out Xray rules that depend on L7/L4-port/user
// metadata that raw IPv4 ICMP packets do not carry.
func isIcmpApplicableRule(rule map[string]any) bool {
	if hasNonEmptySlice(rule["domain"]) ||
		hasNonEmptySlice(rule["protocol"]) ||
		hasNonEmptySlice(rule["user"]) ||
		hasNonEmptySlice(rule["vlessRoute"]) ||
		hasNonEmptyString(rule["vlessRoute"]) ||
		hasNonEmptyMap(rule["attrs"]) ||
		hasNonEmptyPort(rule["port"]) ||
		hasNonEmptyPort(rule["sourcePort"]) {
		return false
	}
	if netStr, ok := rule["network"].(string); ok && strings.TrimSpace(netStr) != "" {
		return false
	}
	return true
}

func resolveRuleSources(rule map[string]any, nets []vpnNet, allSubnets []netip.Prefix) ([]netip.Prefix, bool) {
	candidate := allSubnets
	if rawTags := stringSliceField(rule["inboundTag"]); len(rawTags) > 0 {
		tagSet := make(map[string]bool, len(rawTags))
		for _, t := range rawTags {
			tagSet[t] = true
		}
		var matched []netip.Prefix
		for _, n := range nets {
			if n.tag != "" && tagSet[n.tag] {
				matched = append(matched, parseXrayIPList(n.subnets)...)
			}
		}
		if len(matched) == 0 {
			return nil, false
		}
		candidate = dedupPrefixes(matched)
	}

	if rawSrc := stringSliceField(rule["source"]); len(rawSrc) > 0 {
		srcPrefixes := parseXrayIPList(rawSrc)
		if len(srcPrefixes) == 0 {
			// Specified source filter matched nothing in IPv4; do not widen to all VPN subnets.
			return nil, false
		}
		return intersectPrefixLists(candidate, srcPrefixes), true
	}
	return candidate, true
}

func resolveRuleDestinations(rule map[string]any) ([]netip.Prefix, bool) {
	rawIP := stringSliceField(rule["ip"])
	if len(rawIP) == 0 {
		return nil, true
	}
	dests := parseXrayIPList(rawIP)
	if len(dests) == 0 {
		// Unresolvable geoip:/ext: or IPv6-only IP selector must not match every destination.
		return nil, false
	}
	return dests, true
}

func resolveRuleTarget(
	rule map[string]any,
	obsList []map[string]any,
	obsByTag map[string]map[string]any,
	tunnelsByTag map[string]VpnOutboundConfig,
	balancersByTag map[string][]string,
) (icmpTarget, bool) {
	if obTag, _ := rule["outboundTag"].(string); strings.TrimSpace(obTag) != "" {
		return resolveVpnIcmpTarget(strings.TrimSpace(obTag), obsByTag, tunnelsByTag), true
	}
	if balTag, _ := rule["balancerTag"].(string); strings.TrimSpace(balTag) != "" {
		selectors := balancersByTag[strings.TrimSpace(balTag)]
		if len(selectors) == 0 {
			return icmpTarget{kind: icmpActionDrop}, true
		}
		var chosen *icmpTarget
		for _, ob := range obsList {
			tag, _ := ob["tag"].(string)
			if !matchesAnyPrefix(tag, selectors) {
				continue
			}
			cand := resolveVpnIcmpTarget(tag, obsByTag, tunnelsByTag)
			if cand.kind == icmpActionDrop {
				// Fail closed if any balancer candidate is non-L3 or down.
				return icmpTarget{kind: icmpActionDrop}, true
			}
			if chosen == nil {
				c := cand
				chosen = &c
			}
		}
		if chosen != nil {
			return *chosen, true
		}
		return icmpTarget{kind: icmpActionDrop}, true
	}
	return icmpTarget{}, false
}

func resolveVpnIcmpTarget(tag string, obsByTag map[string]map[string]any, tunnelsByTag map[string]VpnOutboundConfig) icmpTarget {
	if t, isTunnel := tunnelsByTag[tag]; isTunnel {
		iface := strings.TrimSpace(t.Iface)
		if !t.Enable || iface == "" || vpnOutIfaceGone(iface) {
			return icmpTarget{kind: icmpActionDrop}
		}
		table := vpnOutTableOf(iface)
		mark := vpnIcmpMarkForTable(table)
		if mark == 0 {
			return icmpTarget{kind: icmpActionDrop}
		}
		return icmpTarget{
			kind:  icmpActionMark,
			table: table,
			iface: iface,
			mark:  mark,
		}
	}

	ob := obsByTag[tag]
	if ob == nil {
		return icmpTarget{kind: icmpActionDrop}
	}
	proto, _ := ob["protocol"].(string)
	if !strings.EqualFold(strings.TrimSpace(proto), "freedom") {
		return icmpTarget{kind: icmpActionDrop}
	}
	if settings, _ := ob["settings"].(map[string]any); settings != nil {
		if redir, _ := settings["redirect"].(string); strings.TrimSpace(redir) != "" {
			return icmpTarget{kind: icmpActionDrop}
		}
	}

	if pin := vpnOutOutboundPin(ob); pin != "" {
		if vpnOutIfaceGone(pin) {
			return icmpTarget{kind: icmpActionDrop}
		}
		table := vpnOutTableOf(pin)
		mark := vpnIcmpMarkForTable(table)
		if mark == 0 || !icmpEnsurePinnedTable(pin, table) {
			return icmpTarget{kind: icmpActionDrop}
		}
		return icmpTarget{
			kind:  icmpActionMark,
			table: table,
			iface: pin,
			mark:  mark,
		}
	}

	if through, _ := ob["sendThrough"].(string); strings.TrimSpace(through) != "" {
		stIP, err := netip.ParseAddr(strings.TrimSpace(through))
		if err != nil {
			// Hostname or malformed sendThrough: fail closed.
			return icmpTarget{kind: icmpActionDrop}
		}
		if !stIP.IsUnspecified() {
			if !stIP.Is4() {
				return icmpTarget{kind: icmpActionDrop}
			}
			dev := vpnOutDevWithAddr(stIP.String())
			if dev == "" || vpnOutIfaceGone(dev) {
				return icmpTarget{kind: icmpActionDrop}
			}
			table := vpnOutTableOf(dev)
			mark := vpnIcmpMarkForTable(table)
			if mark == 0 || !icmpEnsurePinnedTable(dev, table) {
				return icmpTarget{kind: icmpActionDrop}
			}
			return icmpTarget{
				kind:   icmpActionMark,
				table:  table,
				iface:  dev,
				mark:   mark,
				snatIP: stIP.String(),
			}
		}
	}

	return icmpTarget{
		kind: icmpActionDirect,
		mark: vpnIcmpDirectMark,
	}
}

func writeIcmpPreroutingRules(b *strings.Builder, plan icmpPlan) {
	b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip daddr %s ip protocol icmp fib daddr type local accept\n", vpnAddrSpace, vpnAddrSpace))
	b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip protocol icmp ct direction reply ct status snat accept\n", vpnAddrSpace))

	emittedCatchAllDrop := false
	for _, r := range plan.rules {
		verdict := "counter drop"
		if r.target.kind != icmpActionDrop {
			verdict = fmt.Sprintf("meta mark set 0x%x counter accept", r.target.mark)
		}
		for _, src := range r.saddrs {
			srcExpr := formatNftPrefix(src)
			if len(r.daddrs) == 0 {
				b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip protocol icmp %s\n", srcExpr, verdict))
				if r.target.kind == icmpActionDrop && src.String() == vpnAddrSpace {
					emittedCatchAllDrop = true
				}
				continue
			}
			for _, dst := range r.daddrs {
				b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip daddr %s ip protocol icmp %s\n", srcExpr, formatNftPrefix(dst), verdict))
			}
		}
	}

	if !emittedCatchAllDrop {
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip protocol icmp counter drop\n", vpnAddrSpace))
	}
}

func writeIcmpNatPostRules(b *strings.Builder, plan icmpPlan) {
	if !plan.needNat() {
		return
	}
	b.WriteString("add chain ip vpn nat_post { type nat hook postrouting priority srcnat; policy accept; }\n")
	b.WriteString("flush chain ip vpn nat_post\n")
	b.WriteString(fmt.Sprintf("add rule ip vpn nat_post ip saddr %s ip daddr %s ip protocol icmp return\n", vpnAddrSpace, vpnAddrSpace))
	for _, nat := range plan.nats {
		if nat.snatIP != "" {
			b.WriteString(fmt.Sprintf("add rule ip vpn nat_post oifname %q ip saddr %s ip protocol icmp counter snat to %s\n", nat.iface, vpnAddrSpace, nat.snatIP))
		} else {
			b.WriteString(fmt.Sprintf("add rule ip vpn nat_post oifname %q ip saddr %s ip protocol icmp counter masquerade\n", nat.iface, vpnAddrSpace))
		}
	}
	if plan.directNat {
		b.WriteString(fmt.Sprintf("add rule ip vpn nat_post meta mark 0x%x ip saddr %s ip protocol icmp counter masquerade\n", vpnIcmpDirectMark, vpnAddrSpace))
	}
}

func formatNftPrefix(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func allVpnNetPrefixes(nets []vpnNet) []netip.Prefix {
	var all []netip.Prefix
	for _, n := range nets {
		all = append(all, parseXrayIPList(n.subnets)...)
	}
	return dedupPrefixes(all)
}

func parseXrayIPList(raw []string) []netip.Prefix {
	var out []netip.Prefix
	for _, entry := range raw {
		s := strings.TrimSpace(entry)
		if s == "" {
			continue
		}
		if strings.EqualFold(s, "geoip:private") {
			for _, cidr := range vpnIcmpGeoIPPrivate {
				if p, err := netip.ParsePrefix(cidr); err == nil {
					out = append(out, p.Masked())
				}
			}
			continue
		}
		if p, ok := parseIPv4Prefix(s); ok {
			out = append(out, p)
		}
	}
	return dedupPrefixes(out)
}

func parseIPv4Prefix(s string) (netip.Prefix, bool) {
	if addr, err := netip.ParseAddr(s); err == nil && addr.Is4() {
		return netip.PrefixFrom(addr, 32), true
	}
	if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
		return p.Masked(), true
	}
	return netip.Prefix{}, false
}

func dedupPrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	sorted := make([]netip.Prefix, len(in))
	for i, p := range in {
		sorted[i] = p.Masked()
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Bits() != sorted[j].Bits() {
			return sorted[i].Bits() < sorted[j].Bits()
		}
		return sorted[i].Addr().Compare(sorted[j].Addr()) < 0
	})
	var kept []netip.Prefix
	for _, p := range sorted {
		covered := false
		for _, k := range kept {
			if k.Overlaps(p) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	return kept
}

func intersectPrefixLists(a, b []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, pa := range a {
		for _, pb := range b {
			if !pa.Overlaps(pb) {
				continue
			}
			if pa.Bits() >= pb.Bits() {
				out = append(out, pa)
			} else {
				out = append(out, pb)
			}
		}
	}
	return dedupPrefixes(out)
}

func stringSliceField(v any) []string {
	switch xs := v.(type) {
	case []string:
		out := make([]string, 0, len(xs))
		for _, s := range xs {
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(xs))
		for _, item := range xs {
			if s, ok := item.(string); ok {
				if t := strings.TrimSpace(s); t != "" {
					out = append(out, t)
				}
			}
		}
		return out
	}
	return nil
}

func hasNonEmptySlice(v any) bool {
	return len(stringSliceField(v)) > 0
}

func hasNonEmptyString(v any) bool {
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) != ""
}

func hasNonEmptyMap(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(m) > 0
}

func hasNonEmptyPort(v any) bool {
	switch p := v.(type) {
	case string:
		return strings.TrimSpace(p) != ""
	case float64:
		return p != 0
	case int:
		return p != 0
	}
	return false
}

func matchesAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func sortedUniqueInts(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	cp := append([]int(nil), in...)
	sort.Ints(cp)
	out := cp[:0]
	for i, v := range cp {
		if i == 0 || v != cp[i-1] {
			out = append(out, v)
		}
	}
	return out
}
