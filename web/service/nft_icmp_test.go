package service

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestVpnIcmpMarkForTableAvoidsLowByte(t *testing.T) {
	if vpnIcmpDirectMark&0xff != 0 || vpnIcmpDirectMark == vpnPolicyMark || vpnIcmpDirectMark == 0xff {
		t.Fatalf("invalid direct mark 0x%x", vpnIcmpDirectMark)
	}
	for table := vpnOutRouteTableBase; table <= vpnOutRouteTableBase+512; table++ {
		mark := vpnIcmpMarkForTable(table)
		if mark == 0 || mark&0xff != 0 || mark == vpnPolicyMark || mark == 0xff {
			t.Fatalf("table %d produced unsafe mark 0x%x", table, mark)
		}
	}
	if vpnIcmpMarkForTable(0) != 0 || vpnIcmpMarkForTable(100) != 0 {
		t.Fatal("expected 0 mark for non-tunnel tables")
	}
}

func TestBuildVpnIcmpPlan(t *testing.T) {
	prevGone := vpnOutIfaceGone
	prevTableOf := vpnOutTableOf
	prevDevAddr := vpnOutDevWithAddr
	prevPinTable := icmpEnsurePinnedTable
	t.Cleanup(func() {
		vpnOutIfaceGone = prevGone
		vpnOutTableOf = prevTableOf
		vpnOutDevWithAddr = prevDevAddr
		icmpEnsurePinnedTable = prevPinTable
	})

	vpnOutIfaceGone = func(iface string) bool {
		return iface == "gone0"
	}
	vpnOutTableOf = func(iface string) int {
		switch iface {
		case "wgo0":
			return 30005
		case "ovpnc0":
			return 30006
		case "eth1":
			return 30007
		case "wg-custom":
			return 30008
		default:
			return 0
		}
	}
	vpnOutDevWithAddr = func(addr string) string {
		if addr == "198.51.100.2" {
			return "eth1"
		}
		return ""
	}
	icmpEnsurePinnedTable = func(iface string, table int) bool {
		return iface == "eth1" || iface == "wg-custom"
	}

	nets := []vpnNet{
		{tag: "wgc-1", subnets: []string{"10.7.0.0/24"}},
		{tag: "l2tp-1", subnets: []string{"10.0.2.0/24"}},
	}

	tunnels := []VpnOutboundConfig{
		{Tag: "wg-out", Kind: VpnOutWireguard, Enable: true, Iface: "wgo0"},
		{Tag: "ovpn-out", Kind: VpnOutOpenVPN, Enable: true, Iface: "ovpnc0"},
		{Tag: "down-out", Kind: VpnOutWireguard, Enable: true, Iface: "gone0"},
		{Tag: "off-out", Kind: VpnOutL2TP, Enable: false, Iface: "ppp10"},
	}

	outboundsJSON := []byte(`[
		{"tag": "direct", "protocol": "freedom", "settings": {}},
		{"tag": "blocked", "protocol": "blackhole", "settings": {}},
		{"tag": "vless-1", "protocol": "vless", "settings": {}},
		{"tag": "freedom-pin", "protocol": "freedom", "streamSettings": {"sockopt": {"interface": "wg-custom"}}},
		{"tag": "freedom-src", "protocol": "freedom", "sendThrough": "198.51.100.2"},
		{"tag": "freedom-gone", "protocol": "freedom", "streamSettings": {"sockopt": {"interface": "gone0"}}},
		{"tag": "wg-out", "protocol": "freedom", "streamSettings": {"sockopt": {"interface": "wgo0"}}},
		{"tag": "ovpn-out", "protocol": "freedom", "streamSettings": {"sockopt": {"interface": "ovpnc0"}}},
		{"tag": "down-out", "protocol": "blackhole", "settings": {}},
		{"tag": "off-out", "protocol": "blackhole", "settings": {}}
	]`)

	t.Run("routes L3 outbounds, skips L7 rules, fails closed on proxies and down tunnels", func(t *testing.T) {
		routerJSON := []byte(`{
			"rules": [
				{"type": "field", "domain": ["geosite:ir"], "outboundTag": "direct"},
				{"type": "field", "port": "443", "outboundTag": "vless-1"},
				{"type": "field", "network": "tcp", "outboundTag": "vless-1"},
				{"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
				{"type": "field", "ip": ["geoip:ir"], "outboundTag": "direct"},
				{"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
				{"type": "field", "enabled": false, "inboundTag": ["wgc-1"], "outboundTag": "direct"},
				{"type": "field", "inboundTag": ["wgc-1"], "source": ["10.7.0.8/29", "10.0.2.2"], "outboundTag": "wg-out"},
				{"type": "field", "inboundTag": ["wgc-1"], "outboundTag": "vless-1"},
				{"type": "field", "inboundTag": ["l2tp-1"], "source": ["10.0.2.5"], "outboundTag": "down-out"},
				{"type": "field", "inboundTag": ["l2tp-1"], "source": ["10.0.2.6"], "outboundTag": "freedom-pin"},
				{"type": "field", "inboundTag": ["l2tp-1"], "source": ["10.0.2.7"], "outboundTag": "freedom-src"},
				{"type": "field", "inboundTag": ["l2tp-1"], "source": ["10.0.2.8"], "outboundTag": "freedom-gone"},
				{"type": "field", "source": ["10.0.2.9"], "outboundTag": "direct"},
				{"type": "field", "source": ["10.0.0.0/12"], "outboundTag": "blocked"}
			]
		}`)

		plan := buildVpnIcmpPlan(nets, routerJSON, outboundsJSON, tunnels, nil)
		// Expected matching rules in order:
		// 0: geoip:private -> blocked (Drop)
		// 1: 10.7.0.8/29 (intersected with wgc-1, excluding 10.0.2.2) -> wg-out (Mark 30005)
		// 2: wgc-1 -> vless-1 (Drop)
		// 3: 10.0.2.5 -> down-out (Drop)
		// 4: 10.0.2.6 -> freedom-pin (Mark 30008, wg-custom)
		// 5: 10.0.2.7 -> freedom-src (Mark 30007, eth1, snat 198.51.100.2)
		// 6: 10.0.2.8 -> freedom-gone (Drop)
		// 7: 10.0.2.9 -> direct (Direct, 0x100)
		// 8: 10.0.0.0/12 intersected with active nets -> blocked (Drop)
		if len(plan.rules) != 9 {
			t.Fatalf("got %d rules, want 9: %+v", len(plan.rules), plan.rules)
		}
		if plan.rules[0].target.kind != icmpActionDrop || len(plan.rules[0].daddrs) != len(vpnIcmpGeoIPPrivate) {
			t.Fatalf("unexpected geoip:private rule: %+v", plan.rules[0])
		}
		if len(plan.rules[1].saddrs) != 1 || plan.rules[1].saddrs[0].String() != "10.7.0.8/29" {
			t.Fatalf("source/inboundTag intersection failed: %+v", plan.rules[1].saddrs)
		}
		if plan.rules[1].target.kind != icmpActionMark || plan.rules[1].target.table != 30005 || plan.rules[1].target.mark != vpnIcmpMarkForTable(30005) {
			t.Fatalf("unexpected wg-out target: %+v", plan.rules[1].target)
		}
		if plan.rules[2].target.kind != icmpActionDrop || plan.rules[3].target.kind != icmpActionDrop || plan.rules[6].target.kind != icmpActionDrop {
			t.Fatalf("proxy or down outbound was not failed closed: %+v", plan.rules)
		}
		if plan.rules[4].target.kind != icmpActionMark || plan.rules[4].target.table != 30008 || plan.rules[4].target.snatIP != "" {
			t.Fatalf("unexpected freedom-pin target: %+v", plan.rules[4].target)
		}
		if plan.rules[5].target.kind != icmpActionMark || plan.rules[5].target.table != 30007 || plan.rules[5].target.snatIP != "198.51.100.2" {
			t.Fatalf("unexpected freedom-src target: %+v", plan.rules[5].target)
		}
		if plan.rules[7].target.kind != icmpActionDirect || plan.rules[7].target.mark != vpnIcmpDirectMark {
			t.Fatalf("unexpected direct target: %+v", plan.rules[7].target)
		}
		if !plan.directNat || len(plan.tables) != 3 || len(plan.nats) != 3 {
			t.Fatalf("unexpected plan deps: tables=%v nats=%+v direct=%v", plan.tables, plan.nats, plan.directNat)
		}

		var b strings.Builder
		writeIcmpPreroutingRules(&b, plan)
		writeIcmpNatPostRules(&b, plan)
		nft := b.String()

		for _, want := range []string{
			"ip saddr 10.0.0.0/12 ip daddr 10.0.0.0/12 ip protocol icmp fib daddr type local accept\n",
			"ip saddr 10.0.0.0/12 ip protocol icmp ct direction reply ct status snat accept\n",
			fmt.Sprintf("ip saddr 10.7.0.8/29 ip protocol icmp meta mark set 0x%x counter accept\n", vpnIcmpMarkForTable(30005)),
			"ip saddr 10.7.0.0/24 ip protocol icmp counter drop\n",
			"ip saddr 10.0.2.5 ip protocol icmp counter drop\n",
			"oifname \"wgo0\" ip saddr 10.0.0.0/12 ip protocol icmp counter masquerade\n",
			"oifname \"eth1\" ip saddr 10.0.0.0/12 ip protocol icmp counter snat to 198.51.100.2\n",
			"meta mark 0x100 ip saddr 10.0.0.0/12 ip protocol icmp counter masquerade\n",
			"ip saddr 10.0.0.0/12 ip daddr 10.0.0.0/12 ip protocol icmp return\n",
			"add rule ip vpn prerouting ip saddr 10.0.0.0/12 ip protocol icmp counter drop\n",
		} {
			if !strings.Contains(nft, want) {
				t.Fatalf("missing expected nft rule %q in:\n%s", want, nft)
			}
		}
	})

	t.Run("balancer fails closed if any candidate is non-L3 or down", func(t *testing.T) {
		routerJSON := []byte(`{
			"balancers": [
				{"tag": "bal-l3", "selector": ["wg-out", "ovpn-out"]},
				{"tag": "bal-mixed", "selector": ["wg-out", "vless-1"]}
			],
			"rules": [
				{"type": "field", "inboundTag": ["wgc-1"], "balancerTag": "bal-l3"},
				{"type": "field", "inboundTag": ["l2tp-1"], "balancerTag": "bal-mixed"}
			]
		}`)
		plan := buildVpnIcmpPlan(nets, routerJSON, outboundsJSON, tunnels, nil)
		if len(plan.rules) != 2 {
			t.Fatalf("got %d rules, want 2", len(plan.rules))
		}
		if plan.rules[0].target.kind != icmpActionMark || plan.rules[0].target.iface != "wgo0" {
			t.Fatalf("expected healthy L3 balancer rule, got %+v", plan.rules[0].target)
		}
		if plan.rules[1].target.kind != icmpActionDrop {
			t.Fatalf("mixed L3/proxy balancer must fail closed, got %+v", plan.rules[1].target)
		}
	})

	t.Run("no blackhole falls back to first outbound only for valid client IPs", func(t *testing.T) {
		obsNoBlock := []byte(`[{"tag": "wg-out", "protocol": "freedom", "streamSettings": {"sockopt": {"interface": "wgo0"}}}]`)
		plan := buildVpnIcmpPlan(nets, []byte(`{"rules":[]}`), obsNoBlock, tunnels, []string{"10.7.0.2"})
		if len(plan.rules) != 1 || len(plan.rules[0].saddrs) != 1 || plan.rules[0].saddrs[0].String() != "10.7.0.2/32" {
			t.Fatalf("expected validIPs-only fallback, got %+v", plan.rules)
		}
		if plan.rules[0].target.table != 30005 {
			t.Fatalf("expected fallback to wg-out table 30005, got %+v", plan.rules[0].target)
		}
	})
}

func TestReconcileVpnIcmpRulesOwnership(t *testing.T) {
	prevList := icmpListNetlinkRules
	prevAdd := icmpAddNetlinkRule
	prevDel := icmpDelNetlinkRule
	t.Cleanup(func() {
		icmpListNetlinkRules = prevList
		icmpAddNetlinkRule = prevAdd
		icmpDelNetlinkRule = prevDel
	})

	fullMask := uint32(0xffffffff)
	_, srcIP, _ := net.ParseCIDR("10.9.9.9/32")

	live := []netlink.Rule{
		// Operator rule occupying priority 5000 with non-panel src: must stay.
		{Priority: 5000, Protocol: vpnIcmpRuleProto, Table: 30005, Mark: vpnIcmpMarkForTable(30005), Mask: &fullMask, Src: srcIP, SuppressPrefixlen: -1, SuppressIfgroup: -1, Goto: -1, Flow: -1},
		// Unrelated TPROXY & vpnoutvia rules: must stay.
		{Priority: 100, Table: vpnPolicyTable, Mark: vpnPolicyMark, Mask: &fullMask, SuppressPrefixlen: -1, SuppressIfgroup: -1, Goto: -1, Flow: -1},
		{Priority: 20000, Protocol: vpnOutRuleProto, Table: 30005, SuppressPrefixlen: -1, SuppressIfgroup: -1, Goto: -1, Flow: -1},
		// Panel ICMP rules: duplicate for 30005 (5001, 5002), stale for 30009 (5003).
		{Priority: 5001, Protocol: vpnIcmpRuleProto, Table: 30005, Mark: vpnIcmpMarkForTable(30005), Mask: &fullMask, SuppressPrefixlen: -1, SuppressIfgroup: -1, Goto: -1, Flow: -1},
		{Priority: 5002, Protocol: vpnIcmpRuleProto, Table: 30005, Mark: vpnIcmpMarkForTable(30005), Mask: &fullMask, SuppressPrefixlen: -1, SuppressIfgroup: -1, Goto: -1, Flow: -1},
		{Priority: 5003, Protocol: vpnIcmpRuleProto, Table: 30009, Mark: vpnIcmpMarkForTable(30009), Mask: &fullMask, SuppressPrefixlen: -1, SuppressIfgroup: -1, Goto: -1, Flow: -1},
	}

	icmpListNetlinkRules = func() ([]netlink.Rule, error) {
		return append([]netlink.Rule(nil), live...), nil
	}
	icmpAddNetlinkRule = func(prio int, mark uint32, table int) error {
		live = append(live, netlink.Rule{
			Priority:          prio,
			Protocol:          vpnIcmpRuleProto,
			Table:             table,
			Mark:              mark,
			Mask:              &fullMask,
			SuppressPrefixlen: -1,
			SuppressIfgroup:   -1,
			Goto:              -1,
			Flow:              -1,
		})
		return nil
	}
	icmpDelNetlinkRule = func(target netlink.Rule) error {
		for i, r := range live {
			if r.Priority == target.Priority && r.Table == target.Table && r.Mark == target.Mark && r.Protocol == target.Protocol {
				live = append(live[:i], live[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("rule not found: %+v", target)
	}

	reconcileVpnIcmpRules([]int{30005, 30006})

	var panelTables []int
	var foreignCount int
	for _, r := range live {
		if isVpnIcmpNetlinkRule(r) {
			panelTables = append(panelTables, r.Table)
			if r.Table == 30005 && r.Priority != 5001 {
				t.Fatalf("expected lowest-priority 30005 rule (5001) kept, got pref %d", r.Priority)
			}
			if r.Table == 30006 && r.Priority == 5000 {
				t.Fatalf("added rule collided with occupied priority 5000")
			}
		} else {
			foreignCount++
		}
	}
	if foreignCount != 3 {
		t.Fatalf("expected 3 non-panel rules untouched, got %d", foreignCount)
	}
	if len(panelTables) != 2 || panelTables[0] != 30005 || panelTables[1] != 30006 {
		t.Fatalf("unexpected live panel tables: %v", panelTables)
	}

	clearVpnIcmpRules()
	for _, r := range live {
		if isVpnIcmpNetlinkRule(r) {
			t.Fatalf("clearVpnIcmpRules left rule behind: %+v", r)
		}
	}
	if len(live) != 3 {
		t.Fatalf("clearVpnIcmpRules touched non-panel rules, remaining=%d", len(live))
	}
}

func TestVpnHostForwarding(t *testing.T) {
	prevHas := icmpHasIptables
	prevRun := icmpRunIptables
	t.Cleanup(func() {
		icmpHasIptables = prevHas
		icmpRunIptables = prevRun
		lastIcmpForwardSync.Store(0)
	})
	icmpHasIptables = func() bool { return true }

	t.Run("docker host with FORWARD DROP installs ICMP rules at top of DOCKER-USER idempotently", func(t *testing.T) {
		chains := map[string][]string{
			"FORWARD": {
				"-P FORWARD DROP",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
			},
			"DOCKER-USER": {
				"-N DOCKER-USER",
				"-A DOCKER-USER -j RETURN",
			},
		}
		icmpRunIptables = fakeIptablesRunner(chains)

		ensureVpnHostForwarding()
		du := chains["DOCKER-USER"]
		if len(du) != 4 {
			t.Fatalf("expected 2 inserted rules + header/RETURN, got: %v", du)
		}
		if du[1] != "-A DOCKER-USER -s 10.0.0.0/12 -p icmp -j ACCEPT" ||
			du[2] != "-A DOCKER-USER -d 10.0.0.0/12 -p icmp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" {
			t.Fatalf("unexpected DOCKER-USER rule order: %v", du)
		}

		// Re-running must be a strict no-op without duplicates.
		ensureVpnHostForwarding()
		if len(chains["DOCKER-USER"]) != 4 {
			t.Fatalf("expected idempotent DOCKER-USER, got duplicate rules: %v", chains["DOCKER-USER"])
		}

		cleanupVpnHostForwarding()
		if len(chains["DOCKER-USER"]) != 2 {
			t.Fatalf("cleanup left ICMP rules behind in DOCKER-USER: %v", chains["DOCKER-USER"])
		}
	})

	t.Run("non-docker UFW/DROP host targets FORWARD directly", func(t *testing.T) {
		chains := map[string][]string{
			"FORWARD": {
				"-P FORWARD DROP",
				"-A FORWARD -j ufw-before-forward",
			},
		}
		icmpRunIptables = fakeIptablesRunner(chains)

		ensureVpnHostForwarding()
		fwd := chains["FORWARD"]
		if len(fwd) != 4 || fwd[1] != "-A FORWARD -s 10.0.0.0/12 -p icmp -j ACCEPT" {
			t.Fatalf("expected FORWARD rules for non-docker DROP host, got: %v", fwd)
		}

		cleanupVpnHostForwarding()
		if len(chains["FORWARD"]) != 2 {
			t.Fatalf("cleanup left FORWARD rules behind: %v", chains["FORWARD"])
		}
	})

	t.Run("plain FORWARD ACCEPT host without DOCKER-USER is left untouched", func(t *testing.T) {
		chains := map[string][]string{
			"FORWARD": {
				"-P FORWARD ACCEPT",
			},
		}
		icmpRunIptables = fakeIptablesRunner(chains)

		ensureVpnHostForwarding()
		if len(chains["FORWARD"]) != 1 {
			t.Fatalf("plain host should not be modified, got: %v", chains["FORWARD"])
		}
	})
}

func fakeIptablesRunner(chains map[string][]string) func(args ...string) (string, error) {
	return func(args ...string) (string, error) {
		if len(args) < 2 {
			return "", fmt.Errorf("short args: %v", args)
		}
		op, chain := args[0], args[1]
		lines, exists := chains[chain]
		switch op {
		case "-S":
			if !exists {
				return "", fmt.Errorf("No chain/target/match by that name")
			}
			return strings.Join(lines, "\n") + "\n", nil
		case "-C":
			if !exists {
				return "", fmt.Errorf("no chain")
			}
			want := "-A " + chain + " " + strings.Join(args[2:], " ")
			for _, l := range lines {
				if l == want {
					return "", nil
				}
			}
			return "", fmt.Errorf("rule does not exist")
		case "-I":
			if !exists {
				return "", fmt.Errorf("no chain")
			}
			ruleArgs := args[2:]
			pos := 1
			if len(ruleArgs) > 0 && ruleArgs[0] == "1" {
				ruleArgs = ruleArgs[1:]
			}
			line := "-A " + chain + " " + strings.Join(ruleArgs, " ")
			insertAt := 0
			for insertAt < len(lines) && (strings.HasPrefix(lines[insertAt], "-P ") || strings.HasPrefix(lines[insertAt], "-N ")) {
				insertAt++
			}
			_ = pos
			updated := append([]string{}, lines[:insertAt]...)
			updated = append(updated, line)
			updated = append(updated, lines[insertAt:]...)
			chains[chain] = updated
			return "", nil
		case "-D":
			if !exists {
				return "", fmt.Errorf("no chain")
			}
			want := "-A " + chain + " " + strings.Join(args[2:], " ")
			for i, l := range lines {
				if l == want {
					chains[chain] = append(lines[:i], lines[i+1:]...)
					return "", nil
				}
			}
			return "", fmt.Errorf("not found")
		default:
			return "", fmt.Errorf("unsupported op %s", op)
		}
	}
}
