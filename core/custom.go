package core

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv6, not loopback, not link-local, not private/ULA
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

// getActionPriority 返回 action 的优先级，数字越小优先级越高
// 优先级设计：
//
//	0: dns - DNS 配置（不生成路由规则）
//	1: block, protocol - 域名/协议阻止（最高优先级阻止）
//	2: block_ip, block_port - IP/端口阻止
//	3: balancer, route - 域名匹配的负载均衡/路由（同级，保持配置顺序）
//	4: balancer_ip, route_ip - IP 匹配的负载均衡/路由（同级，保持配置顺序）
//	5: default_out, default_balancer - 兜底规则（最低优先级）
func getActionPriority(action string) int {
	switch action {
	case "dns":
		return 0
	case "block", "protocol":
		return 1
	case "block_ip", "block_port":
		return 2
	case "balancer", "route":
		return 3
	case "balancer_ip", "route_ip":
		return 4
	case "default_out", "default_balancer":
		return 5
	default:
		return 6
	}
}

// sortRoutesByPriority 按优先级排序路由规则
func sortRoutesByPriority(routes []panel.Route) []panel.Route {
	sorted := make([]panel.Route, len(routes))
	copy(sorted, routes)
	sort.SliceStable(sorted, func(i, j int) bool {
		return getActionPriority(sorted[i].Action) < getActionPriority(sorted[j].Action)
	})
	return sorted
}

func GetCustomConfig(infos []*panel.NodeInfo) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, *observatory.Config, error) {
	//dns
	queryStrategy := "UseIPv4v6"
	if !hasPublicIPv6() {
		queryStrategy = "UseIPv4"
	}
	coreDnsConfig := &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("localhost"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}
	//outbound
	defaultoutbound, _ := buildDefaultOutbound()
	coreOutboundConfig := append([]*core.OutboundHandlerConfig{}, defaultoutbound)
	block, _ := buildBlockOutbound()
	coreOutboundConfig = append(coreOutboundConfig, block)
	dnsOut, _ := buildDnsOutbound()
	coreOutboundConfig = append(coreOutboundConfig, dnsOut)

	//route
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": "dns_out",
	})
	coreRouterConfig := &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{dnsRule},
		DomainStrategy: &domainStrategy,
	}

	// observatory tags for leastping/leastload strategies
	var observatoryTags []string

	for _, info := range infos {
		if len(info.Common.Routes) == 0 {
			continue
		}
		// 按优先级排序路由规则
		sortedRoutes := sortRoutesByPriority(info.Common.Routes)
		for _, route := range sortedRoutes {
			switch route.Action {
			case "dns":
				if route.ActionValue == nil {
					continue
				}
				server := &coreConf.NameServerConfig{
					Address: &coreConf.Address{
						Address: xnet.ParseAddress(*route.ActionValue),
					},
				}
				if len(route.Match) != 0 {
					server.Domains = route.Match
					server.SkipFallback = true
				}
				coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
			case "block":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_ip":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_port":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"port":        strings.Join(route.Match, ","),
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "protocol":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"protocol":    route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "route":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "route_ip":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "default_out":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"network":     "tcp,udp",
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "balancer":
				balancerConfig, err := ParseBalancerConfig(route.ActionValue)
				if err != nil {
					continue
				}
				// 构建出站配置
				newOutbounds, err := BuildBalancerOutbounds(balancerConfig, coreOutboundConfig)
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, newOutbounds...)
				// 构建负载均衡规则
				balancingRule, err := BuildBalancingRule(balancerConfig)
				if err != nil {
					continue
				}
				coreRouterConfig.Balancers = append(coreRouterConfig.Balancers, balancingRule)
				// 构建路由规则（域名匹配）
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"balancerTag": balancerConfig.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				// 收集 Observatory tags
				if balancerConfig.Strategy == "leastping" || balancerConfig.Strategy == "leastload" {
					observatoryTags = append(observatoryTags, GetSelectorTags(balancerConfig)...)
				}
			case "balancer_ip":
				balancerConfig, err := ParseBalancerConfig(route.ActionValue)
				if err != nil {
					continue
				}
				newOutbounds, err := BuildBalancerOutbounds(balancerConfig, coreOutboundConfig)
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, newOutbounds...)
				balancingRule, err := BuildBalancingRule(balancerConfig)
				if err != nil {
					continue
				}
				coreRouterConfig.Balancers = append(coreRouterConfig.Balancers, balancingRule)
				// 构建路由规则（IP 匹配）
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"balancerTag": balancerConfig.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if balancerConfig.Strategy == "leastping" || balancerConfig.Strategy == "leastload" {
					observatoryTags = append(observatoryTags, GetSelectorTags(balancerConfig)...)
				}
			case "default_balancer":
				balancerConfig, err := ParseBalancerConfig(route.ActionValue)
				if err != nil {
					continue
				}
				newOutbounds, err := BuildBalancerOutbounds(balancerConfig, coreOutboundConfig)
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, newOutbounds...)
				balancingRule, err := BuildBalancingRule(balancerConfig)
				if err != nil {
					continue
				}
				coreRouterConfig.Balancers = append(coreRouterConfig.Balancers, balancingRule)
				// 构建路由规则（所有流量）
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"network":     "tcp,udp",
					"balancerTag": balancerConfig.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if balancerConfig.Strategy == "leastping" || balancerConfig.Strategy == "leastload" {
					observatoryTags = append(observatoryTags, GetSelectorTags(balancerConfig)...)
				}
			default:
				continue
			}
		}
	}
	DnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// 创建固定的 Observatory 配置
	var observatoryConfig *observatory.Config
	if len(observatoryTags) > 0 {
		observatoryConfig = &observatory.Config{
			SubjectSelector:   observatoryTags,
			ProbeUrl:          "https://www.gstatic.com/generate_204",
			ProbeInterval:     int64(10 * time.Second), // 10秒，time.Duration 单位是纳秒
			EnableConcurrency: true,
		}
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, observatoryConfig, nil
}
