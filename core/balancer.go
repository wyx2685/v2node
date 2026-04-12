package core

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// BalancerActionValue 负载均衡 action_value 配置结构
//
// 用于 balancer、balancer_ip、default_balancer 三种 Action
//
// 示例:
//
//	{
//	  "tag": "proxy-lb",
//	  "outbounds": [
//	    {"tag": "proxy-1", "protocol": "vmess", "settings": {...}},
//	    {"tag": "proxy-2", "protocol": "trojan", "settings": {...}},
//	    {"tag": "fallback-proxy", "protocol": "vmess", "settings": {...}}
//	  ],
//	  "selector": ["proxy-1", "proxy-2"],
//	  "strategy": "leastping",
//	  "fallbackTag": "fallback-proxy"
//	}
type BalancerActionValue struct {
	// Tag 负载均衡器标识（必填）
	Tag string `json:"tag"`
	// Outbounds 出站配置数组（必填）
	Outbounds []json.RawMessage `json:"outbounds"`
	// Selector 参与负载均衡的出站 tag 列表（可选，默认使用所有 outbounds）
	Selector []string `json:"selector,omitempty"`
	// Strategy 负载均衡策略: random(默认), roundrobin, leastping, leastload
	Strategy string `json:"strategy"`
	// FallbackTag 回退出站 tag，当所有出站不可用时使用（可以是不在 selector 中的出站）
	FallbackTag string `json:"fallbackTag,omitempty"`
}

// ParseBalancerConfig 解析负载均衡配置
func ParseBalancerConfig(actionValue *string) (*BalancerActionValue, error) {
	if actionValue == nil {
		return nil, fmt.Errorf("action_value is nil")
	}
	var config BalancerActionValue
	if err := json.Unmarshal([]byte(*actionValue), &config); err != nil {
		return nil, fmt.Errorf("failed to parse balancer config: %w", err)
	}
	if config.Tag == "" {
		return nil, fmt.Errorf("balancer tag is required")
	}
	if len(config.Outbounds) == 0 {
		return nil, fmt.Errorf("balancer outbounds is required")
	}
	if config.Strategy == "" {
		config.Strategy = "random"
	}
	return &config, nil
}

// BuildBalancerOutbounds 构建出站配置
func BuildBalancerOutbounds(config *BalancerActionValue, existingOutbounds []*core.OutboundHandlerConfig) ([]*core.OutboundHandlerConfig, error) {
	var newOutbounds []*core.OutboundHandlerConfig

	for _, outboundRaw := range config.Outbounds {
		outbound := &coreConf.OutboundDetourConfig{}
		if err := json.Unmarshal(outboundRaw, outbound); err != nil {
			return nil, fmt.Errorf("failed to parse outbound: %w", err)
		}
		if outbound.Tag == "" {
			continue
		}
		if hasOutboundWithTag(existingOutbounds, outbound.Tag) {
			continue
		}
		if hasOutboundWithTag(newOutbounds, outbound.Tag) {
			continue
		}
		built, err := outbound.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build outbound %s: %w", outbound.Tag, err)
		}
		newOutbounds = append(newOutbounds, built)
	}

	return newOutbounds, nil
}

// GetSelectorTags 获取参与负载均衡的 tag 列表
// 如果设置了 Selector 则使用 Selector，否则使用所有 outbounds 的 tag
func GetSelectorTags(config *BalancerActionValue) []string {
	// 优先使用 Selector 字段
	if len(config.Selector) > 0 {
		return config.Selector
	}
	// 否则从 outbounds 提取所有 tag
	var tags []string
	for _, outboundRaw := range config.Outbounds {
		var outbound struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(outboundRaw, &outbound); err != nil {
			continue
		}
		if outbound.Tag != "" {
			tags = append(tags, outbound.Tag)
		}
	}
	return tags
}

// BuildBalancingRule 构建负载均衡规则（返回 coreConf.BalancingRule 供 RouterConfig 使用）
func BuildBalancingRule(config *BalancerActionValue) (*coreConf.BalancingRule, error) {
	selectorTags := GetSelectorTags(config)
	if len(selectorTags) == 0 {
		return nil, fmt.Errorf("no valid selector tags found")
	}

	confBalancer := &coreConf.BalancingRule{
		Tag:         config.Tag,
		Selectors:   selectorTags,
		FallbackTag: config.FallbackTag,
	}

	switch config.Strategy {
	case "random":
		confBalancer.Strategy.Type = "random"
	case "roundrobin":
		confBalancer.Strategy.Type = "roundRobin"
	case "leastping":
		confBalancer.Strategy.Type = "leastPing"
	case "leastload":
		confBalancer.Strategy.Type = "leastLoad"
	default:
		confBalancer.Strategy.Type = "random"
	}

	return confBalancer, nil
}
