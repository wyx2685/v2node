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
//	    {"tag": "proxy-2", "protocol": "trojan", "settings": {...}}
//	  ],
//	  "strategy": "leastping",
//	  "fallbackTag": "direct"
//	}
type BalancerActionValue struct {
	// Tag 负载均衡器标识（必填）
	Tag string `json:"tag"`
	// Outbounds 出站配置数组（必填），自动提取 tag 作为 selector
	Outbounds []json.RawMessage `json:"outbounds"`
	// Strategy 负载均衡策略: random(默认), roundrobin, leastping, leastload
	Strategy string `json:"strategy"`
	// FallbackTag 回退出站 tag，当所有出站不可用时使用
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

// GetSelectorTags 从 outbounds 提取所有 tag
func GetSelectorTags(config *BalancerActionValue) []string {
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
