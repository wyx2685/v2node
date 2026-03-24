package core

import (
	"encoding/json"
	"fmt"
	"strconv"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/limiter"
	"github.com/xtls/xray-core/infra/conf"
)

func (v *V2Core) AddNode(tag string, info *panel.NodeInfo) error {
	inBoundConfig, err := buildInbound(info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}

	// User Routes
	if info.Common != nil && len(info.Common.Routes) > 0 {
		l, _ := limiter.GetLimiter(tag)
		for _, route := range info.Common.Routes {
			if route.Action == "route_user" && route.ActionValue != nil {
				outbound := &conf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				// Use remarks as tag
				if route.Remarks != "" {
					outbound.Tag = route.Remarks
				} else {
					outbound.Tag = "route_user_" + strconv.Itoa(route.Id)
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				err = v.addOutbound(custom_outbound)
				if err != nil {
					continue
				}
				if l != nil {
					for _, uuid := range route.Match {
						l.UpdateUserRoute(uuid, outbound.Tag)
					}
				}
			}
		}
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}
