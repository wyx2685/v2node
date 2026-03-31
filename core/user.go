package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/counter"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/core/app/dispatcher"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/anytls"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/tuic"
	"github.com/xtls/xray-core/proxy/vless"
)

func (v *V2Core) GetUserManager(tag string) (proxy.UserManager, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handler, err := v.ihm.GetHandler(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}
	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.UserManager", tag)
	}
	return userManager, nil
}

func (vc *V2Core) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	userManager, err := vc.GetUserManager(tag)
	if err != nil {
		return fmt.Errorf("get user manager error: %s", err)
	}
	var user string
	vc.users.mapLock.Lock()
	defer vc.users.mapLock.Unlock()
	for i := range users {
		user = format.UserTag(tag, users[i].Uuid)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = userManager.RemoveUser(ctx, user)
		cancel()
		if err != nil {
			return err
		}
		delete(vc.users.uidMap, user)
		if v, ok := vc.dispatcher.Counter.Load(tag); ok {
			tc := v.(*counter.TrafficCounter)
			tc.Delete(user)
		}
		if v, ok := vc.dispatcher.LinkManagers.Load(user); ok {
			lm := v.(*dispatcher.LinkManager)
			lm.CloseAll()
			vc.dispatcher.LinkManagers.Delete(user)
		}
	}
	return nil
}

func (vc *V2Core) GetUserTrafficSlice(tag string, mintraffic int) ([]panel.UserTraffic, error) {
	trafficSlice := make([]panel.UserTraffic, 0)
	vc.users.mapLock.RLock()
	defer vc.users.mapLock.RUnlock()
	if v, ok := vc.dispatcher.Counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		c.Counters.Range(func(key, value interface{}) bool {
			email := key.(string)
			traffic := value.(*counter.TrafficStorage)
			up := traffic.UpCounter.Load()
			down := traffic.DownCounter.Load()
			if up+down > int64(mintraffic*1000) {
				traffic.UpCounter.Store(0)
				traffic.DownCounter.Store(0)
				if vc.users.uidMap[email] == 0 {
					c.Delete(email)
					return true
				}
				trafficSlice = append(trafficSlice, panel.UserTraffic{
					UID:      vc.users.uidMap[email],
					Upload:   up,
					Download: down,
				})
			}
			return true
		})
		if len(trafficSlice) == 0 {
			return nil, nil
		}
		return trafficSlice, nil
	}
	return nil, nil
}

func (v *V2Core) AddUsers(p *AddUsersParams) (added int, err error) {
	v.users.mapLock.Lock()
	defer v.users.mapLock.Unlock()
	for i := range p.Users {
		v.users.uidMap[format.UserTag(p.Tag, p.Users[i].Uuid)] = p.Users[i].Id
	}
	var users []*protocol.User
	switch p.NodeInfo.Type {
	case "vmess":
		users = buildVmessUsers(p.Tag, p.Users)
	case "vless":
		users = buildVlessUsers(p.Tag, p.Users, p.Common.Flow)
	case "trojan":
		users = buildTrojanUsers(p.Tag, p.Users)
	case "shadowsocks":
		users = buildSSUsers(p.Tag,
			p.Users,
			p.Common.Cipher,
			p.Common.ServerKey)
	case "hysteria2":
		users = buildHysteria2Users(p.Tag, p.Users)
	case "tuic":
		users = buildTuicUsers(p.Tag, p.Users)
	case "anytls":
		users = buildAnyTLSUsers(p.Tag, p.Users)
	default:
		return 0, fmt.Errorf("unsupported node type: %s", p.NodeInfo.Type)
	}
	man, err := v.GetUserManager(p.Tag)
	if err != nil {
		return 0, fmt.Errorf("get user manager error: %s", err)
	}
	for _, u := range users {
		mUser, err := u.ToMemoryUser()
		if err != nil {
			return 0, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = man.AddUser(ctx, mUser)
		cancel()
		if err != nil {
			return 0, err
		}
	}
	return len(users), nil
}

func buildVmessUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i, user := range userInfo {
		users[i] = buildVmessUser(tag, &user)
	}
	return users
}

func buildVmessUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	vmessAccount := &conf.VMessAccount{
		ID:       userInfo.Uuid,
		Security: "auto",
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(vmessAccount.Build()),
	}
}

func buildVlessUsers(tag string, userInfo []panel.UserInfo, flow string) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildVlessUser(tag, &(userInfo)[i], flow)
	}
	return users
}

func buildVlessUser(tag string, userInfo *panel.UserInfo, flow string) (user *protocol.User) {
	vlessAccount := &vless.Account{
		Id: userInfo.Uuid,
	}
	vlessAccount.Flow = flow
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(vlessAccount),
	}
}

func buildTrojanUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildTrojanUser(tag, &(userInfo)[i])
	}
	return users
}

func buildTrojanUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	trojanAccount := &trojan.Account{
		Password: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(trojanAccount),
	}
}

func buildSSUsers(tag string, userInfo []panel.UserInfo, cypher string, serverKey string) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildSSUser(tag, &userInfo[i], cypher, serverKey)
	}
	return users
}

func buildSSUser(tag string, userInfo *panel.UserInfo, cypher string, serverKey string) (user *protocol.User) {
	if serverKey == "" {
		ssAccount := &shadowsocks.Account{
			Password:   userInfo.Uuid,
			CipherType: getCipherFromString(cypher),
		}
		return &protocol.User{
			Level:   0,
			Email:   format.UserTag(tag, userInfo.Uuid),
			Account: serial.ToTypedMessage(ssAccount),
		}
	} else {
		var keyLength int
		switch cypher {
		case "2022-blake3-aes-128-gcm":
			keyLength = 16
		case "2022-blake3-aes-256-gcm":
			keyLength = 32
		case "2022-blake3-chacha20-poly1305":
			keyLength = 32
		}
		ssAccount := &shadowsocks_2022.Account{
			Key: base64.StdEncoding.EncodeToString([]byte(userInfo.Uuid[:keyLength])),
		}
		return &protocol.User{
			Level:   0,
			Email:   format.UserTag(tag, userInfo.Uuid),
			Account: serial.ToTypedMessage(ssAccount),
		}
	}
}

func getCipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

func buildHysteria2Users(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildHysteria2User(tag, &userInfo[i])
	}
	return users
}

func buildHysteria2User(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	hysteria2Account := &hyaccount.Account{
		Auth: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(hysteria2Account),
	}
}

func buildTuicUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildTuicUser(tag, &userInfo[i])
	}
	return users
}

func buildTuicUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	tuicAccount := &tuic.Account{
		Uuid:     userInfo.Uuid,
		Password: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(tuicAccount),
	}
}

func buildAnyTLSUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildAnyTLSUser(tag, &userInfo[i])
	}
	return users
}

func buildAnyTLSUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	anyTLSAccount := &anytls.Account{
		Password: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(anyTLSAccount),
	}
}
