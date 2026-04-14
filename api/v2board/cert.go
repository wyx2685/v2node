package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type NodeCertPair struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (c *Client) GetNodeCertPair() (pair *NodeCertPair, changed bool, err error) {
	const path = "/api/v1/server/UniProxy/nodecert"
	r, err := c.client.
		R().
		SetHeader("If-None-Match", c.nodeCertEtag).
		ForceContentType("application/json").
		Get(path)

	if err != nil {
		return nil, false, err
	}
	if r == nil {
		return nil, false, fmt.Errorf("received nil response")
	}
	if r.StatusCode() == 304 {
		return nil, false, nil
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.nodeCertBodyHash == newBodyHash {
		return nil, false, nil
	}
	c.nodeCertBodyHash = newBodyHash
	c.nodeCertEtag = r.Header().Get("ETag")

	defer func() {
		if r.RawBody() != nil {
			r.RawBody().Close()
		}
	}()

	pair = &NodeCertPair{}
	err = json.Unmarshal(r.Body(), pair)
	if err != nil {
		return nil, false, fmt.Errorf("decode node cert error: %s", err)
	}
	if pair.Cert == "" || pair.Key == "" {
		return nil, false, fmt.Errorf("received empty cert or key")
	}
	return pair, true, nil
}
