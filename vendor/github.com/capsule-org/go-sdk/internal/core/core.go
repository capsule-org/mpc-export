package core

import (
	"errors"

	"github.com/capsule-org/go-sdk/internal/network"
	"github.com/capsule-org/go-sdk/internal/round"

	"github.com/capsule-org/multi-party-sig/pkg/ecdsa"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/paillier"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/pool"
	"github.com/capsule-org/multi-party-sig/pkg/protocol"
	"github.com/capsule-org/multi-party-sig/protocols/cmp"
	"github.com/capsule-org/multi-party-sig/protocols/example"
)

const (
	protocolOfflineID                  = "cmp/presign-offline"
	protocolOnlineID                   = "cmp/presign-online"
	protocolFullID                     = "cmp/presign-full"
	protocolOfflineRounds round.Number = 7
	protocolFullRounds    round.Number = 8
)

func XOR(id party.ID, ids party.IDSlice, net *network.Network, protocolId string, useWebSocket bool) error {
	handler, err := protocol.NewMultiHandler(example.StartXOR(id, ids), []byte(protocolId))
	if err != nil {
		return err
	}
	err = network.HandlerLoop(id, handler, net, protocolId, nil, useWebSocket)
	if err != nil {
		return err
	}
	_, err = handler.Result()
	if err != nil {
		return err
	}
	return nil
}

func Keygen(id party.ID, ids party.IDSlice, threshold int, n *network.Network, pl *pool.Pool, protocolId string, secretKey *paillier.SecretKey, statusFunc network.JSFunc, useWebSocket bool) (*cmp.Config, error) {
	handler, err := protocol.NewMultiHandler(
		cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl, secretKey),
		[]byte(protocolId),
	)
	if err != nil {
		return nil, err
	}
	err = network.HandlerLoop(id, handler, n, protocolId, statusFunc, useWebSocket)
	if err != nil {
		return nil, err
	}
	r, err := handler.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func Refresh(c *cmp.Config, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*cmp.Config, error) {
	hRefresh, err := protocol.NewMultiHandler(cmp.Refresh(c, pl), []byte(protocolId))
	if err != nil {
		return nil, err
	}
	err = network.HandlerLoop(c.ID, hRefresh, n, protocolId, nil, useWebSocket)
	if err != nil {
		return nil, err
	}

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func Sign(c *cmp.Config, m []byte, signers party.IDSlice, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*ecdsa.Signature, error) {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl), []byte(protocolId))
	if err != nil {
		return nil, err
	}
	err = network.HandlerLoop(c.ID, h, n, protocolId, nil, useWebSocket)
	if err != nil {
		return nil, err
	}

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return nil, errors.New("failed to verify cmp signature")
	}
	return signature, nil
}

func PreSign(c *cmp.Config, signers party.IDSlice, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*ecdsa.PreSignature, error) {
	h, err := protocol.NewMultiHandler(cmp.Presign(c, signers, pl), []byte(protocolId))
	if err != nil {
		return nil, err
	}

	err = network.HandlerLoop(c.ID, h, n, protocolId, nil, useWebSocket)
	if err != nil {
		return nil, err
	}

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}

	preSignature := signResult.(*ecdsa.PreSignature)
	if err = preSignature.Validate(); err != nil {
		return nil, errors.New("failed to verify cmp presignature")
	}
	return preSignature, nil
}

func PreSignOnline(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) error {
	h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, preSignature, m, pl), []byte(protocolId))
	if err != nil {
		return err
	}
	err = network.HandlerLoop(c.ID, h, n, protocolId, nil, useWebSocket)
	if err != nil {
		return err
	}

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}
