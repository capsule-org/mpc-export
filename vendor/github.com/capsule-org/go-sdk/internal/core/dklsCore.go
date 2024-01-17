package core

import (
	"errors"

	"github.com/capsule-org/go-sdk/internal/network"

	"github.com/capsule-org/multi-party-sig/pkg/ecdsa"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/pool"
	"github.com/capsule-org/multi-party-sig/pkg/protocol"
	"github.com/capsule-org/multi-party-sig/protocols/doerner"
	"github.com/capsule-org/multi-party-sig/protocols/doerner/keygen"
)

func dklsBaseKeygen(id party.ID, otherId party.ID, n *network.Network, pl *pool.Pool, protocolId string, isReceiver, useWebSocket bool) (interface{}, error) {
	handler, err := protocol.NewTwoPartyHandler(doerner.Keygen(curve.Secp256k1{}, isReceiver, id, otherId, pl), []byte(protocolId), isReceiver)
	if err != nil {
		return nil, err
	}
	network.HandlerLoop(id, handler, n, protocolId, nil, useWebSocket)

	return handler.Result()
}

func DKLSSenderKeygen(id, otherId party.ID, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*doerner.ConfigSender, error) {
	resultRound, err := dklsBaseKeygen(id, otherId, n, pl, protocolId, false, useWebSocket)
	if err != nil {
		return nil, err
	}
	newConfigSender, ok := resultRound.(*doerner.ConfigSender)
	if !ok {
		return nil, errors.New("failed to cast result to *ConfigSender")
	}
	return newConfigSender, nil
}

func DKLSReceiverKeygen(id, otherId party.ID, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*doerner.ConfigReceiver, error) {
	resultRound, err := dklsBaseKeygen(id, otherId, n, pl, protocolId, true, useWebSocket)
	if err != nil {
		return nil, err
	}
	newConfigReceiver, ok := resultRound.(*doerner.ConfigReceiver)
	if !ok {
		return nil, errors.New("failed to cast result to *ConfigReceiver")
	}
	return newConfigReceiver, nil
}

func DKLSSenderRefresh(configSender *keygen.ConfigSender, id, otherId party.ID, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*doerner.ConfigSender, error) {
	handler, err := protocol.NewTwoPartyHandler(doerner.RefreshSender(configSender, id, otherId, pl), []byte(protocolId), false)
	if err != nil {
		return nil, err
	}
	network.HandlerLoop(id, handler, n, protocolId, nil, useWebSocket)

	resultRound, err := handler.Result()
	if err != nil {
		return nil, err
	}
	newConfigSender, ok := resultRound.(*doerner.ConfigSender)
	if !ok {
		return nil, errors.New("failed to cast result to *ConfigSender")
	}
	return newConfigSender, nil
}

func DKLSReceiverRefresh(configReceiver *keygen.ConfigReceiver, id, otherId party.ID, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*doerner.ConfigReceiver, error) {
	handler, err := protocol.NewTwoPartyHandler(doerner.RefreshReceiver(configReceiver, id, otherId, pl), []byte(protocolId), true)
	if err != nil {
		return nil, err
	}
	network.HandlerLoop(id, handler, n, protocolId, nil, useWebSocket)

	resultRound, err := handler.Result()
	if err != nil {
		return nil, err
	}
	newConfigReceiver, ok := resultRound.(*doerner.ConfigReceiver)
	if !ok {
		return nil, errors.New("failed to cast result to *ConfigReceiver")
	}
	return newConfigReceiver, nil
}

func DKLSSenderSign(configSender *keygen.ConfigSender, id, otherId party.ID, hash []byte, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*ecdsa.Signature, error) {
	handler, err := protocol.NewTwoPartyHandler(doerner.SignSender(configSender, id, otherId, hash, pl), []byte(protocolId), false)
	if err != nil {
		return nil, err
	}
	network.HandlerLoop(id, handler, n, protocolId, nil, useWebSocket)

	resultRound, err := handler.Result()
	if err != nil {
		return nil, err
	}
	sig, ok := resultRound.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("failed to cast result to Signature")
	}

	return sig, nil
}

func DKLSReceiverSign(configReceiver *keygen.ConfigReceiver, id, otherId party.ID, hash []byte, n *network.Network, pl *pool.Pool, protocolId string, useWebSocket bool) (*ecdsa.Signature, error) {
	handler, err := protocol.NewTwoPartyHandler(doerner.SignReceiver(configReceiver, id, otherId, hash, pl), []byte(protocolId), true)
	if err != nil {
		return nil, err
	}
	network.HandlerLoop(id, handler, n, protocolId, nil, useWebSocket)

	resultRound, err := handler.Result()
	if err != nil {
		return nil, err
	}
	sig, ok := resultRound.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("failed to cast result to Signature")
	}

	return sig, nil
}
