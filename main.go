package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"

	mpcsigner "github.com/capsule-org/go-sdk/signer"
	"github.com/capsule-org/multi-party-sig/pkg/ecdsa"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/pool"
	"github.com/capsule-org/multi-party-sig/pkg/protocol"
	"github.com/capsule-org/multi-party-sig/protocols/doerner"
	"github.com/capsule-org/multi-party-sig/protocols/doerner/keygen"
	"github.com/google/uuid"
)

type Network struct {
	parties          party.IDSlice
	listenChannels   map[party.ID]chan *protocol.Message
	done             chan struct{}
	closedListenChan chan *protocol.Message
	mtx              sync.Mutex
}

func NewNetwork(parties party.IDSlice) *Network {
	closed := make(chan *protocol.Message)
	close(closed)
	c := &Network{
		parties:          parties,
		listenChannels:   make(map[party.ID]chan *protocol.Message, 2*len(parties)),
		closedListenChan: closed,
	}
	return c
}

func (n *Network) init() {
	N := len(n.parties)
	for _, id := range n.parties {
		n.listenChannels[id] = make(chan *protocol.Message, N*N)
	}
	n.done = make(chan struct{})
}

func (n *Network) Next(id party.ID) <-chan *protocol.Message {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	if len(n.listenChannels) == 0 {
		n.init()
	}
	c, ok := n.listenChannels[id]
	if !ok {
		return n.closedListenChan
	}
	return c
}

func (n *Network) Send(msg *protocol.Message) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	for id, c := range n.listenChannels {
		if msg.IsFor(id) && c != nil {
			n.listenChannels[id] <- msg
		}
	}
}

func (n *Network) Done(id party.ID) chan struct{} {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	if _, ok := n.listenChannels[id]; ok {
		close(n.listenChannels[id])
		delete(n.listenChannels, id)
	}
	if len(n.listenChannels) == 0 {
		close(n.done)
	}
	return n.done
}

// func (n *Network) Quit(id party.ID) {
// 	n.mtx.Lock()
// 	defer n.mtx.Unlock()
// 	n.parties = n.parties.Remove(id)
// }

func handlerLoop(id party.ID, h protocol.Handler, network *Network) {
	for {
		select {
		case msg, ok := <-h.Listen():
			if !ok {
				<-network.Done(id)
				return
			}
			go network.Send(msg)

		case msg := <-network.Next(id):
			h.Accept(msg)
		}
	}
}

func runHandler(wg *sync.WaitGroup, id party.ID, handler protocol.Handler, network *Network) {
	defer wg.Done()
	handlerLoop(id, handler, network)
}

func runSign(hash []byte, configSender *keygen.ConfigSender, configReceiver *keygen.ConfigReceiver) (*ecdsa.Signature, error) {
	partyIDs := party.IDSlice{"USER", "CAPSULE"}
	pl := pool.NewPool(0)
	defer pl.TearDown()

	session := uuid.New()
	h0, err := protocol.NewTwoPartyHandler(doerner.SignReceiver(configReceiver, partyIDs[0], partyIDs[1], hash, pl), session[:], true)
	if err != nil {
		return nil, err
	}
	h1, err := protocol.NewTwoPartyHandler(doerner.SignSender(configSender, partyIDs[1], partyIDs[0], hash, pl), session[:], true)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	network := NewNetwork(partyIDs)
	wg.Add(2)
	go runHandler(&wg, partyIDs[0], h0, network)
	go runHandler(&wg, partyIDs[1], h1, network)
	wg.Wait()

	resultRound0, err := h0.Result()
	if err != nil {
		return nil, err
	}
	sig, ok := resultRound0.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("error casting result to Signature")
	}
	return sig, nil
}

func main() {
	fmt.Println("\n\n---------------- Generating signature with backup share ----------------\n")
	userShare := os.Args[1]
	capsuleShareConfig := os.Args[2]
	rlpEncodedTxHashHex := os.Args[3]

	userSigner, err := mpcsigner.DKLSDeserializeSigner(userShare, "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	address, err := userSigner.GetAddress()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("address:")
	fmt.Println(address)

	capsuleShare := fmt.Sprintf(
		`{"walletId":"%s","id":"%s","otherId":"%s","receiverConfig":"%s","senderConfig":"%s","isReceiver":%t,"disableWebSockets":%t}`,
		userSigner.GetWalletId(),
		"CAPSULE",
		"USER",
		capsuleShareConfig,
		"9g==",
		true,
		false,
	)
	capsuleSigner, err := mpcsigner.DKLSDeserializeSigner(capsuleShare, "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	hashBytes, err := hex.DecodeString(rlpEncodedTxHashHex)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	sig, err := runSign(hashBytes, userSigner.GetSenderConfigStruct(), capsuleSigner.GetReceiverConfigStruct())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	sigBytes, err := sig.SigEthereum()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	sigHex := hex.EncodeToString(sigBytes)
	fmt.Println("\nsignature:")
	fmt.Println("0x" + sigHex + "\n")
}
