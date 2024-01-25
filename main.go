package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
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
	closedListenChan chan *protocol.Message
	mtx              sync.Mutex
}

func newNetwork(parties party.IDSlice) *Network {
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
}

func (n *Network) next(id party.ID) <-chan *protocol.Message {
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

func (n *Network) send(msg *protocol.Message) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	for id, c := range n.listenChannels {
		if msg.IsFor(id) && c != nil {
			n.listenChannels[id] <- msg
		}
	}
}

func handlerLoop(id party.ID, h protocol.Handler, network *Network) {
	for {
		select {
		case msg, ok := <-h.Listen():
			if !ok {
				return
			}
			go network.send(msg)

		case msg := <-network.next(id):
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
	handlerUser, err := protocol.NewTwoPartyHandler(doerner.SignReceiver(configReceiver, partyIDs[0], partyIDs[1], hash, pl), session[:], true)
	if err != nil {
		return nil, err
	}
	handlerCapsule, err := protocol.NewTwoPartyHandler(doerner.SignSender(configSender, partyIDs[1], partyIDs[0], hash, pl), session[:], true)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	network := newNetwork(partyIDs)
	wg.Add(2)
	go runHandler(&wg, partyIDs[0], handlerUser, network)
	go runHandler(&wg, partyIDs[1], handlerCapsule, network)
	wg.Wait()

	result, err := handlerUser.Result()
	if err != nil {
		return nil, err
	}
	sig, ok := result.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("error casting result to Signature")
	}
	return sig, nil
}

func main() {
	fmt.Println("\n\n---------------- Generating private key with backup share ----------------\n")
	userShare := os.Args[1]
	capsuleShareConfig := os.Args[2]

	// if userShare is the snaps recovery secret, extract the share from everything after the "|" character
	if strings.Contains(userShare, "|") {
		splitUserShare := strings.SplitN(userShare, "|", 2)
		userShare = splitUserShare[1]
	}

	userSigner, err := mpcsigner.DKLSDeserializeSigner(userShare, "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// regex to replace non base64 characters with "ff" as it's encoded incorrectly in the pdf
	reg, err := regexp.Compile("[^A-Za-z0-9+/=]+")
	if err != nil {
		fmt.Println("error compiling regex:", err)
		os.Exit(1)
	}

	cleanCapsuleShareConfig := reg.ReplaceAllString(
		strings.ReplaceAll(capsuleShareConfig, " ", ""),
		"ff",
	)

	capsuleShare := fmt.Sprintf(
		`{"walletId":"%s","id":"%s","otherId":"%s","receiverConfig":"%s","senderConfig":"%s","isReceiver":%t,"disableWebSockets":%t}`,
		userSigner.GetWalletId(),
		"CAPSULE",
		"USER",
		cleanCapsuleShareConfig,
		"9g==",
		true,
		false,
	)

	capsuleSigner, err := mpcsigner.DKLSDeserializeSigner(capsuleShare, "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	sk1 := userSigner.GetPrivateKey()
	sk2 := capsuleSigner.GetPrivateKey()

	sk := sk1.Add(sk2)

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	skHex := hex.EncodeToString(skBytes)

	fmt.Println("private key hex:")
	fmt.Println("0x" + skHex)
}
