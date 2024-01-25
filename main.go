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
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
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

func runExport() (curve.Scalar, curve.Scalar, error) {
	userShare := os.Args[1]
	capsuleShareConfig := os.Args[2]

	// if userShare is the snaps recovery secret, extract the share from everything after the "|" character
	if strings.Contains(userShare, "|") {
		splitUserShare := strings.SplitN(userShare, "|", 2)
		userShare = splitUserShare[1]
	}
	fmt.Println("userShare:")
	fmt.Println(userShare)

	userSigner, err := mpcsigner.DKLSDeserializeSigner(userShare, "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("userSigner:")
	// fmt.Println(userSigner)

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

	fmt.Println("capsule share cfg:")

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

	fmt.Println("capsule share passed:")

	capsuleSigner, err := mpcsigner.DKLSDeserializeSigner(capsuleShare, "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("capsule signer :")

	sk1 := userSigner.GetPrivateKey()
	sk2 := capsuleSigner.GetPrivateKey()

	sk := sk1.Mul(sk2)
	pk := sk.ActOnBase()

	xbytes := pk.(*curve.Secp256k1Point).XBytes()
	ybytes := pk.(*curve.Secp256k1Point).YBytes()
	rawPKey := append(xbytes[:], ybytes[:]...)

	pkString := "0x04" + hex.EncodeToString(rawPKey)

	if pkString != userSigner.GetPublicKey() {
		os.Exit(1)
	}

	return userSigner.GetPrivateKey(), capsuleSigner.GetPrivateKey(), nil
}

// func main() {
// 	runExport()
// }

func main() {
	fmt.Println("\n\n---------------- Generating signature with backup share ----------------\n")
	userShare := os.Args[1]
	capsuleShareConfig := os.Args[2]
	rlpEncodedTxHashHex := os.Args[3]

	// if userShare is the snaps recovery secret, extract the share from everything after the "|" character
	if strings.Contains(userShare, "|") {
		splitUserShare := strings.SplitN(userShare, "|", 2)
		userShare = splitUserShare[1]
	}

	// remove "0x" prefix if it exists
	if rlpEncodedTxHashHex[:2] == "0x" {
		rlpEncodedTxHashHex = rlpEncodedTxHashHex[2:]
	}

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

	// regex to replace non base64 characters with "ff" as it's encoded incorrectly in the pdf
	reg, err := regexp.Compile("[^A-Za-z0-9+/=]+")
	if err != nil {
		fmt.Println("error compiling regex:", err)
		return
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

	fmt.Println("user private key:")
	fmt.Println(userSigner.GetPrivateKey())

	fmt.Println("capsule private key:")
	fmt.Println(capsuleSigner.GetPrivateKey())

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

//
// user share: "394d6d461b4efcd2d59295ceb1e84dbf983973befe2620b331168deef4e05e62|eyJ3YWxsZXRJZCI6IjQwNTNhNWY2LWRhNTctNGZjZS1iNWJlLWUxOGFkNGNjYjg4NCIsImlkIjoiVVNFUiIsIm90aGVySWQiOiJDQVBTVUxFIiwicmVjZWl2ZXJDb25maWciOiI5Zz09Iiwic2VuZGVyQ29uZmlnIjoicEdWVFpYUjFjRmtJa3FCV3M2aHNxc05oYUFITWZGL1l2NDJZZ0ZEQ2lNZmNGS3d1R3dCaHpVTG1QenZ1VVBEUnVUazl2cjVtbzNCZTVXOW1PSEpRWkZ4eURzWWVkQURlclhQVTFGTEhtRkFQYVI0MnZFT3FtWWpPZm5FendZWXdVRGRxYW8xbEZCT2FwNFlmRVpsM2RMSlFNNVpaaFhTMVNlYlY0cWhpcElER0xsRGJoWCtuV1l2NE9DU0lhK3k0V1lFZlVMNHZ2Si9ycE1IalIvaVVVdjJBWlA5UXFtOWM4OHpmeGlpK2czYUFhdml2NjFEdnEwelJuZlU1a2kxejBMOXQ5bXBrVUk0RzB4UGZBelNZT2EvcjlkS1BjQTFRbmN3UDAxZ21Gc3E3dC9lUjc1WEVJbENPUE5ValhCTXBZSHJZdjZodzZzQVhVTXR5ODFwWUhVVUJEc29xQzlrTHNUZFFVSTNPVitpMHRBSkIwOFNxNlUzZncxQWNHRXZmTzNicE80elg5eW9RNHdISlVLcmwybWY4eFRTbUtFTzB6dmdBa0ROUVFCdFZhbFNYRzh3Ukd2WFA4aEtjMGxEVEZ2cEJ3STRGRjh2OUNEZWhzL2NEVUJnM1haY1A2c0QyTW9GMDA5Q0NhQ0ZRSVllZm11OUFSeDl0cmhFZlJJLzMrbEJrZjlhRHBXYnRDV1dlSkZ1UEpxVFVVTGwwU2NHL25aWWFIc3RyRVlQMkJTdFEzcXR4ZTN5UHA1Ymp4cEZxVXNiNUJWRHdYTVBnWEJXbDdZL0hWMEJjd3NrWVVLMHpSdW0xQmlaRXpwMmxrcEVRZjdGUVAxdDZqVW45OEk3eU1mNmE3N0VrK2xDdnlWM2wzWE1LT1Y3dFRuWFIrSjhDVUVtaFVFV1B1RjVxWUJlY2xyV1BEVXBRQ1kwNlZkcDVjbVVnd2doOWcvOGhmbEJndEpBZkZmNG5IZitXR3dxbWw1UnNVRmsremRDOWpURWVkd2gwYU5Vc2hvbFFIQm9ua3NoNmZIWXhSQy90TlVUNHpGQ0hNSi9GeWRsNWhUQUlsN3dRbmNBVVVFUEFwL0paOHBNbmttT1BhQ09hRFlsUWp5eTFLcC93VmxKeDBEbkxGRUNQVlZBVWFtY3YxanA0ZG40Rit5OXBoMU03VU1CUkZ3M3F6WlBPc0xpdVZpeUN4VTVRZnB0cDlwNkFwSER3cWVBekNxSnF5MUNBd0pSTnluNk5GdlZiMXdUU0ZWUHpVQk9DUzB3dDdvbWlHazVxTSs5Y3ZCVlFvTmJpKzRnZFpoY09LdmVsbmJTY0hGQlFuOHpEYy9yVkNFc3BTZHdqWFB4V1VJMVJGZTZJODNCWTN5WjBZdzhLUHJKUXVCMVV4cDBmdlVKN2ZlQVNyYy9JUEZCdWp1TXZQMmcrYU1hVnJKeEs2RFo1VUhPU29SY1pxajRlSzM4T05wV1I5bEJROEVJQkxNQkR2NFUxa1Y0S2Rja09abEEyOElYQUUyRTNNeG1DaU9YcFdDOWxVRnJmVXdXdytidjF6TWFkcHF1V1I0NVFCSFQrVllNQ25JTDR0WUhNWm9qSDExQ3lDSjAwczhNK2xQVDEvTlBEYlZaMVVKRFRnQnhoZTJaOUFDMmJRVFNNdGFWUTc0L2l0aTd2dWllQ29NMGlnbTNXV2xBTGh0MU53emEzZ2NvOGtxclJTcU5QVVBzeERoZDBmTmdhOFVDQzRKOVhUd1ZRM0N6aitUU3cvbU1VaFpOT3pqWDNNVkFGcXlaNzU4M2J0elpTVlU0dGc2Nk1VR09uN3Y5bFVZTjJaUklsYU5FRTMyVlFySnlmQUFCaWF0UzBINHJlRFhZVkdGQWRCTmRheFkwT1E2R094dExaRktwL1VMTlB3Qi9pQWRkakpsMGs5VjNNbWxGUUVIZE1VVFZrTjA5YWFZaTN5R2F6UlZCMjhmMmdYSGE4UGNIMkJYNWQ2MHJEVUlVWlhoQkFydDNoMEpJSXh5RGlFc0ZRdEdSbkVrUWc4OTN0NkxXU2l0WTZrRkRaa1ZxTER0a1MydVkwU2RsUDVnMTJVQTl1R0Rma2VzYjdUQ0oxTkZla2xxNVE4VmNhRFB6bEFwT0lkeXVUTFdwWUxsRCtPV2QyTmpOdzFqK0NYYXdrK3AyelVJRzZIM1JDMGdKUGFDek4yNXNHdjU5UWhadXMwSjZVVXNlS01INXpNQnRsZ1ZCMU02M1h4QUxIWWZ2THJQVlBaZ0FXVU1hNnQrYnc3K2xOSkZWMVNnR1N5cDlRZ0pCYVBUOUdiemxlS282ay9FSE5KRkRxRS80YlRHTzBOUHRkYk9pSG56TXVVS2JJM0ZNTDJCd1Q2a2liL0FweWxSUlEycEFWTEVEMDFHZzNwY3lhWEswVjZGQ0s4MnJIZzBGZTd4cVdNRXV3amx3RFVQTGdBbnZRV0g3U2FKTlhMc1Y3RDZ4UWsxVE5wblM5ZE56Y045Z1FYSzJ3SzFBZnE4N1R1dzVDU3VYMjRpQVJZcERmVUcyV1NSTk1iWjlrdXlYOEU5d2FRcGhRb3NLQkphQlNHSUF6WWRUa3RORUhVMUI5YWppWk1kaGlyMTQ2YXF1VzhVQUxVTy9XNXFDWHRYSWNzU1NnVG40U3pWQlFENVgzWTJlQTZMVlJURCtLRHJ1TGVsQUNZUGhGanh4ZXBVbXM4RlRESzBlMVVJQ1M4TG5uQ3VLQ21naTVmVHIyQnFGUWVlQXpYZUt6bm0yeURjUk0raVJIVFZDbGFXbzdGRll1ZWN2cjR2SnZUTEVQVUN0YU52RWc2OXp1Z0U1L2VnMWx3VkZRVThkUTZCUE1odlc0S1NWYVpKNmVpVkIrVkcxMzJ1QTZVbDhjY1NXMlh0QkVVSWRYQ0hPeDRJR3BnYU9QRW9TSm8rUlFPQmczTjBQMkNRaFY3eDl4R1lqYnlWRGJuNHVCSXNBa3ZTVlMwdnZxbmVVRlVCVC9WOGxMSU9DYkZpaWQ1NTE4ZlVGUUpkYzREbmxGUG1PcDgvSW5sK2RmSEZEWmpjVGdxWW5lZUl5K3F2ZVVpcHhOVUUwNnl1aEdqZ1FwR1ZsUCtVZm1SZ0ZRZmt6aFFKaHkxVVp2QlphS3BMYVdYRkNqV3Rsbmx2VnhGMVNjb2NiSkFsMFBVR3pFNk1QUDZMTTZsNVNCWDY3U2R2TlE4emlnS29HbGFIUkxmYXRUQW9QcjRsRGlxanN0WEtpZVVvZUhKbEFGUHlJU1VCY0pOTEl5cFd3TFBPK3kyWHJXM3UxUW5ucmt1TFRMY05PbGVieTZhdWhOZlZETm1OcXE1NlZ1R1ZWNU9KUkswcGF6VVBXZ1JFUEZkN0VEZDR6RUNkY3JPNFJRaXJqNmQrNEQ4VzQwQitkaHFzY3hnMUJHYnJiN1RPREZ2WDNqVjIwcGFidkNVS01vbXBPS2ZtTFlvQVpnb3ZkaUZaNVFzUlJkOVg5VzkybHA4UTVPQlZXMGJWRE1QaVY5eSthL3phMThZRC9panUrWlVER1BGdVRIbXRPOUR6djRYbzNBbnJwUTRwdHYzY1dCQjJBWUNiS0hSQTVxWUZCcFZJMDJqTGREY1duY3ZPZWEvTzRLVUdzWXNIZGhwdzB1VnBUNEVIMFhvc0ZRTndZMVFhbXRnd3VneU5Nd3MrK2Q1bEN0U01iaVFxamEzKzVhVGZ5MmVUUzVVQjEzRW5QVDVzcXFackJUaExkcDYyWlF0bEw3YzB3dHo0WHRkNHdwMXlDWXRGQ3JTWEJyaURjK3AwNHc0SnhnMzJaOFVNbFBiMktXWUs5UEs3UU1GMExPd214UTlyRnA2Tlgya0JqMWdmTlJob2ZNUDFESTdjSmRLNUlQbG9pNlJFeGppdEtXVUpKUEg3SzV4b1hqSEpQaFFMdDR5TGxyVTJWamNtVjBVMmhoY21WWUlLRVRpbmxaTjFJZjl6cVdqSTV1VFFldHIvV1B0eG9BWXhmZkFQMlF5Q3NFWmxCMVlteHBZMWdoQW95SXpKWWo2cGMyYlFldnJqeTZKaHN4OTArbzdFTnFiKy9EeXc0T2U1UldhRU5vWVdsdVMyVjVXQ0QrNS9mS0JQZmdNTjVXVDRpL1p0NjV2V3BKeTRSNDFGWm1VdEVjK1VCUEdRPT0iLCJpc1JlY2VpdmVyIjpmYWxzZSwiZGlzYWJsZVdlYlNvY2tldHMiOnRydWV9"
// capsule share "pGVTZXR1cFkRBJiAUMKIx9wUrC4bAGHNQuY/O+5Q8NG5OT2+vmajcF7lb2Y4clBkXHIOxh50AN6tc9TUUseYUA9pHja8Q6qZiM5+cTPBhjBQN2pqjWUUE5qnhh8RmXd0slCwZBXaOBsw247o/M02GoDVUNuFf6dZi
// /g4JIhr7LhZgR9QKh/HpxU5IB7ivQV+lCTwy1Cqb1zzzN/GKL6DdoBq+K/rUCSxAZ8j9C82wiqThznEBHJQka3QKlrdvUOAlSSLRdOMt1CdzA/TWCYWyru395HvlcQiUO8AiIjUkXqxX/01JXdX1E9Qy3LzWlgdRQEOyioL
// 2QuxN1BtEq6FuIWo/g/jtpQUhH1rUBwYS987duk7jNf3KhDjAclQg9NvrywX267epZzRyALL/FA95R3FtfeQvxOc6TdyqjvTUNMW+kHAjgUXy/0IN6Gz9wNQGDddlw/qwPYygXTT0IJoIVBVE5eeC0gUrkKlXvyose9RUJc
// ZgrIwLcmPX/TGObj0RytQuXRJwb+dlhoey2sRg/YFK1DnFZeYkiwytOOWQJQIQ6DVUPBcw+BcFaXtj8dXQFzCyRhQrTNG6bUGJkTOnaWSkRB/sVA/W3qNSf3wjvIx/prvsST6UFj1KMmfg9JqmYBntaS2ZddQSaFQRY
// +4XmpgF5yWtY8NSlCFsKga2EX4TCapS8mi4AH+UGC0kB8V/icd/5YbCqaXlGxQjh/bvAhLahryZC4g6WP6slAcGieSyHp8djFEL+01RPjMUIcwn8XJ2XmFMAiXvBCdwBRQGU2BWk+c21avxljqqVZKyVAhm2f6ZrcQEM
// xMuRPz9BagUBRqZy/WOnh2fgX7L2mHUztQStmu2cHqibAQAFpe4TVNslDNDuCrDYBLCQa/zJZQZ9txUIDAlE3Kfo0W9VvXBNIVU/NQE4JLTC3uiaIaTmoz71y8FVC5gxpPO1XeRjI6q3iNbx7XUFCfzMNz+tUISylJ3CN
// c/FZQyQciRvjN9DcrcCU8ovEh4lC4HVTGnR+9Qnt94BKtz8g8UDbAtVwWyeE/rilf0JgWPI1Qc5KhFxmqPh4rfw42lZH2UFBpEcOwQxzdoGZNrY2WM1kVUNWgMTGfCjSE56tUcFV8U6VQR2d2lR5zZQL71rUFDs51z1
// AEdP5VgwKcgvi1gcxmiMfXULIInTSzwz6U9PX808NtVnVQkNOAHGF7Zn0ALZtBNIy1pVDvj+K2Lu+6J4KgzSKCbdZaULY28jEr8T5EDq7bfgBsfuVQQNOy5mw4Mqi5GKkIiXkxIFCz7Qm/BuDqJa56bMa96bv+UAWrJnv
// nzdu3NlJVTi2DroxQY6fu/2VRg3ZlEiVo0QTfZVCsnJ8AAGJq1LQfit4NdhUYUB0E11rFjQ5DoY7G0tkUqn9QGdYEojduS2emOznUXw/A4FB6exdgKMHYrONFReXBdy/yUHbx/aBcdrw9wfYFfl3rSsNQhRleEECu3eHQk
// gjHIOISwVC0ZGcSRCDz3e3otZKK1jqQUNmRWosO2RLa5jRJ2U/mDXZQ3pz/9dbCCw9Xqblw7/nUhVDxVxoM/OUCk4h3K5MtalguUB1dWVR79qB0s5khaHzYJfdQ6C8sY6NS4GEwEnIJNHLjFlCFm6zQnpRSx4owfn
// MwG2WBUM5YuRe0SkDT7kMAIjQu6PBQxrq35vDv6U0kVXVKAZLKn1CAkFo9P0ZvOV4qjqT8Qc0kUOoT/htMY7Q0+11s6IefMy5QpsjcUwvYHBPqSJv8CnKVFFDakBUsQPTUaDelzJpcrRXoUIrzaseDQV7vGpYwS7
// COXANQ8uACe9BYftJok1cuxXsPrFCTVM2mdL103Nw32BBcrbArUB+rztO7DkJK5fbiIBFikN9QrKaNZvtfT51YRMzWR4tInlD6RZxbWDqEu4E2EE/+R6mhUH1qOJkx2GKvXjpqq5bxQAtQ79bmoJe1chyxJKBOfhLNU
// FDTmhfRRhZ/0oQX4vWMw9A3UKWyfLFTd9niW1SDqvu2lFVQgJLwuecK4oKaCLl9OvYGoVB54DNd4rOebbINxEz6JEdNUFH/uw+St9omhuCFFNECLU1Qz+E2tzmixHW5jGOg402BalBvqZLAZ7gy55qoPbOEjEYJUG
// MMIQz6EbSeOa/Ko3j7o+FQyjLcQhVOvi/Gd7qmPi2NgVA4GDc3Q/YJCFXvH3EZiNvJUKwxQIVi60polkQsY88W5NVQMhG6xg+y/Eh4wk6roX6BvlC4DTeTOTdg7Q+jjPg8ADp/UJUQ7zJs9FAohD7wMyeG00tQxZrc
// U5/8YJzw8ZUd5EFYpVB+TOFAmHLVRm8FloqktpZcUN5UuIOmBjCaShs8KjCn8z1QbMTow8/oszqXlIFfrtJ281DzOKAqgaVodEt9q1MCg+viUOKqOy1cqJ5Sh4cmUAU/IhJQFwk0sjKlbAs877LZetbe7VBv5ghah2Nvg
// ADHoqjEOuRfUKzcN8u19LbHpaHTMux8hY9Q9aBEQ8V3sQN3jMQJ1ys7hFANyTaDu+gfCIGNxf30d6lIULBSQYoPAVx2JEEVXAdwvTpQ0ZvqI4Gi+AwrIdHupZEBkVBYbzg7aZX8q5URgyBdWQBZUKn1ZqdPiI54FKHs
// VJ0irLRQkIqfANzx910SNEPhZDBH8VDGNKkJ9o3VY0qWasYNWYARUKOgvA9ki+FErgcrawaCUJ1Qaxiwd2GnDS5WlPgQfReiwVBw3//A1LT40qvCVvhMRaweUNSPhbCdIGeP+HkezF0o/SVQHXcSc9PmyqpmsFOEt
// 2nrZlATfg10iO1+Q5XJ0YPRhxj5UGTv3m423ZvoE9qiQsYzAoFQyU9vYpZgr08rtAwXQs7CbFD2sWno1faQGPWB81GGh8w/UMjtwl0rkg+WiLpETGOK0pZQnklROe7Kr1wYL3N+LW9yoJiAUErjdGoH5IqRBDkDNt+k9
// WFQIWwkKwDpEiTr3emAMEsswVDR7DHcGj2gBwQ2Hq9gGS9TUME2GDssPSfI+5nQy8j9mMpQHzNealWUnrMrdaTanv3a71AzllmFdLVJ5tXiqGKkgMYuUMmFw6/RUnyPwRJTuQy4F9dQvi+8n+ukweNH+JRS/YBk
// /1CBlDZ/Eb8ujfTp17w4mQFqUO+rTNGd9TmSLXPQv232amRQjgbTE98DNJg5r+v10o9wDVBUqDdCesJABwkJ7rj6ePYTUI481SNcEylgeti/qHDqwBdQLu8c0gipgzva/YoOuhntHFBQjc5X6LS0AkHTxKrpTd/DUPMfq
// RR2moK87Hu9vuOMsAhQquXaZ/zFNKYoQ7TO+ACQM1BAG1VqVJcbzBEa9c/yEpzSUPnzSEGeE0tOVFGAEjeel/FQFIwxqkWHhH6wQK64BWwnClAhh5+a70BHH22uER9Ej/f6UGR/1oOlZu0JZZ4kW48mpNRQ4Szl
// 3NO9Sijd2fiJke4cH1Deq3F7fI+nluPGkWpSxvkFUKcvnx42rasntMdZ8jcqyJtQqx1nObelJkJvnb9yaQvIClAu3yMnvBpNhyRAAxrrgjVpUK/JXeXdcwo5Xu1OddH4nwJQ27WBErHISg/Ngf0NTksc3lAJjTpV2nlyZSDCCH
// 2D/yF+UEUBhYx8w/B9VefmmrWNf79QWT7N0L2NMR53CHRo1SyGiVCM5cv/tQ6qLWF4aViE65CEUAMVPo2SqdoRXBWBF4K7p1BQQ8Cn8lnykyeSY49oI5oNiVCPLLUqn/BWUnHQOcsUQI9VUKnNnNbpW6CF2vv
// BAWMsvahQwFEXDerNk86wuK5WLILFTlB+m2n2noCkcPCp4DMKomrLUJLaOaKVJ5ms4nr6dFPBKZpQOUn0Cp+FoB62npC6WbQPnFCg1uL7iB1mFw4q96WdtJwcUBOFEO5X7HzbeaH9TICdwuZQjVEV7ojzcFjfJ
// nRjDwo+slBssjXMRpro/qhXCeRqK2GzUG6O4y8/aD5oxpWsnEroNnlQ6fmuepkmNp6tCneSSdMwdlDwQgEswEO/hTWRXgp1yQ5mUDbwhcATYTczGYKI5elYL2VQWt9TBbD5u/XMxp2mq5ZHjlDP0Bgkpm7aUwcd0
// gbAeKfbUN7kAcqHJ0tCsm/bCR/95AZQviOJb4b9zAjXykVpPIaO9VCTui/ts3n+uM5QY3RqV8QcUAuG3U3DNreByjySqtFKo09Q+zEOF3R82BrxQILgn1dPBVDcLOP5NLD+YxSFk07ONfcxUGXzTM3uMRmrukwjylzC1
// yNQ7dOHTPhuHVj1F9aE+m31sFBQDUcQaJ4nsGiBlWP/TvwwUIzOScxzpPZlHzYAYqmJhy1Qs0/AH+IB12MmXST1XcyaUVAQd0xRNWQ3T1ppiLfIZrNFUAqquInSjrBBRjEpnfWFX4xQCES5H7BLpDDY+9/v7z0PT1D
// H4uW1S5wvIHn566FlpC3sUJha0TrliKMzUCIzEeUOKsJQD24YN+R6xvtMInU0V6SWrlAU9lYY7oVcNVu9bhDAs+91UP45Z3Y2M3DWP4JdrCT6nbNQgbofdELSAk9oLM3bmwa/n1AUNfMCrxRkSwhyzHSZ+4UUUHUz
// rdfEAsdh+8us9U9mABZQscDVTEiCyYsNh7maUA4k/lDcg536LpriDXsMayJebrd1UCpNQdFTCWPlOKYSGTfqWBtQU0buohTGQDZhkvsTZaCu3VC0p9xe1UXm3EfRCwgiRNeUUPxUUAF3SZNWhYuMuQeVZL1QSp
// DXKL4+bK8YeVeUiGLVTFC0gOlrori8EyrTfts2YZUJUDNxRy3tg7MDzvewSoIBiItQbZZJE0xtn2S7JfwT3BpCmFCiwoEloFIYgDNh1OS00QdTUFLeHEoNUn99MP3HZIZgXWZQLMJ5CnoVz1uHFmAPC3kmfFAPlfdjZ4D
// otVFMP4oOu4t6UAJg+EWPHF6lSazwVMMrR7VQ0JoPnlYA8hxeCbppd05OFFBmcvktb5jrEyr31WDX0qLSUKVpajsUVi55y+vi8m9MsQ9QK1o28SDr3O6ATn96DWXBUVBTx1DoE8yG9bgpJVpknp6JUH5UbXfa4Dp
// SXxxxJbZe0ERQh1cIc7HggamBo48ShImj5FAKU2oFBKHYFoGDbHB7fcb5UNufi4EiwCS9JVLS++qd5QVQFP9XyUsg4JsWKJ3nnXx9QVAl1zgOeUU+Y6nz8ieX518cUNmNxOCpid54jL6q95SKnE1QTTrK6EaOBCkZW
// U/5R+ZGAVBgto3VSZ5G+err+MUlFFUmUKNa2WeW9XEXVJyhxskCXQ9QyE0Hgdcj8bki6GRIH/sqZFA4ChWk7hYuDhpynvs9wqirUGkvRBtBBh2xRPjqQLRxnUZQfPZcB3UCycY2X1CmLaMT1lCeeuS4tMtw06V5vLp
// q6E19UM2Y2qrnpW4ZVXk4lErSlrNQ9Wlg00K0DqHvRP8l9mNVR1CKuPp37gPxbjQH52GqxzGDUEZutvtM4MW9feNXbSlpu8JQoyiak4p+YtigBmCi92IVnlCxFF31f1b3aWnxDk4FVbRtUMw+JX3L5r/NrXxgP+KO75l
// QMY8W5Mea070PO/hejcCeulDim2/dxYEHYBgJsodEDmpgUGlUjTaMt0Nxady855r87gpQMoWmjjCohDb9k4nX1fwUolA3BjVBqa2DC6DI0zCz753mUK1IxuJCqNrf7lpN/LZ5NLlQ/x57AWLzjDlrZOa9qL3QrVC2UvtzT
// C3Phe13jCnXIJi0UKtJcGuINz6nTjDgnGDfZnxQBl/gMWCcxVYgNIyKtB6XRFB+uzrPZwm/r/TCuO+ChEr2UDZ7ysdEa0H9QI5nbEze7ftQkk8fsrnGheMck+FAu3jIuWtTZWNyZXRTaGFyZVggSamoxm0wCmLIwbm/kZp
// GhT1VUb4i6ZbLRoHPuxmCrrlmUHVibGljWCECjIjMliPqlzZtB6+uPLomGzH3T6jsQ2pv78PLDg57lFZoQ2hhaW5LZXlYIP7n98oE9+Aw3lZPiL9m3rm9aknLhHjUVmZS0Rz5QE8Z"
