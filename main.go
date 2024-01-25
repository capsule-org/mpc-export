package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"

	mpcsigner "github.com/capsule-org/go-sdk/signer"
)

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
