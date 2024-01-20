# mpc-export-internal

## Usage

This repo can be used to sign a transaction for a DKLS Capsule wallet using a user share, the corresponding backup Capsule share, and the RLP encoded Keccak-256 hash in hex format of a transaction. To get the RLP encoded hash in hex format of a transaction, use a tool such as https://toolkit.klaytn.foundation/transaction/rlpEncode to get the RLP encoding of a transaction and then use a tool such as https://emn178.github.io/online-tools/keccak_256.html to get the Keccak-256 hash.

To get the user share, retrieve the recovery secret you saved when initially creating your wallet or retrieve the user share from a frontend where you have logged in with your Capsule wallet. It will be the string in the `signer` field of the wallet you'd like to sign with.

Retrieve the backup share contents by downloading the pdf `CapsuleBackupShare.pdf` from the backup kit email received during wallet creation and copying the contents of the `Capsule Backup Key` section.

To sign a transaction run:
```sh
go run main.go "contents of user share..." "contents of backup share..." "rlp encoded hash in hex..."
```

## Build

To build the binary and move it to the `mpc-export` repo (assuming the `mpc-export` repo is adjacent to the current directory) run the following:
```sh
go build -o mpcExportBinary && mv mpcExportBinary ../mpc-export
```
