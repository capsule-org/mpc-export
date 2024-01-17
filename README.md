# mpc-export-utils

## Usage

This repo can be used to sign a transaction for a Capsule wallet using a user share, the corresponding backup Capsule share, and the RLP encoded hash in hex format of a transaction.

To sign a transaction run:
```sh
go run main.go "contents of user share..." "contents of backup share..." "rlp encoded hash in hex..."
```
