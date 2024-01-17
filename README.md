# mpc-export-utils

## Usage

This repo can be used to sign a transaction for a Capsule wallet using a user share, the corresponding backup Capsule share, and the RLP encoded hash in hex format of a transaction.

Retrieve the user share from a frontend where you have logged in with your Capsule wallet. It will be the string in the `signer` field of the wallet you'd like to sign with.

Retrieve the backup share contents by downloading the pdf `CapsuleBackupShare.pdf` from the backup kit email received during wallet creation and copying the contents of the `Capsule Backup Key` section.

To sign a transaction run:
```sh
go run main.go "contents of user share..." "contents of backup share..." "rlp encoded hash in hex..."
```
