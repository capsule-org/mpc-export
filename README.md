# mpc-export-internal

## Usage

This repo can be used to export the private key for a DKLS Capsule wallet using a user share and the corresponding backup Capsule share.

Get the user share from one of these two locations:
  - The recovery secret you saved when initially creating your wallet.
  - A frontend where you have logged in with your Capsule wallet. It will be the string in the `signer` field of the wallet you'd like to sign with.

Retrieve the backup share contents by downloading the pdf `CapsuleBackupShare.pdf` from the backup kit email received during wallet creation and copying the contents of the `Capsule Backup Key` section.

To export the private key run:
```sh
go run main.go "contents of user share..." "contents of backup share..."
```

## Build

To build the binary and move it to the `mpc-export` repo (assuming the `mpc-export` repo is adjacent to the current directory) run the following:
```sh
go build -o mpcExportBinary && mv mpcExportBinary ../mpc-export
```
