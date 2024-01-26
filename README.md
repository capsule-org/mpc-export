# mpc-export-internal

This repo can be used to export the private key for a DKLS Capsule wallet using a user share and the corresponding backup Capsule share.

## Setup

Before running this script, you'll need to have Go installed on your machine. If you don't yet have it, you can download it [here](https://go.dev/doc/install)

## Usage

Get the user share from one of these two locations:
  - The recovery secret you saved when initially creating your wallet.
  - A frontend where you have logged in with your Capsule wallet. It will be the string in the `signer` field of the wallet you'd like to sign with.

Retrieve the backup share contents by downloading the pdf `CapsuleBackupShare.pdf` from the backup kit email received during wallet creation (Subject: Welcome to Capsule Snap Account - Capsule Account Information) and copying the contents of the `Capsule Backup Key` section.

Note, you'll need to copy this information using a PDF Reader App such as Preview or Adobe Acrobat.

To export the private key run:
```sh
USER_SHARE = "contents of the user share"
CAPSULE_SHARE = "contents of the capsule share"
go run main.go $USER_SHARE $CAPSULE_SHARE
```

## Build

To build the binary and move it to the `mpc-export` repo (assuming the `mpc-export` repo is adjacent to the current directory) run the following:
```sh
go build -o mpcExportBinary && mv mpcExportBinary ../mpc-export
```
