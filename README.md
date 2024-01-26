# mpc-export

This repo can be used to export the private key for a DKLS Capsule wallet using a user share and the corresponding backup Capsule share.

## Setup

Before running this script, you'll need to have Go installed on your machine. If you don't yet have it, you can download it [here](https://go.dev/doc/install)

## Usage

Get the user share from one of these two locations:
  - The recovery secret you saved when initially creating your wallet.
  - A frontend where you have logged in with your Capsule wallet. It will be the string in the `signer` field of the wallet you'd like to sign with.

<img width="438" alt="image" src="https://github.com/capsule-org/mpc-export/assets/2686353/9b9357f2-f2e9-4592-88ff-c5a3972de872">

Retrieve the backup share contents by downloading the pdf `CapsuleBackupShare.pdf` from the backup kit email received during wallet creation (Subject: Welcome to Capsule Snap Account - Capsule Account Information) and copying the contents of the `Capsule Backup Key` section.

<img width="388" alt="image" src="https://github.com/capsule-org/mpc-export/assets/2686353/7a349461-5bc6-4976-a007-05f111f5d9da">

**Note:** You'll need to copy this information using a PDF Reader App such as Preview or Adobe Acrobat.

To export the private key run:
```sh
USER_SHARE = "contents of the user share"
CAPSULE_SHARE = "contents of the capsule share"
go run main.go $USER_SHARE $CAPSULE_SHARE
```
