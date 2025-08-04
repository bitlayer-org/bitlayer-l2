# Bitlayer Overview

[Bitlayer](https://www.bitlayer.org) is the first Bitcoin security-equivalent layer 2 based on BitVM. It consists of an EVM compatible chain/sequencer (bitlayer-l2) that can map BTC ecological assets and facilitate the entry of BTC users. Bitlayer-l2 is a fork of [geth](https://github.com/ethereum/go-ethereum).

## Why Bitlayer?
Due to the technical nature of Bitcoin, there exists a trade-off between "Security and Turing completeness" for Bitcoin layer 2 solutions.

Bitlayer aims to resolve this dilemma and realize a Bitcoin layer 2 that is equally secure as Bitcoin and Turing complete through cryptographic innovations and blockchain protocol engineering. This is intended to ultimately foster a prosperous Bitcoin ecosystem.

## Technical Features
Bitlayer's core objective is to address the trade-off between security (trustless) and Turing completeness in BTC Layer 2. Based on this context, three key tasks are abstracted:

1. Trustless entry and exit of L1 assets
2. State transitions using a Turing-complete L2 virtual machine
3. L1 verification of the validity of L2 state transitions

### Key Components:
- Utilization of DLC/LN protocol for trustless bidirectional flow of signals/assets
- Support for various VMs (EVM, SolanaVM, MoveVM)
- Optimistic rollup for scalability

## Architecture

![arch](./architecture.png)

Bitlayer follows the typical model of an Optimistic Rollup.

## Roadmap

![roadmap](./roadmap.png)

Bitlayer-l2 is the geth client in MAINNET-V1.

## Building the source

Building `geth` requires both a Go (version 1.21 or later) and a C compiler. After installing the dependencies, run:

```shell
make geth
```

To build the full suite of utilities:

```shell
make all
```

## System Requirements
- OS: Linux, macOS, Windows
- RAM: Minimum 8GB
- CPU: 4+ cores
- Storage: SSD with minimum 100GB free space

## Documentation

The official documentation for Bitlayer can be found [here](https://docs.bitlayer.org). It contains all the conceptual and architectural details of the chain along with operational guides for users running the nodes.

## License

The go-ethereum library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html).

The go-ethereum binaries (i.e. all code inside of the `cmd` directory) are licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Social Media & Contacts

- 🌐 Website: <https://bitlayer.org>
- 🐦 X (Twitter): <https://x.com/BitlayerLabs>
- 📝 Medium: <https://medium.com/@Bitlayer>
- 📧 Email: <build@bitlayer.org>
- 💻 GitHub: <https://github.com/bitlayer-org>

## Join Our Community
- [Discord](https://discord.gg/bitlayer)
- [Telegram](https://t.me/bitlayer)
