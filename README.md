# chuni-c2c-dumper

A utility to help you debug your cabinet-to-cabinet play.

## Features

- Based on pcap, no interference with game playing
- Work on both data link layer (physical or TAP devices) and network layer (TUN devices)
- Decode as much information
- Zero configuration (see below)

## Installation

- Windows: Install [Npcap](https://npcap.com/#download) in WinPcap API-compatible mode (in Installation Options). Download [prebuilt binary](https://github.com/AsakuraMizu/chuni-c2c-dumper/releases) and run.
- Linux: Install libpcap. Run the code from source.
- MacOS: No additional libraries required.

## Usage

```
Usage: chuni-c2c-dumper [OPTIONS]

Options:
  -l, --list             List available network interfaces
  -f, --file <FILE>      Pcap file to read from
  -d, --device <DEVICE>  Network interface to capture
      --dump <DUMP>      Dump decrypted packets to
  -h, --help             Print help
  -V, --version          Print version
```

Note that `--list`, `--file` and `--device` are mutually exclusive, and if you don't specify any of them, the program will try to find a network interface with ip address under `192.168.139.0/24`.

**Reminder:** It cannot replace regular network analyzer like Wireshark. It only decrypts and shows UDP packets with destination port 50200. In case of cab-to-cab failure, you'd better use both Wireshark and this utility to debug.
