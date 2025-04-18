# NATS Wireshark Dissector

A Wireshark dissector for the NATS messaging system's client protocol. This dissector decodes and displays NATS protocol messages in a human-readable format within Wireshark.

## Features

- Decodes NATS client protocol messages (port 4222)
- Supports all standard NATS commands:
  - Basic commands (PUB, SUB, UNSUB, MSG)
  - Headers (HPUB, HMSG)
  - Queue groups
  - Auto-unsubscribe
  - JSON payloads
  - Protocol acknowledgments (+OK/-ERR)
- Displays detailed message information:
  - Command type and parameters
  - Subject names
  - Subscription IDs
  - Queue groups
  - Headers (for HPUB/HMSG)
  - Message payloads (with JSON parsing)
  - Error messages

## Installation

### Prerequisites

- Wireshark v4.4.6 or later
- Lua support enabled in Wireshark

### Installation Steps

1. Locate your Wireshark plugins directory:
   - Open Wireshark -> About Wireshark
   - Select the Folders tab
   - Look for the Personal Lua Plugins directory

2. Copy the `nats.lua` and `dkjson.lua` files to your plugins directory:
   ```bash
   cp nats.lua ~/.wireshark/plugins/
   cp dkjson.lua ~/.wireshark/plugins/
   ```

3. Restart Wireshark

### Verification

1. Open Wireshark
2. Go to Help -> About Wireshark -> Plugins
3. Look for "nats.lua" in the list of loaded plugins

## Usage

1. Start capturing NATS traffic:
   ```bash
   tcpdump -i any port 4222 -w nats_traffic.pcap
   ```

2. Open the capture file in Wireshark

3. The dissector will automatically decode NATS protocol messages on port 4222

4. You can filter NATS traffic using:
   ```
   nats
   ```

## Limitations

- This dissector only handles the NATS client protocol (port 4222)
- The NATS cluster protocol (port 6222) uses a different binary protocol and is not supported
- Some advanced NATS features may not be fully decoded

## Contributing

Feel free to submit issues and Pull Requests for enhancements and bug fixes

## License

This project is licensed under the MIT License - see the LICENSE file for details.
