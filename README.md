# FilterTap

A lightweight WFP (Windows Filtering Platform) kernel driver that captures network metadata at L2: local interface MAC, gateway MAC, and DNS queries.

## What it does

The driver registers two WFP callout filters at the Ethernet frame layer (`FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET` and outbound), receiving every L2 frame. It extracts:

- **Local NIC MAC** — from the source MAC of the first outbound IPv4 frame to a public address
- **Local NIC IP** — from the same packet's IPv4 source field
- **Gateway MAC** — from the destination MAC of that frame (the L2 next hop for public traffic)
- **DNS queries** — hostname lookups (A/AAAA/MX/etc.), logged as they pass

Once local + gateway MAC are captured, it prints both and stops inspecting.

## Output

```
FilterTap LOCAL   AA:BB:CC:DD:EE:FF  192.168.1.100
FilterTap ROUTER  11:22:33:44:55:66
FilterTap DNS Q type=1 example.com
FilterTap DNS Q type=1 google.com
```

Visible in DbgView (Capture Kernel enabled, filter `IHVDRIVER`).

## How EAC uses this

EAC installs filters identical to this driver to obtain a machine's hardware ID (HWID). Retrieving the MAC via WFP sidesteps user-mode API-level spoofing (IOCTL paths, `NsiGetAllParametersEx`) because it reads directly from frames traversing the network stack at kernel layer. The MAC is stable per NIC and difficult to forge without driver-level intervention.

DNS visibility is a side effect of L2 inspection: DNS queries are visible in plaintext until encrypted (DoH/DoT), so a comprehensive frame tap sees all non-encrypted lookups.

## Build

```
cmake --preset default
cmake --build --preset default
```

Requires Windows Driver Kit (WDK 10.0.x). The CMake will test-sign the binary on first build using a self-signed cert.

## Load

Elevated, unsigned driver load (requires test-signing or a valid cert):

```powershell
# Enable test-signing mode (one-time)
Bcdedit.exe /set testsigning on
# Restart required

# Load driver
sc create FilterTap binPath= "C:\path\to\NetworkFilter.sys"
sc start FilterTap

# Generate traffic to trigger capture
ping 8.8.8.8
curl https://example.com

# View output in DbgView
```

Unload:

```powershell
sc stop FilterTap
sc delete FilterTap
```

## Security & Privacy

This driver (and EAC's version) has full visibility into all network frames passing through your interface for the duration it's active. While this one only logs MAC and DNS, the capability to read payloads is present. For encrypted traffic (HTTPS, VPN) the payload is ciphertext; DNS-over-TLS or DoH hides queries. Unencrypted protocols (HTTP, IMAP without TLS, etc.) are fully visible.

Running anti-cheat drivers is a choice to make informed about. This driver documents what's technically happening at L2.
