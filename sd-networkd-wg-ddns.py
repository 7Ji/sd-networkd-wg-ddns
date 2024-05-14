import pathlib
from enum import Enum
from typing import Self
import sys
import subprocess
import socket

class WireGuardPeer:
    PublicKey: str
    EndpointHost: str
    EndpointPort: int
    LatestHandshake: int

    def __init__(self, pubkey: str, host: str, port: int, handshake: int):
        self.PublicKey = pubkey
        self.EndpointHost = host
        self.EndpointPort = port
        self.LatestHandshake = handshake

    def get_key(self) -> str:
        return self.PublicKey

class WireGuardNetDevParsingState(Enum):
    Initial = 1
    NetDevSection = 2
    WireGuardPeerSection = 3
    OtherSection = 4

class WireGuardNetDev:
    Name: str
    WireGuardPeers: list[WireGuardPeer]

    def __init__(self, name: str, peers: list[WireGuardPeer]):
        self.Name = name
        self.WireGuardPeers = peers

    @classmethod
    def from_file(cls, path) -> Self:
        with open(path, "rb") as f:
            buffer: bytes = f.read()
        parsing_state = WireGuardNetDevParsingState.Initial
        netdev = WireGuardNetDev("", [])
        for line in buffer.splitlines():
            line = line.strip()
            if len(line) == 0 or line.startswith(b'#'):
                continue
            if line.startswith(b'['):
                if not line.endswith(b']'):
                    raise Exception("Section title not ended")
                match line[1:-1]:
                    case b"NetDev":
                        parsing_state = WireGuardNetDevParsingState.NetDevSection
                    case b"WireGuardPeer":
                        netdev.WireGuardPeers.append(WireGuardPeer("", "", 0, 0))
                        parsing_state = WireGuardNetDevParsingState.WireGuardPeerSection
                    case _:
                        parsing_state = WireGuardNetDevParsingState.OtherSection
                        pass
            else:
                match parsing_state:
                    case WireGuardNetDevParsingState.NetDevSection:
                        (key, value) = line.split(b'=', 1)
                        match key:
                            case b"Name":
                                netdev.Name = value.decode("utf-8")
                            case b"Kind":
                                if value != b"wireguard":
                                    raise Exception("Non-wireguard device")
                            case _:
                                pass
                    case WireGuardNetDevParsingState.WireGuardPeerSection:
                        (key, value) = line.split(b'=', 1)
                        match key:
                            case b"PublicKey":
                                netdev.WireGuardPeers[-1].PublicKey = value.decode("utf-8")
                            case b"Endpoint":
                                (host, port) = value.rsplit(b':', 1)
                                if host.startswith(b'[') and host.endswith(b']'):
                                    host = host[1:-1]
                                netdev.WireGuardPeers[-1].EndpointHost = host.decode("utf-8")
                                netdev.WireGuardPeers[-1].EndpointPort = int(port)
                    case _:
                        pass
        return netdev
    
    def report(self):
        print(f"Name: {self.Name}")
        for peer in self.WireGuardPeers:
            print("Peer:")
            print(f" - PublicKey: {peer.PublicKey}")
            print(f" - EndpointHost: {peer.EndpointHost}")
            print(f" - EndpointPort: {peer.EndpointPort}")

    @classmethod
    def from_interface(cls, interface: str) -> Self:
        r1 = subprocess.run(("wg", "show", interface, "endpoints"), stdout = subprocess.PIPE, check = True)
        r2 = subprocess.run(("wg", "show", interface, "latest-handshakes"), stdout = subprocess.PIPE, check = True)
        peers: list[WireGuardPeer] = []
        for (line1, line2) in zip(r1.stdout.splitlines(), r2.stdout.splitlines()):
            (key1, endpoint) = line1.split(b'\t', 1)
            (key2, latest_handshake) = line2.split(b'\t', 1)
            if key1 != key2:
                raise Exception("Different key from wg-show")
            (host, port) = endpoint.rsplit(b':', 1)
            if host.startswith(b'[') and host.endswith(b']'):
                host = host[1:-1]
            peers.append(WireGuardPeer(key1.decode("utf-8"), host.decode("utf-8"), int(port), int(latest_handshake)))

        return WireGuardNetDev(interface, peers)

    def sort_peers(self):
        self.WireGuardPeers.sort(key = WireGuardPeer.get_key)


def is_ip_address(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False

def update(name: str, netdev_peers: list[WireGuardPeer], interface_peers: list[WireGuardPeer]):
    for (netdev_peer, interface_peer) in zip(netdev_peers, interface_peers):
        if netdev_peer.PublicKey != interface_peer.PublicKey:
            raise Exception("Different pubkeys")
        if netdev_peer.EndpointHost == interface_peer.EndpointHost:
            continue
        print(f"Maybe different: config host '{netdev_peer.EndpointHost}', interface host '{interface_peer.EndpointHost}'")
        addresses = socket.getaddrinfo(netdev_peer.EndpointHost, netdev_peer.EndpointPort)
        address = addresses[0]
        host = address[4][0]
        if host == interface_peer.EndpointHost:
            print("Resolved to same host, no need to update")
            continue
        port = address[4][1]
        match address[0]:
            case socket.AddressFamily.AF_INET:
                endpoint = f"{host}:{port}"
            case socket.AddressFamily.AF_INET6:
                endpoint = f"[{host}]:{port}"
            case _:
                raise Exception("Non v4 or v6 address")
        print(f"Different: config host '{host}' port {netdev_peer.EndpointPort}, interface host '{interface_peer.EndpointHost}' port {interface_peer.EndpointPort}, updating")
        subprocess.run(("wg", "set", name, "peer", netdev_peer.PublicKey, "endpoint", endpoint), check = True)

if __name__ == "__main__":
    netdev = WireGuardNetDev.from_file(sys.argv[1])
    netdev.sort_peers()
    interface = WireGuardNetDev.from_interface(netdev.Name)
    interface.sort_peers()
    update(netdev.Name, netdev.WireGuardPeers, interface.WireGuardPeers)


