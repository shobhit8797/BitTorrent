import hashlib
import json
import math
import socket
import sys
from time import sleep

import bencodepy
import requests


class Bencode:
    def _decode(self, data):
        if data.startswith(b"i"):
            return extract_integer(data)
        if data[0:1].isdigit():
            return extract_string(data)
        if data.startswith(b"l"):
            data = data[1:]
            result = []
            while not data.startswith(b"e"):
                value, data = self._decode(data)
                result.append(value)
            return result, data[1:]
        if data.startswith(b"d"):
            data = data[1:]
            result = {}
            while not data.startswith(b"e"):
                key, data = self._decode(data)
                value, data = self._decode(data)
                result[key.decode()] = value
            return result, data[1:]

    def decode(self, bencoded_value):
        decoded_value, _ = self._decode(bencoded_value)
        return decoded_value

    def encode(self, data):
        return bencodepy.encode(data)


def discover_peers(torrent_file) -> list:
    decoded_data = get_torrent_file_info(torrent_file)
    tracker_url = decoded_data["announce"].decode()

    response = requests.get(
        tracker_url,
        params={
            "info_hash": hashlib.sha1(bencodepy.encode(decoded_data["info"])).digest(),
            "peer_id": "00112233445566778899",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": decoded_data["info"]["length"],
            "compact": 1,
        },
    )
    decoded_response = Bencode().decode(response.content)

    peers = []
    for peer_ip in range(0, len(decoded_response["peers"]), 6):
        ip = ".".join(str(decoded_response["peers"][peer_ip + i]) for i in range(4))
        port = (
            decoded_response["peers"][peer_ip + 4] << 8
            | decoded_response["peers"][peer_ip + 5]
        )
        peers.append(f"{ip}:{port}")

    return peers


def get_torrent_file_info(torrent_file):
    with open(torrent_file, "rb") as f:
        encoded_data = f.read()
    decoded_data = Bencode().decode(encoded_data)
    return decoded_data


def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")


def extract_string(data):
    """
    Extract length and String component from a bencoded string
    """
    length, string = data.split(b":", 1)
    length = int(length)
    return string[:length], string[length:]


def extract_integer(data):
    """
    Extract integer component from a bencoded integer
    """
    end = data.index(b"e")
    return int(data[1:end]), data[end + 1 :]


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(Bencode().decode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        torrent_file = sys.argv[2]
        decoded_data = get_torrent_file_info(torrent_file)
        print(f"Tracker URL: {decoded_data['announce'].decode()}")
        print(f"Length: {decoded_data['info']['length']}")
        print(
            f"Info Hash: {hashlib.sha1(Bencode().encode(decoded_data['info'])).hexdigest()}"
        )
        print(f"Piece Length: {decoded_data['info']['piece length']}")
        print(f"Piece Hashes:")
        for piece_index in range(0, len(decoded_data["info"]["pieces"]), 20):
            print(decoded_data["info"]["pieces"][piece_index : piece_index + 20].hex())
    elif command == "peers":
        torrent_file = sys.argv[2]
        peers = discover_peers(torrent_file)

        [print(peer) for peer in peers]

    elif command == "handshake":
        torrent_file = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")

        decoded_data = get_torrent_file_info(torrent_file)
        info_hash = hashlib.sha1(Bencode().encode(decoded_data["info"])).digest()

        handshake_message = (
            chr(19).encode()
            + b"BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
            + info_hash
            + "12345678901234567890".encode()
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((ip, int(port)))
            client.send(handshake_message)

            reply = client.recv(68)
            print("Peer ID:", reply[48:].hex())

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
