import hashlib
import json
import socket
import struct
import sys

import bencodepy
import requests
from urllib.parse import unquote


def discover_peers(torrent_file) -> list:
    torrent = Torrent(torrent_file)
    decoded_data = torrent.decode_file()
    tracker_url = decoded_data["announce"].decode()

    response = requests.get(
        tracker_url,
        params={
            "info_hash": torrent.get_info_hash(),
            "peer_id": "00112233445566778899",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": decoded_data["info"]["length"],
            "compact": 1,
        },
    )
    response.raise_for_status()  # Raise an error for bad responses
    decoded_response = Bencode().decode(response.content)

    peers = []
    for peer_ip in range(0, len(decoded_response["peers"]), 6):
        ip = ".".join(str(decoded_response["peers"][peer_ip + i]) for i in range(4))
        port = struct.unpack(
            ">H", decoded_response["peers"][peer_ip + 4 : peer_ip + 6]
        )[0]
        peers.append(f"{ip}:{port}")

    return peers


def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")


def get_peer_id(client_socket, ip, port, info_hash):
    handshake_message = (
        b"\x13BitTorrent protocol" + b"\x00" * 8 + info_hash + b"12345678901234567890"
    )
    client_socket.connect((ip, int(port)))
    client_socket.send(handshake_message)

    reply = client_socket.recv(68)  # Receive handshake response
    return reply[48:].hex()  # Peer ID is the last 20 bytes


def read_peer_message(client_socket: socket.socket) -> tuple[int, bytes]:
    # Read the message length
    message_length = struct.unpack(">I", client_socket.recv(4))[0]
    message_id = int(client_socket.recv(1)[0])

    # Initialize an empty byte array to store the payload
    payload = b""
    bytes_remaining = message_length - 1

    # Keep receiving data until we have received the full payload
    while bytes_remaining > 0:
        chunk = client_socket.recv(bytes_remaining)
        if not chunk:
            raise ConnectionError("Connection lost while receiving payload")
        payload += chunk
        bytes_remaining -= len(chunk)

    return message_id, payload


def send_request(
    client_socket: socket.socket, index: int, begin: int, length: int
) -> None:
    """Send a request message for a block of data."""
    request_msg = struct.pack(
        ">BIII", 6, index, begin, length
    )  # Message ID = 6 is 'request'
    client_socket.sendall(struct.pack(">I", len(request_msg)) + request_msg)


class Bencode:
    def decode(self, bencoded_value: bytes) -> int | str | list | dict:
        decoded_value, _ = self._decode(bencoded_value)
        return decoded_value

    def _decode(self, data: bytes) -> tuple:
        if data.startswith(b"i"):
            return self._extract_integer(data)
        elif chr(data[0]).isdigit():
            return self._extract_string(data)
        elif data.startswith(b"l"):
            return self._extract_list(data)
        elif data.startswith(b"d"):
            return self._extract_dict(data)
        raise ValueError("Invalid bencoded data")

    def _extract_string(self, data: bytes) -> tuple[bytes, bytes]:
        length, string = data.split(b":", 1)
        length = int(length)
        return string[:length], string[length:]

    def _extract_integer(self, data: bytes) -> tuple[int, bytes]:
        end = data.index(b"e")
        return int(data[1:end]), data[end + 1 :]

    def _extract_list(self, data: bytes) -> tuple[list, bytes]:
        data = data[1:]
        result = []
        while not data.startswith(b"e"):
            value, data = self._decode(data)
            result.append(value)
        return result, data[1:]

    def _extract_dict(self, data: bytes) -> tuple[dict, bytes]:
        data = data[1:]
        result = {}
        while not data.startswith(b"e"):
            key, data = self._decode(data)
            value, data = self._decode(data)
            result[key.decode()] = value
        return result, data[1:]


class Torrent:
    BLOCK_SIZE = 2**14  # 16 KiB blocks

    def __init__(self, torrent_fie: str) -> None:
        self.socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.torrent_file = torrent_fie
        self.decoded_data = self.decode_file()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.socket.close()

    def decode_file(self) -> dict:
        with open(self.torrent_file, "rb") as f:
            encoded_data = f.read()
        return Bencode().decode(encoded_data)

    def get_info_hash(self) -> bytes:
        return hashlib.sha1(bencodepy.encode(self.decoded_data["info"])).digest()

    def get_peers_list(self) -> list:
        self.peers_list: list = discover_peers(self.torrent_file)
        return self.peers_list

    def get_first_peer_info(self) -> tuple[str, str]:
        self.get_peers_list()
        ip, port = self.peers_list[0].split(":")
        return ip, port

    def get_piece_data_from_peer(self, piece_index, piece_length):
        """Download an entire piece by requesting blocks of 16 KiB."""
        blocks = []

        no_of_blocks = (piece_length) // self.BLOCK_SIZE
        print(f"Number of blocks: {no_of_blocks}")

        for i in range(no_of_blocks):
            send_request(self.socket, piece_index, i * self.BLOCK_SIZE, self.BLOCK_SIZE)
            print(
                f"Requested block {i} of piece {piece_index}, length {self.BLOCK_SIZE}"
            )

            message_id, payload = read_peer_message(self.socket)
            while message_id != 7:
                message_id, payload = read_peer_message(self.socket)

            block_data = payload[8:]
            blocks.append(block_data)

        if piece_length % self.BLOCK_SIZE:
            i += 1
            send_request(
                self.socket,
                piece_index,
                i * self.BLOCK_SIZE,
                (piece_length - (i * self.BLOCK_SIZE)),
            )
            print(
                f"Requested block {i} of piece {piece_index}, length {(piece_length - (i * self.BLOCK_SIZE))}"
            )

            message_id, payload = read_peer_message(self.socket)
            assert message_id == 7

            block_data = payload[8:]
            blocks.append(block_data)

        return b"".join(blocks)

    def download_piece(self, piece_index: int, output_file: str) -> None:
        ip, port = self.get_first_peer_info()
        peer_id = get_peer_id(self.socket, ip, port, self.get_info_hash())

        # Wait for the bitfield message (message ID = 5)
        message_id, _ = read_peer_message(self.socket)
        while message_id != 5:
            message_id, _ = read_peer_message(self.socket)

        # Send interested message (message ID = 2)
        self.socket.sendall(struct.pack(">IB", 1, 2))

        # Wait for unchoke message (message ID = 1)
        message_id, _ = read_peer_message(self.socket)
        while message_id != 1:
            message_id, _ = read_peer_message(self.socket)

        piece_length = self.decoded_data["info"]["piece length"]
        file_length = self.decoded_data["info"]["length"]

        # Adjust for the last piece if necessary
        total_pieces = (file_length + piece_length - 1) // piece_length

        if piece_index == total_pieces - 1:
            piece_length = file_length % piece_length
            print(f"Last piece length: {piece_length}")
            if piece_length == 0:
                piece_length = self.decoded_data["info"]["piece length"]

        # Download the piece
        piece_data = self.get_piece_data_from_peer(piece_index, piece_length)

        # Write the downloaded piece to the output file
        with open(output_file, "wb") as f:
            f.write(piece_data)

    def download_file(self, torrent_file, output_file):
        decoded_data = self.get_info()
        file_length = decoded_data["info"]["length"]
        piece_length = decoded_data["info"]["piece length"]
        total_pieces = (file_length + piece_length - 1) // piece_length
        pieces_hashes = [
            decoded_data["info"]["pieces"][i : i + 20]
            for i in range(0, len(decoded_data["info"]["pieces"]), 20)
        ]
        print(
            f"File Length: {file_length}, Piece Length: {piece_length}, Total Pieces: {total_pieces}"
        )

        # Discover peers
        peers = discover_peers(torrent_file)
        if not peers:
            print("No peers found.")
            return

        print(f"Found {len(peers)} peers. Connecting to the first one...")

        # Connect to the first available peer
        peer_ip, peer_port = peers[0].split(":")

        info_hash = hashlib.sha1(bencodepy.encode(decoded_data["info"])).digest()
        peer_id = get_peer_id(self.socket, peer_ip, peer_port, info_hash)

        print(f"Connected to peer {peer_ip}:{peer_port}, Peer ID: {peer_id}")

        # Wait for the bitfield message (message ID = 5)
        message_id, _ = read_peer_message(self.socket)
        while message_id != 5:
            message_id, _ = read_peer_message(self.socket)

        # Send interested message (message ID = 2)
        self.socket.sendall(struct.pack(">IB", 1, 2))

        # Wait for unchoke message (message ID = 1)
        message_id, _ = read_peer_message(self.socket)
        while message_id != 1:
            message_id, _ = read_peer_message(self.socket)

        # Open the output file in write mode
        with open(output_file, "wb") as f:
            # Loop through each piece index
            for piece_index in range(total_pieces):
                # Calculate piece length (handle last piece separately)
                if piece_index == total_pieces - 1:
                    piece_length = file_length % decoded_data["info"]["piece length"]
                    if piece_length == 0:
                        piece_length = decoded_data["info"]["piece length"]

                # Download the piece
                piece_data = self.get_piece_data_from_peer(piece_index, piece_length)

                # Verify piece integrity
                piece_hash = hashlib.sha1(piece_data).digest()
                if piece_hash != pieces_hashes[piece_index]:
                    print(f"Piece {piece_index} hash mismatch. Re-trying...")
                    continue  # Re-download the piece if the hash doesn't match

                # Write the piece to the output file
                f.write(piece_data)
                print(f"Piece {piece_index} downloaded and verified.")

        print(f"File downloaded successfully to {output_file}")


class MagnetLink:
    def __init__(self, magnet_link: str) -> None:
        self.magnet_link = magnet_link

    def get_params(self, query_string: str) -> dict:
        queries = query_string.split("&")

        query_dict = {}
        for query in queries:
            key, value = query.split("=")
            query_dict[key] = value

        return query_dict

    def parse(self) -> dict:
        _, query_string = self.magnet_link.split("?", 1)

        query_dict = self.get_params(query_string)
        query_dict["Info Hash"] = query_dict["xt"][9:]
        query_dict["Tracker URL"] = unquote(query_dict["tr"])

        return query_dict


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(Bencode().decode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        torrent_file = sys.argv[2]

        torrent = Torrent(torrent_file)
        decoded_data = torrent.decode_file()
        print(f"Tracker URL: {decoded_data['announce'].decode()}")
        print(f"Length: {decoded_data['info']['length']}")
        print(f"Info Hash: {torrent.get_info_hash()}")
        print(f"Piece Length: {decoded_data['info']['piece length']}")
        print("Piece Hashes:")
        for piece_index in range(0, len(decoded_data["info"]["pieces"]), 20):
            print(decoded_data["info"]["pieces"][piece_index : piece_index + 20].hex())
    elif command == "peers":
        torrent_file = sys.argv[2]
        peers = discover_peers(torrent_file)
        print(*peers, sep="\n")
    elif command == "handshake":
        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        torrent_file = sys.argv[2]
        ip, port = sys.argv[3].split(":")

        info_hash = Torrent(torrent_file).get_info_hash()
        peer_id = get_peer_id(_socket, ip, port, info_hash)

        print("Peer ID:", peer_id)
    elif command == "download_piece":
        _ = sys.argv[2]
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        piece_index = int(sys.argv[5])

        Torrent(torrent_file).download_piece(piece_index, output_file)
    elif command == "download":
        _ = sys.argv[2]
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]

        Torrent(torrent_file).download_file(torrent_file, output_file)
    elif command == "magnet_parse":
        magnet_link = sys.argv[2]

        query_dict = MagnetLink(magnet_link).parse()
        print(f"Tracker URL: {query_dict['Tracker URL']}")
        print(f"Info Hash: {query_dict['Info Hash']}")

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
