import hashlib
import json
import socket
import struct
import sys

import bencodepy
import requests


class Bencode:
    def decode(self, bencoded_value):
        decoded_value, _ = self._decode(bencoded_value)
        return decoded_value

    def _decode(self, data):
        if data.startswith(b"i"):
            return self._extract_integer(data)
        elif chr(data[0]).isdigit():
            return self._extract_string(data)
        elif data.startswith(b"l"):
            return self._extract_list(data)
        elif data.startswith(b"d"):
            return self._extract_dict(data)
        raise ValueError("Invalid bencoded data")

    def _extract_string(self, data):
        length, string = data.split(b":", 1)
        length = int(length)
        return string[:length], string[length:]

    def _extract_integer(self, data):
        end = data.index(b"e")
        return int(data[1:end]), data[end + 1 :]

    def _extract_list(self, data):
        data = data[1:]
        result = []
        while not data.startswith(b"e"):
            value, data = self._decode(data)
            result.append(value)
        return result, data[1:]

    def _extract_dict(self, data):
        data = data[1:]
        result = {}
        while not data.startswith(b"e"):
            key, data = self._decode(data)
            value, data = self._decode(data)
            result[key.decode()] = value
        return result, data[1:]


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


def get_torrent_file_info(torrent_file):
    with open(torrent_file, "rb") as f:
        encoded_data = f.read()
    return Bencode().decode(encoded_data)


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


def read_peer_message(client_socket):
    message_length = struct.unpack(">I", client_socket.recv(4))[0]
    print(message_length)
    message_id = int(client_socket.recv(1)[0])
    payload = client_socket.recv(message_length - 1) if message_length > 1 else b""

    return message_id, payload


def send_request(client_socket, index, begin, length):
    """Send a request message for a block of data."""
    request_msg = struct.pack(
        ">BIII", 6, index, begin, length
    )  # Message ID = 6 is 'request'
    client_socket.sendall(struct.pack(">I", len(request_msg)) + request_msg)


def download_piece(client_socket, piece_index, piece_length):
    """Download an entire piece by requesting blocks of 16 KiB."""
    block_size = 2**14  # 16 KiB blocks
    blocks = []
    downloaded_length = 0

    # Calculate how many blocks are needed for the entire piece
    while downloaded_length < piece_length:
        block_offset = downloaded_length
        block_length = min(block_size, piece_length - downloaded_length)

        # Send request for a block within the piece
        send_request(client_socket, piece_index, block_offset, block_length)
        print(
            f"Requested block {block_offset} of piece {piece_index}, length {block_length}"
        )

        # Wait for a piece message (message ID = 7)
        message_id, payload = read_peer_message(client_socket)
        while message_id != 7:  # Waiting for 'piece' message
            message_id, payload = read_peer_message(client_socket)

        block_data = payload[8:]  # Skip the first 8 bytes (piece index + block offset)
        blocks.append(block_data)

        # Update how much data we've downloaded for this piece
        downloaded_length += len(block_data)

    return b"".join(blocks)  # Return the full piece data


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
            f"Info Hash: {hashlib.sha1(bencodepy.encode(decoded_data['info'])).hexdigest()}"
        )
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

        decoded_data = get_torrent_file_info(torrent_file)
        info_hash = hashlib.sha1(bencodepy.encode(decoded_data["info"])).digest()

        peer_id = get_peer_id(_socket, ip, port, info_hash)
        print("Peer ID:", peer_id)

    elif command == "download_piece":
        _ = sys.argv[2]
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        piece_index = int(sys.argv[5])

        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _socket.settimeout(10)  # 10-second timeout for socket operations

        decoded_data = get_torrent_file_info(torrent_file)

        peers_li = discover_peers(torrent_file)
        ip, port = peers_li[0].split(":")

        info_hash = hashlib.sha1(bencodepy.encode(decoded_data["info"])).digest()
        peer_id = get_peer_id(_socket, ip, port, info_hash)

        # Wait for the bitfield message (message ID = 5)
        message_id, _ = read_peer_message(_socket)
        while message_id != 5:
            message_id, _ = read_peer_message(_socket)

        # Send interested message (message ID = 2)
        _socket.sendall(struct.pack(">IB", 1, 2))

        # Wait for unchoke message (message ID = 1)
        message_id, _ = read_peer_message(_socket)
        while message_id != 1:
            message_id, _ = read_peer_message(_socket)

        piece_length = decoded_data["info"]["piece length"]
        file_length = decoded_data["info"]["length"]

        # Adjust for the last piece if necessary
        total_pieces = (file_length + piece_length - 1) // piece_length
        if piece_index == total_pieces - 1:
            piece_length = file_length % piece_length
            if piece_length == 0:
                piece_length = decoded_data["info"]["piece length"]

        # Download the piece
        piece_data = download_piece(_socket, piece_index, piece_length)

        # Write the downloaded piece to the output file
        with open(output_file, "wb") as f:
            f.write(piece_data)

        print(f"Piece {piece_index} downloaded successfully.")
        _socket.close()

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
