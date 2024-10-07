import json
import sys
import hashlib
import bencodepy
# import requests - available if you need it!


# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def extract_string(data):
    length, string = data.split(b":", 1)
    length = int(length)
    return string[:length], string[length:]


def extract_integer(data):
    end = data.index(b"e")
    return int(data[1:end]), data[end + 1 :]


def decode(data):
    if data.startswith(b"i"):
        return extract_integer(data)
    if chr(data[0]).isdigit():
        return extract_string(data)
    if data.startswith(b"l"):
        data = data[1:]
        result = []
        while not data.startswith(b"e"):
            value, data = decode(data)
            result.append(value)
        return result, data[1:]
    if data.startswith(b"d"):
        data = data[1:]
        result = {}
        while not data.startswith(b"e"):
            key, data = decode(data)
            value, data = decode(data)
            result[key.decode()] = value
        return result, data[1:]


def decode_bencode(bencoded_value):
    decoded_value, _ = decode(bencoded_value)
    return decoded_value
    # if chr(bencoded_value[0]).isdigit():
    #     first_colon_index = bencoded_value.find(b":")
    #     if first_colon_index == -1:
    #         raise ValueError("Invalid encoded value")
    #     return bencoded_value[first_colon_index+1:]
    # elif chr(bencoded_value[0]) == "i" and chr(bencoded_value[-1] == "e"):
    #     return int(bencoded_value[1:-1])
    # else:
    #     return bencodepy.decode(bencoded_value)


def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()

    raise TypeError(f"Type not serializable: {type(data)}")


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        torrent_file = sys.argv[2]
        with open(torrent_file, "rb") as f:
            encoded_data = f.read()
        decoded_data = decode_bencode(encoded_data)
        print(decoded_data)
        print(f"Tracker URL: {decoded_data['announce'].decode()}")
        print(f"Length: {decoded_data['info']['length']}")
        print(f"Info Hash: {hashlib.sha1(bencodepy.encode(decoded_data['info'])).hexdigest()}")
        print(f"Piece Length: {decoded_data['info']['piece length']}")
        print(f"Piece Hashes:")
        for piece_index in range(0, len(decoded_data['info']['pieces']), 20):
            print(decoded_data['info']['pieces'][piece_index: piece_index+20].hex())

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
