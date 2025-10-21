def message_to_binary(message: str) -> str:
    encoded_bytes = message.encode('utf-8')

    binary_string = ''.join(format(byte, '08b') for byte in encoded_bytes)

    return binary_string


def binary_to_message(binary_str: str) -> str:
    if len(binary_str) % 8 != 0:
        pass

    byte_chunks = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]

    byte_data = bytes([int(chunk, 2) for chunk in byte_chunks])

    try:
        message = byte_data.decode('utf-8')
    except UnicodeDecodeError:
        message = byte_data.decode('utf-8', errors='replace')

    return message
