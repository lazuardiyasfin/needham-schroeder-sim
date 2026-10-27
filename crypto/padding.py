def pkcs7_pad(data, block_size):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    if not isinstance(block_size, int):
        raise TypeError("Block size must be an integer")

    padding = block_size - (len(data) % block_size)

    return data + bytes([padding] * padding)

def pkcs7_unpad(data, block_size):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    if not isinstance(block_size, int):
        raise TypeError("Block size must be an integer")

    pad_length = data[-1]
    if pad_length < 1 or pad_length > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_length:] != bytes([pad_length] * pad_length):
        raise ValueError("Invalid padding bytes")
    
    return data[:-pad_length]