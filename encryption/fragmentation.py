import base64

def fragment_message(message, max_length=160):
    """
    Splits a long message into fragments to fit within the SMS character limit.
    Each fragment includes a sequence header (e.g., 1/3) for reassembly.
    """
    # Encode message to Base64 to handle non-ASCII characters in ciphertext
    encoded_message = base64.b64encode(message).decode()

    # Ensure proper fragment sizes with space for headers
    header_template = "1/1: "  # Example header format
    header_length = len(header_template) - 4  # Account for actual numbering
    fragment_size = max_length - header_length

    # Split the message into fragments
    fragments = []
    total_fragments = (len(encoded_message) + fragment_size - 1) // fragment_size
    for i in range(total_fragments):
        header = f"{i + 1}/{total_fragments}: "
        start = i * fragment_size
        end = start + fragment_size
        fragments.append(header + encoded_message[start:end])

    return fragments

def reassemble_message(fragments):
    """
    Reassembles fragments into the original message.
    """
    # Sort fragments by sequence number in the header
    fragments.sort(key=lambda x: int(x.split('/')[0]))

    # Remove headers and concatenate the Base64 strings
    encoded_message = ''.join(f.split(': ', 1)[1] for f in fragments)

    # Ensure proper Base64 padding
    missing_padding = len(encoded_message) % 4
    if missing_padding != 0:
        encoded_message += '=' * (4 - missing_padding)

    # Decode Base64 back to the original message
    return base64.b64decode(encoded_message.encode())
