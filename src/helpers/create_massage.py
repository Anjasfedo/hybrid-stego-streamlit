import string


def create_pattern_padded_message(base_message: str, target_byte_size: int) -> str:
    character_pool = string.ascii_letters + string.digits + string.punctuation

    try:
        message_bytes = base_message.encode('utf-8')
    except UnicodeEncodeError:
        return ""

    current_byte_size = len(message_bytes)

    if current_byte_size > target_byte_size:
        # If the base message is too large, truncate it to fit the target size
        try:
            truncated_bytes = message_bytes[:target_byte_size]
            return truncated_bytes.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            # If decoding fails, try character by character
            result = ""
            byte_count = 0
            for char in base_message:
                char_bytes = char.encode('utf-8')
                if byte_count + len(char_bytes) > target_byte_size:
                    break
                result += char
                byte_count += len(char_bytes)
            return result

    padding_needed = target_byte_size - current_byte_size

    pattern_repeats = (padding_needed // len(character_pool)) + 1
    full_pattern = character_pool * pattern_repeats
    padding = full_pattern[:padding_needed]

    return base_message + padding

my_message = (
    "This message uses deterministic padding. 🚀 "
    "The padding is a repeating, non-random sequence. "
    "Let's test it: 123!@#<>? éçñ. 😊👍"
)
