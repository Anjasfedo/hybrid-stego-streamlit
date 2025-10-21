from src.helpers.binary_massage import message_to_binary


def calculate_ber(original_text: str, extracted_text: str) -> float:
    if not extracted_text:
        return 1.0

    original_binary = message_to_binary(original_text)
    extracted_binary = message_to_binary(extracted_text)

    total_bits = len(original_binary)
    if total_bits == 0:
        return 0.0

    errors = 0
    compare_len = min(len(original_binary), len(extracted_binary))
    for i in range(compare_len):
        if original_binary[i] != extracted_binary[i]:
            errors += 1

    errors += abs(len(original_binary) - len(extracted_binary))

    return errors / total_bits
