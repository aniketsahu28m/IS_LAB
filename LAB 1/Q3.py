
def create_playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    seen_chars = set()
    matrix = []

    for char in key:
        if char not in seen_chars and char.isalpha():
            matrix.append(char)
            seen_chars.add(char)

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in seen_chars:
            matrix.append(char)
            seen_chars.add(char)

    playfair_matrix = [matrix[i:i + 5] for i in range(0, 25, 5)]
    return playfair_matrix

def prepare_plaintext(text):
    text = text.upper().replace(' ', '').replace('J', 'I')

    prepared_text = ""
    i = 0
    while i < len(text):
        prepared_text += text[i]

        if i == len(text) - 1:
            prepared_text += 'X'
            break

        if text[i] == text[i + 1]:
            prepared_text += 'X'
            i += 1
        else:
            prepared_text += text[i + 1]
            i += 2

    return prepared_text

def find_char_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return -1, -1

def encipher_message(matrix, prepared_text):
    ciphertext = ""
    for i in range(0, len(prepared_text), 2):
        char1 = prepared_text[i]
        char2 = prepared_text[i + 1]

        row1, col1 = find_char_position(matrix, char1)
        row2, col2 = find_char_position(matrix, char2)

        if row1 == row2:
            new_col1 = (col1 + 1) % 5
            new_col2 = (col2 + 1) % 5
            ciphertext += matrix[row1][new_col1] + matrix[row2][new_col2]

        elif col1 == col2:
            new_row1 = (row1 + 1) % 5
            new_row2 = (row2 + 1) % 5
            ciphertext += matrix[new_row1][col1] + matrix[new_row2][col2]

        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]

    return ciphertext

key = "GUIDANCE"
plaintext = "The key is hidden under the door pad"

playfair_matrix = create_playfair_matrix(key)
print("Playfair Matrix:")
for row in playfair_matrix:
    print(row)

prepared_message = prepare_plaintext(plaintext)
print("\nPrepared Plaintext:", prepared_message)

encrypted_message = encipher_message(playfair_matrix, prepared_message)
print("Encrypted Message:", encrypted_message)