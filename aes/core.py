class AES:
    S_BOX = (
        (0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76),
        (0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0),
        (0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15),
        (0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75),
        (0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84),
        (0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf),
        (0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8),
        (0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2),
        (0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73),
        (0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb),
        (0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79),
        (0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08),
        (0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a),
        (0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e),
        (0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf),
        (0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16)
    )

    INV_S_BOX = (
        (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB),
        (0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB),
        (0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E),
        (0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25),
        (0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92),
        (0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84),
        (0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06),
        (0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B),
        (0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73),
        (0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E),
        (0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B),
        (0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4),
        (0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F),
        (0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF),
        (0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61),
        (0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D),
    )

    RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

    def __init__(self, key):
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes.")

        key_length = len(key) * 8
        if key_length == 128:
            self.rounds = 10
        elif key_length == 192:
            self.rounds = 12
        elif key_length == 256:
            self.rounds = 14
        else:
            raise ValueError("Key must have size 128, 192, or 256 bits.")

        self.key_columns = len(key) // 4
        self.words = self._key_expansion(key)

    def _sub_bytes(self, state):
        """Substitutes each byte in the state with its corresponding value from the S-box"""
        new_state = []
        for row in state:
            new_row = []
            for byte in row:
                new_row.append(self.S_BOX[byte >> 4][byte & 0x0F])
            new_state.append(new_row)
        return new_state

    def _inv_sub_bytes(self, state):
        """Substitutes each byte in the state with its corresponding value from the inverse S-box"""
        return [[self.INV_S_BOX[byte >> 4][byte & 0x0F] for byte in row] for row in state]

    @staticmethod
    def _shift_rows(state):
        """Cyclically shifts the last three rows of the state to the left"""
        new_state = [state[0][:]]
        for r in range(1, 4):
            new_state.append(state[r][r:] + state[r][:r])
        return new_state

    @staticmethod
    def _inv_shift_rows(state):
        """Cyclically shifts the last three rows of the state to the right"""
        new_state = [state[0][:]]
        for r in range(1, 4):
            new_state.append(state[r][-r:] + state[r][:-r])
        return new_state

    @staticmethod
    def _x_times(byte):
        """Performs byte multiplication by 2 in GF(2^8)"""
        if byte & 0x80:
            return ((byte << 1) ^ 0x1b) & 0xff
        return (byte << 1) & 0xff

    def _mix_columns(self, state):
        """Multiplies each column of the state by a fixed polynomial in GF(2^8)"""
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]

            s0_02 = self._x_times(s0)
            s1_02 = self._x_times(s1)
            s2_02 = self._x_times(s2)
            s3_02 = self._x_times(s3)

            # b * {03} = b * ({02} + {01}) = b * {02} + b
            s0_03 = s0_02 ^ s0
            s1_03 = s1_02 ^ s1
            s2_03 = s2_02 ^ s2
            s3_03 = s3_02 ^ s3

            new_state[0][c] = s0_02 ^ s1_03 ^ s2 ^ s3
            new_state[1][c] = s0 ^ s1_02 ^ s2_03 ^ s3
            new_state[2][c] = s0 ^ s1 ^ s2_02 ^ s3_03
            new_state[3][c] = s0_03 ^ s1 ^ s2 ^ s3_02
            
        return new_state

    def _inv_mix_columns(self, state):
        """Multiplies each column of the state by a fixed polynomial in GF(2^8) for decryption"""
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]

            s0_02 = self._x_times(s0); s0_04 = self._x_times(s0_02); s0_08 = self._x_times(s0_04)
            s1_02 = self._x_times(s1); s1_04 = self._x_times(s1_02); s1_08 = self._x_times(s1_04)
            s2_02 = self._x_times(s2); s2_04 = self._x_times(s2_02); s2_08 = self._x_times(s2_04)
            s3_02 = self._x_times(s3); s3_04 = self._x_times(s3_02); s3_08 = self._x_times(s3_04)

            # b * {09} = b * ({08} + {01}) = b * {08} + b
            s0_09 = s0_08 ^ s0
            s1_09 = s1_08 ^ s1
            s2_09 = s2_08 ^ s2
            s3_09 = s3_08 ^ s3

            # b * {0b} = b * ({08} + {02} + {01}) = b * {08} + b * {02} + b
            s0_0b = s0_08 ^ s0_02 ^ s0
            s1_0b = s1_08 ^ s1_02 ^ s1
            s2_0b = s2_08 ^ s2_02 ^ s2
            s3_0b = s3_08 ^ s3_02 ^ s3

            # b * {0d} = b * ({08} + {04} + {01}) = b * {08} + b * {04} + b
            s0_0d = s0_08 ^ s0_04 ^ s0
            s1_0d = s1_08 ^ s1_04 ^ s1
            s2_0d = s2_08 ^ s2_04 ^ s2
            s3_0d = s3_08 ^ s3_04 ^ s3

            # b * {0e} = b * ({08} + {04} + {02}) = b * {08} + b * {04} + b * {02}
            s0_0e = s0_08 ^ s0_04 ^ s0_02
            s1_0e = s1_08 ^ s1_04 ^ s1_02
            s2_0e = s2_08 ^ s2_04 ^ s2_02
            s3_0e = s3_08 ^ s3_04 ^ s3_02

            new_state[0][c] = s0_0e ^ s1_0b ^ s2_0d ^ s3_09
            new_state[1][c] = s0_09 ^ s1_0e ^ s2_0b ^ s3_0d
            new_state[2][c] = s0_0d ^ s1_09 ^ s2_0e ^ s3_0b
            new_state[3][c] = s0_0b ^ s1_0d ^ s2_09 ^ s3_0e
        
        return new_state

    @staticmethod
    def _add_round_key(state, round_key):
        """XORs the state with the round key"""
        new_state = []
        for r in range(4):
            new_row = []
            for c in range(4):
                new_row.append(state[r][c] ^ round_key[c][r])
            new_state.append(new_row)
        return new_state
          
    def _key_expansion(self, key):
        """Expands the key into an array of words"""
        words = [list(key[4*i:4*(i+1)]) for i in range(self.key_columns)]

        total_words = 4 * (self.rounds + 1)

        for i in range(self.key_columns, total_words):
            temp = list(words[i-1])
            if i % self.key_columns == 0:
                temp = temp[1:] + temp[:1]  # RotWord
                temp = [self.S_BOX[byte >> 4][byte & 0x0f] for byte in temp]  # SubWord
                temp[0] ^= self.RCON[i // self.key_columns - 1]
            elif self.key_columns > 6 and i % self.key_columns == 4:
                temp = [self.S_BOX[byte >> 4][byte & 0x0f] for byte in temp]  
            new_word = [words[i - self.key_columns][j] ^ temp[j] for j in range(4)]
            words.append(new_word)
        
        return words

    def encrypt_block(self, plaintext):
        """Encrypts a single 128-bit block of plaintext using the AES algorithm"""
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes.")
        if len(plaintext) * 8 != 128:
            raise ValueError("Plaintext must have 128-bits size.")

        state = [[plaintext[r + 4 * c] for c in range(4)] for r in range(4)]

        state = self._add_round_key(state, self.words[:4])

        for round in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.words[4*round:4*(round+1)])
        
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.words[4*self.rounds:])

        return bytes([state[r][c] for c in range(4) for r in range(4)])

    def decrypt_block(self, ciphertext):
        """Decrypts a single 128-bit block of ciphertext using the AES algorithm"""
        if not isinstance(ciphertext, bytes):
            raise TypeError("Ciphertext must be bytes.")
        if len(ciphertext) * 8 != 128:
            raise ValueError("Ciphertext must have 128-bits size.")

        state = [[ciphertext[r + 4 * c] for c in range(4)] for r in range(4)]

        state = self._add_round_key(state, self.words[4*self.rounds:])

        for round in range(self.rounds - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.words[4*round:4*(round+1)])
            state = self._inv_mix_columns(state)

        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.words[:4])
        
        return bytes([state[r][c] for c in range(4) for r in range(4)])