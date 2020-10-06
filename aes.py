import os
import optparse
import re
import math

# round constants
rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# S-Box
sbox = \
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

# inverse S-Box
inv_sbox = \
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
     0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
     0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
     0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
     0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
     0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
     0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
     0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
     0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
     0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
     0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
     0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
     0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
     0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
     0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
     0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]


def option_parse() -> (bool, str, str, str):
	parser = optparse.OptionParser(usage="usage: aes.py [-e|-d] -i <input file> -o <output file> -k <key>")
	parser.add_option("--encrypt", action="store_true", dest="mode")
	parser.add_option("--decrypt", action="store_false", dest="mode")
	parser.add_option("--in", action="store", type="string", dest="fin", help="input file name")
	parser.add_option("--out", action="store", type="string", dest="fout", help="output file name")
	parser.add_option("--key", action="store", type="string", dest="key", help="key: 16 byte hex string")
	parser.add_option("--iv", action="store", type="string", dest="iv", help="initialization vector: 16 byte hex string")

	(options, args) = parser.parse_args()
	mode = options.mode
	fin = os.path.abspath(options.fin)
	fout = os.path.abspath(options.fout)
	key = options.key
	iv = options.iv

	if (mode is None) | (fin is None) | (fout is None) | (key is None) | (iv is None):
		print(parser.usage)
		exit()
	elif (not re.search(re.compile(r'^[a-fA-F0-9]{32}$'), key)):
		print("key given is not a 16 byte hex string")
		exit()
	elif (not re.search(re.compile(r'^[a-fA-F0-9]{32}$'), iv)):
		print("iv given is not a 16 byte hex string")
		exit()

	return mode, fin, fout, key, iv


def rotate_word(array: list, num: int) -> list:
    temp = array.copy()
    return temp[num:] + temp[:num]


def substitute_word(array: list) -> list:
    temp = array.copy()
    for i in range(4):
        temp[i] = sbox[temp[i]]
    return temp


def xor_list_with_int(array: list, num: int) -> list:
    temp = array.copy()
    temp[0] ^= num
    return temp


def xor_list_with_list(array1: list, array2: list) -> list:
    temp1 = array1.copy()
    temp2 = array2.copy()

    for i in range(len(temp1)):
        temp1[i] ^= temp2[i]

    return temp1


def key_expansion(key: list) -> list:
    words = [[0x00, 0x00, 0x00, 0x00]] * 44

    for i in range(4):
        words[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]

    for i in range(4, 44):
        temp = words[i - 1].copy()
        if i % 4 == 0:
            temp = xor_list_with_int(substitute_word(rotate_word(temp, 1)), rcon[int(i / 4)])
        words[i] = xor_list_with_list(words[i - 4], temp)

    expanded_key = [[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00]] * 11

    for i in range(11):
        expanded_key[i] = words[4 * i] + words[4 * i + 1] + words[4 * i + 2] + words[4 * i + 3]
        expanded_key[i] = aes_state_array_orientation(expanded_key[i])

    return expanded_key


def add_round_key(buff: list, rkey: list) -> list:
	
	return xor_list_with_list(buff, rkey)


# galois field GF(2^8) multiplication
def galois_mul(num: int, mul: int) -> int:
    product = 0
    for i in range(8):
        if mul & 1:
            product ^= num
        # get the leftmost bit
        hi_bit_set = num & 0x80
        num <<= 1
        if hi_bit_set:
            num ^= 0x1b
        mul >>= 1
    # keep size of int at 1 byte
    return product & 0xff


def mix_columns(buff: list) -> list:
	temp = buff.copy()
	for i in range(4):
		temp[0 + i] = galois_mul(buff[0 + i], 0x02) ^ galois_mul(buff[4 + i], 0x03) ^ buff[8 + i] ^ buff[12 + i]
		temp[4 + i] = buff[0 + i] ^ galois_mul(buff[4 + i], 0x02) ^ galois_mul(buff[8 + i], 0x03) ^ buff[12 + i]
		temp[8 + i] = buff[0 + i] ^ buff[4 + i] ^ galois_mul(buff[8 + i], 0x02) ^ galois_mul(buff[12 + i], 0x03)
		temp[12 + i] = galois_mul(buff[0 + i], 0x03) ^ buff[4 + i] ^ buff[8 + i] ^ galois_mul(buff[12 + i], 0x02)
	return temp


def shift_rows(buff: list) -> list:
	temp = buff.copy()
	# temp[0:4] = rotate_word(temp[0:4], 0)
	temp[4:8] = rotate_word(temp[4:8], 1)
	temp[8:12] = rotate_word(temp[8:12], 2)
	temp[12:16] = rotate_word(temp[12:16], 3)
	return temp


def substitute_bytes(buff: list) -> list:
	temp = buff.copy()
	for i in range(16):
		temp[i] = sbox[temp[i]]
	return temp


# modify read buffer to aes state array orientation
# looks bad because I am using 1d array instead of 2d
# example buffer on read:
# b0  b1  b2  b3		b0  b4  b8  b12
# b4  b5  b6  b7		b1  b5  b9  b13
# b8  b9  b10 b11	->	b2  b6  b10 b14
# b12 b13 b14 b15		b3  b7  b11 b15
# calling the function again undos itself
def aes_state_array_orientation(buff: list) -> list:
	temp = buff.copy()

	temp[0] = buff[0]
	temp[1] = buff[4]
	temp[2] = buff[8]
	temp[3] = buff[12]
	temp[4] = buff[1]
	temp[5] = buff[5]
	temp[6] = buff[9]
	temp[7] = buff[13]
	temp[8] = buff[2]
	temp[9] = buff[6]
	temp[10] = buff[10]
	temp[11] = buff[14]
	temp[12] = buff[3]
	temp[13] = buff[7]
	temp[14] = buff[11]
	temp[15] = buff[15]

	return temp


def pad_block(block_in: list) -> list:

	block_out = []

	if ( len(block_in) == 16 ):
		for x in range(16):
			block_out.append(int(block_in[x]))
	# if current buffer is < 16 bytes, pad with zeroes
	elif ( len(block_in) < 16 ):
		for x in range(len(block_in)):
			block_out.append(int(block_in[x]))
		for y in range(len(block_in), 16):
			block_out.append(0x0)

	return block_out


def encrypt_10rounds(block_in: list, schedule: list) -> list:

	# initialize with adding rkey0 to the buffer
	block_out = add_round_key(block_in, schedule[0])

	# rounds 1-9: sub, shift, mix, add
	for j in range(1, 10):
		block_out = add_round_key(mix_columns(shift_rows(substitute_bytes(block_out))), schedule[j])
				
	# round 10: sub, shift, add
		block_out = add_round_key(shift_rows(substitute_bytes(block_out)), schedule[10])

	return block_out


def encrypt(fin: str, fout: str, key: str, iv: str):

	file_size = os.path.getsize(fin)
	if (file_size == 0):
		print ("Size of input file is 0 bytes")
		exit()
	elif (file_size % 16 == 0):
		buff_count = int(file_size / 16)
	elif (file_size % 16 != 0):
		buff_count = int(math.floor(file_size / 16)) + 1

	# separate the 16 byte hex string into array of bytes
	key = [int(x, 16) for x in re.findall("..", key)]
	
	key_schedule = key_expansion(key)

	iv = aes_state_array_orientation([int(x, 16) for x in re.findall("..", iv)])

	with open(fin, "rb") as src, open(fout, "wb") as dst:

		plainblock_0 = src.read(16)
		cipherblock = xor_list_with_list(aes_state_array_orientation(pad_block(plainblock_0)), iv)

		cipherblock = encrypt_10rounds(cipherblock, key_schedule)

		# undo text book array orientation and write to dst file
		cipherblock = aes_state_array_orientation(cipherblock)
		dst.write(bytearray(cipherblock))
		
		for i in range(1, buff_count):
			
			plainblock = src.read(16)
			
			cipherblock = xor_list_with_list(aes_state_array_orientation(pad_block(plainblock)), cipherblock)

			cipherblock = encrypt_10rounds(cipherblock, key_schedule)

			cipherblock = aes_state_array_orientation(cipherblock)
			dst.write(bytearray(cipherblock))


def inverse_mix_columns(buff: list) -> list:
	temp = buff.copy()
	for i in range(4):
		temp[0 + i] = galois_mul(buff[0 + i], 0x0e) ^ galois_mul(buff[4 + i], 0x0b) ^ galois_mul(buff[8 + i], 0x0d) ^ galois_mul(buff[12 + i], 0x09)
		temp[4 + i] = galois_mul(buff[0 + i], 0x09) ^ galois_mul(buff[4 + i], 0x0e) ^ galois_mul(buff[8 + i], 0x0b) ^ galois_mul(buff[12 + i], 0x0d)
		temp[8 + i] = galois_mul(buff[0 + i], 0x0d) ^ galois_mul(buff[4 + i], 0x09) ^ galois_mul(buff[8 + i], 0x0e) ^ galois_mul(buff[12 + i], 0x0b)
		temp[12 + i] = galois_mul(buff[0 + i], 0x0b) ^ galois_mul(buff[4 + i], 0x0d) ^ galois_mul(buff[8 + i], 0x09) ^ galois_mul(buff[12 + i], 0x0e)
	return temp


def inverse_substitute_bytes(buff: list) -> list:
	temp = buff.copy()
	for i in range(16):
		temp[i] = inv_sbox[temp[i]]
	return temp


def inverse_shift_rows(buff: list) -> list:
	temp = buff.copy()
	# temp[0:4] = rotate_word(temp[0:4], 0)
	temp[4:8] = rotate_word(temp[4:8], 3)
	temp[8:12] = rotate_word(temp[8:12], 2)
	temp[12:16] = rotate_word(temp[12:16], 1)
	return temp


def decrypt(fin: str, fout: str, key: str):

	file_size = os.path.getsize(fin)
	if (file_size == 0):
		print ("Size of input file is 0 bytes")
		exit()
	else:
		# assuming file encrypted with this encryption tool, it will be a multiple of 16
		buff_count = int(file_size / 16)

	# separate the 32 char hex string into array of bytes
	key = [int(x, 16) for x in re.findall("..", key)]

	key_schedule = key_expansion(key)

	with open(fin, "rb") as src, open(fout, "wb") as dst:
		
		for i in range(buff_count):
			
			cipherblock = src.read(16)
			plainblock = []
			
			for x in range(16):
				plainblock.append(int(cipherblock[x]))
			
			# transform buffer into aes state array orientation
			plainblock = aes_state_array_orientation(plainblock)

			# initialize with adding rkey10 to the buffer
			plainblock = add_round_key(plainblock, key_schedule[10])

			# rounds 1-9: shift, sub, add, mix
			for j in range(9, 0, -1):
				plainblock = inverse_mix_columns(add_round_key(inverse_substitute_bytes(inverse_shift_rows(plainblock)), key_schedule[j]))
				
			# round 10: shift, sub, add
			plainblock = add_round_key(inverse_substitute_bytes(inverse_shift_rows(plainblock)), key_schedule[0])

			# undo text book array orientation
			plainblock = aes_state_array_orientation(plainblock)
			dst.write(bytearray(plainblock))


def main():
	mode, fin, fout, key, iv = option_parse()

	if mode:
		encrypt(fin, fout, key, iv)
	else:
		decrypt(fin, fout, key, iv)


if __name__ == "__main__":
	main()