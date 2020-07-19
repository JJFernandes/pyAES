import os
import optparse
import re
import math
import lookup_tables as lt


def option_parse() -> (bool, str, str, str):
	parser = optparse.OptionParser(usage="usage: aes.py [-e|-d] -i <input file> -o <output file> -k <key>")
	parser.add_option("-e", "--encrypt", action="store_true", dest="mode")
	parser.add_option("-d", "--decrypt", action="store_false", dest="mode")
	parser.add_option("-i", "--input-file", action="store", type="string", dest="fin", help="specify source file")
	parser.add_option("-o", "--output-file", action="store", type="string", dest="fout", help="specify destination file")
	# later will allow for regular passwords sent to hash to get 32 char hex string
	parser.add_option("-k", "--key", action="store", type="string", dest="key", help="32 character hex string key")

	(options, args) = parser.parse_args()
	mode = options.mode
	fin = options.fin
	fout = options.fout
	key = options.key

	# requiring that the input file be named so I dont have to deal with it
	if (mode is None) | (fin is None) | (fout is None) | (key is None):
		print(parser.usage)
		exit()
	elif (not re.search(re.compile(r'^[a-fA-F0-9]{32}$'), key)):
		print("key given is not a 32 character hex string")
		exit()

	return mode, fin, fout, key


def rotate_word(array: list, num: int) -> list:
    temp = array.copy()
    return temp[num:] + temp[:num]


def substitute_word(array: list) -> list:
    temp = array.copy()
    for i in range(4):
        temp[i] = lt.sbox[temp[i]]
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
            temp = xor_list_with_int(substitute_word(rotate_word(temp, 1)), lt.rcon[int(i / 4)])
        words[i] = xor_list_with_list(words[i - 4], temp)

    expanded_key = [[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00]] * 11

    for i in range(11):
        expanded_key[i] = words[4 * i] + words[4 * i + 1] + words[4 * i + 2] + words[4 * i + 3]
        expanded_key[i] = text_book_array(expanded_key[i])

    return expanded_key


def add_round_key(buff: list, rkey: list) -> list:
	return xor_list_with_list(buff, rkey)


# galois field GF(2^8) multiplication
def GF8_mult(num: int, mul: int) -> int:
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
		temp[0 + i] = GF8_mult(buff[0 + i], 0x02) ^ GF8_mult(buff[4 + i], 0x03) ^ buff[8 + i] ^ buff[12 + i]
		temp[4 + i] = buff[0 + i] ^ GF8_mult(buff[4 + i], 0x02) ^ GF8_mult(buff[8 + i], 0x03) ^ buff[12 + i]
		temp[8 + i] = buff[0 + i] ^ buff[4 + i] ^ GF8_mult(buff[8 + i], 0x02) ^ GF8_mult(buff[12 + i], 0x03)
		temp[12 + i] = GF8_mult(buff[0 + i], 0x03) ^ buff[4 + i] ^ buff[8 + i] ^ GF8_mult(buff[12 + i], 0x02)
	return temp


def shift_rows(buff: list) -> list:
	temp = buff.copy()
	temp[0:4] = rotate_word(temp[0:4], 0)
	temp[4:8] = rotate_word(temp[4:8], 1)
	temp[8:12] = rotate_word(temp[8:12], 2)
	temp[12:16] = rotate_word(temp[12:16], 3)
	return temp


def substitute_bytes(buff: list) -> list:
	temp = buff.copy()
	for i in range(16):
		temp[i] = lt.sbox[temp[i]]
	return temp


# patch function to modify buffer to match order of textbook example
# my functions were written based on textbook orientation
# and my lists are 1D instead of 2D
# example buffer on read:
# 01 23 45 67		 01 89 fe 76	
# 89 ab cd ef	>>>  23 ab dc 54
# fe dc ba 98		 45 cd ba 32
# 76 54 32 10		 67 ef 98 10
# calling the function again undos itself
def text_book_array(buff: list) -> list:
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


def encrypt(fin: str, fout: str, key: str):

	file_size = os.path.getsize(fin)
	if (file_size == 0):
		print ("Size of input file is 0 bytes")
		exit()
	elif (file_size % 16 == 0):
		buff_count = int(file_size / 16)
	elif (file_size % 16 != 0):
		buff_count = int(math.floor(file_size / 16)) + 1

	# separate the 32 char hex string into array of bytes
	key = [int(x, 16) for x in re.findall("..", key)]

	key_schedule = key_expansion(key)

	with open(fin, "rb") as src, open(fout, "wb") as dst:
		
		for i in range(buff_count):
			
			buff_read = src.read(16)
			buff_write = []
			
			if ( len(buff_read) == 16 ):
				for x in range(16):
					buff_write.append(int(buff_read[x]))
			# if current buffer is < 16 bytes, pad with zeroes
			elif ( len(buff_read) < 16 ):
				for x in range(len(buff_read)):
					buff_write.append(int(buff_read[x]))
				for y in range(len(buff_read), 16):
					buff_write.append(0x00)

			# initialize with adding rkey0 to the buffer
			buff_write = text_book_array(buff_write)
			buff_write = add_round_key(buff_write, key_schedule[0])

			# rounds 1-9: sub, shift, mix, add
			for j in range(1, 10):
				buff_write = add_round_key(mix_columns(shift_rows(substitute_bytes(buff_write))), key_schedule[j])
				
			# round 10: sub, shift, add
			buff_write = add_round_key(shift_rows(substitute_bytes(buff_write)), key_schedule[10])
			# undo text book array orientation
			buff_write = text_book_array(buff_write)
			dst.write(bytearray(buff_write))


def main():
	mode, fin, fout, key = option_parse()

	fin = os.path.abspath(fin)
	fout = os.path.abspath(fout)

	if mode:
		encrypt(fin, fout, key)
	else:
		print("decrypt not ready")


if __name__ == "__main__":
	main()