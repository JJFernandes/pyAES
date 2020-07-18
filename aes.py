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
	fout = options.fin
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

    return expanded_key


def encrypt(fin: str, fout: str, key: str):
	# separate the 32 char hex string into array of bytes
	key = [int(x, 16) for x in re.findall("..", key)]

	key_schedule = key_expansion(key)


def main():
	mode, fin, fout, key = option_parse()

	if mode:
		encrypt(fin, fout, key)
	else:
		print("decrypt not ready")


if __name__ == "__main__":
	main()