import optparse
import re
import math
import lookup_tables as lt


def option_parse() -> (bool, str, str, str):
	# later will allow for regular passwords sent to hash to get 32 char hex string
	hex_re = re.compile(r'^[a-fA-F0-9]{32}$')

	parser = optparse.OptionParser(usage="usage: aes.py [-e|-d] -i <input file> -o <output file> -k <key>")
	parser.add_option("-e", "--encrypt", action="store_true", dest="mode")
	parser.add_option("-d", "--decrypt", action="store_false", dest="mode")
	parser.add_option("-i", "--input-file", action="store", type="string", dest="fin", help="specify source file")
	parser.add_option("-o", "--output-file", action="store", type="string", dest="fout", help="specify destination file")
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
	elif (not re.search(hex_re, key)):
		print("key given is not a 32 character hex string")
		exit()

	return mode, fin, fout, key


def encrypt(fin: str, fout: str, key: str):
	# separate the 32 char hex string into array of bytes
	key = [int(x, 16) for x in re.findall("..", key)]

	#key_schedule = generate_key_schedule(key)


def main():
	mode, fin, fout, key = option_parse()

	if mode:
		encrypt(fin, fout, key)
	else:
		print("decrypt not ready")


if __name__ == "__main__":
	main()