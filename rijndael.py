import codecs
import random
from math import sqrt, ceil
from time import sleep

# generate additional round keys from original key
# Phase Zero
def extend_round_key(cipher_matrix, rounds):
	rcon = [['01','00','00','00'],['02','00','00','00'],['04','00','00','00'],['08','00','00','00'],['10','00','00','00'],['20','00','00','00'],['40','00','00','00'],['80','00','00','00'],['1B','00','00','00'],['36','00','00','00']]
	extended_round_key = cipher_matrix.copy()
	for extension in range(rounds):
		for j in range(len(extended_round_key)):
			for i in range(len(extended_round_key)):
				if (len(extended_round_key[i]) % 4 == 0):
					extended_round_key[i] += [bin_to_hex(xor(xor((''.join(byte_substitution(hex_to_bin(extended_round_key[(i+1)%len(extended_round_key)][len(extended_round_key[i])-1])))),hex_to_bin(extended_round_key[i][-4])),hex_to_bin(rcon[extension][i])))]
				else:
					extended_round_key[i] += [bin_to_hex(xor(hex_to_bin(extended_round_key[i][-1]), hex_to_bin(extended_round_key[i][-4])))]
	return extended_round_key

# perform the Byte Substitution step
# Phase One
def byteSubstitution_step(matrix, round = 1):
	for i in range(len(matrix)):
		for j in range(len(matrix)):
			matrix[i][j] = bin_to_hex(''.join(byte_substitution(hex_to_bin(matrix[i][j]))))
	print('Round: '+str(round+1)+' ByteSubstitution')
	print(*matrix, sep='\n', end='\n\n')
	return matrix

# perfomr the Shift Row step
# Phase Two
def shiftRow_step(matrix, round = 1):
	for i in range(len(matrix)):
		for j in range(i):
			temp = matrix[i][0]
			del matrix[i][0]
			matrix[i] += [temp]
	print('Round: '+str(round+1)+' ShiftRow')
	print(*matrix, sep='\n', end='\n\n')
	return matrix

# perform the MixColumn step
# Phase Three
def mixColumn_step(matrix, round = 1):
	transformed_matrix = [[] for i in range(len(matrix))]
	# 'transform' matrix to make operations more code friendly
	for i in range(0,len(matrix)):
		for j in range(0,len(matrix)):
			transformed_matrix[i] += [matrix[j][i]]
	# convert the hex strings to binary strings
	transformed_matrix = [[hex_to_bin(element) for element in row] for row in transformed_matrix]
	# perform MixColumn operation of Rijndael Cipher
	mixColumn_matrix = square_matrix_mult(transformed_matrix)
	# convert the binary strings to hex strings
	mixColumn_matrix = [[bin_to_hex(element) for element in row] for row in mixColumn_matrix]
	# print MixColumn matrix
	print('Round: '+str(round+1)+' MixColumn Matrix')
	print(*mixColumn_matrix, sep='\n', end='\n\n')
	return mixColumn_matrix

# perform the AddRoundKey step
# Phase Four
def addRoundKey_step(matrix, extended_round_key, round=1):
	for i in range(len(matrix)):
		for j in range(len(matrix)):
			matrix[i][j] = bin_to_hex(xor(hex_to_bin(matrix[i][j]), hex_to_bin(extended_round_key[i][j+4*(round+1)])))
	print('Round: '+str(round+1)+' AddRoundKey')
	print(*matrix, sep='\n', end='\n\n')
	return matrix

# convert a hex string to binary string
def hex_to_bin(hex_str):
	hex_dict = {'0': '0000','1': '0001','2': '0010','3': '0011','4': '0100','5': '0101','6': '0110','7': '0111','8': '1000','9': '1001','A': '1010','B': '1011','C': '1100','D': '1101','E': '1110','F': '1111'}
	bin_str = ''
	for i in range(0, len(hex_str)):
		bin_str += hex_dict[hex_str[i]]
	return bin_str

# convert binary string to hex string
def bin_to_hex(bin_str):
	bin_dict = {'0000': '0','0001': '1','0010': '2','0011': '3','0100': '4','0101': '5','0110': '6','0111': '7','1000': '8','1001': '9','1010': 'A','1011': 'B','1100': 'C','1101': 'D','1110': 'E','1111': 'F'}
	hex_str = ''
	for i in range(0, int(len(bin_str)/4)):
		hex_str += bin_dict[bin_str[(0+4*i):4+4*i]]
	return hex_str

# perform a binary modulo operation within the GF(2^8) field
def bin_modulo(bin_str, modulo_str = '100011011'):
	if len(bin_str) < len(modulo_str):
		return bin_str
	elif bin_str == modulo_str:
		return '00000000'
	while len(bin_str) >= len(modulo_str):
		bin_temp = xor(bin_str, modulo_str)
		bin_temp += bin_str[len(modulo_str)::]
		bin_str = bin_temp
	return bin_str

def bin_and(bin_str1, bin_str2):
	output = ['' for i in range(len(bin_str1))]
	for i in range(len(bin_str1)):
		if bin_str1[i] == '1' and bin_str2[i] == '1':
			output[i] = '1'
		else:
			output[i] = '0'
	return output

# xor two binary numbers - ommitting leading zeroes and then padding to return an 8 bit string
def xor(bin_str1, bin_str2, pad_2 = False):
	if pad_2:
		bin_str2 = bin_str2.rjust(len(bin_str1),'0')
	xor_out = ''
	for i in range(0, len(bin_str2)):
		if int(bin_str1[i]) != int(bin_str2[i]):
			xor_out += '1'
		elif int(bin_str1[i]) == int(bin_str2[i]) and len(xor_out) == 0:
			xor_out += ''
		elif int(bin_str1[i]) == int(bin_str2[i]) and len(xor_out) > 0:
			xor_out += '0'
	return zero_padding(xor_out)

# all padding used is to return an 8 bit string
def zero_padding(bin_str):
	return bin_str.rjust(8,'0')

# multiply a binary string by 0x01, 0x02, or 0x03
def bin_mult(bin_str, mult_str):
	if mult_str == '01':
		return zero_padding(bin_str)
	elif mult_str == '02':
		return zero_padding(bin_modulo((bin_str+'0')))
	elif mult_str == '03':
		step_one = xor((bin_str+'0'), bin_str, pad_2 = True)
		step_two = bin_modulo(step_one)
		return zero_padding(step_two)

# add a list of binary numbers together
# in GF(2^8) this is equivalent to XORing each number
def xy_add(xy_array):
	add_out = xy_array[0]
	for i in range(1,len(xy_array)):
		add_out = xor(add_out, xy_array[i], pad_2 = True)
	return bin_modulo(add_out)

# multiply matrix by standard matrix (mult_matrix)
def square_matrix_mult(transformed_matrix):
	mult_matrix = 	[['02','03','01','01'],
					['01','02','03','01'],
					['01','01','02','03'],
					['03','01','01','02']]
	output_matrix = [[] for i in range(len(mult_matrix))]
	for i in range(0,len(mult_matrix)):
		for j in range(0,len(mult_matrix)):
			temp_array = []
			for k in range(0,len(mult_matrix)):
				temp_array += [bin_mult(transformed_matrix[j][k], mult_matrix[i][k])]
			output_matrix[i] += [xy_add(temp_array)]
	return output_matrix



# generate a random 128 bit key and output as a string of hexidecimal characters
def key_generation(length = 128):
	key = ''
	for i in range(0,length):
		key += str(random.randrange(0,2))
	return bin_to_hex(key)

# convert a string of length 2*n^2 into an n*n matrix, inserting character pairs from the string into the matrix column-wise
def to_matrix_array(matrix_string):
	matrix = [[] for i in range(int(sqrt((len(matrix_string)/2))))]
	index = 0
	for i in range(0,len(matrix)):
		for j in range(0,len(matrix)):
			matrix[j] += [matrix_string[index:index+2]]
			index += 2
	return matrix

def from_matrix_array(matrix):
	matrix_of_pairs = ''
	for column in range(0,len(matrix)):
		for row in range(0,len(matrix)):
			matrix_of_pairs += matrix[row][column]
	return matrix_of_pairs

# check if the '8-bit' string is too long, is '00000000' (this maps to itself), or needs to be inverted
def multiplicative_inverse_choice(galois_str):
	if len(galois_str) > 8:
		print('String too long for Galois Multiplicative Inverse')
	elif galois_str == '00000000':
		return galois_str
	else:
		return binary_gf_inverse(galois_str)

# check if all the sublists in a list of lists are empty
def empty_lists(input_list):
	empty = True
	for sublist in input_list:
		if len(sublist) != 0:
			empty = False
			break
	return empty

# perform multiplcation of two quadratic representations of binary numbers
def multi_variable_multiplication(mult_len, bin_in, uk):
	mult = [[] for i in range(mult_len)]
	for i in range(len(bin_in)):
		if bin_in[i] == '1':
			for j in range(len(uk)):
				mult[i+j] += uk[j]
	return mult

# perform long division of two quadratic representations of binary numbers
def multi_variable_divide(mult, modulus):
	while not len(mult) < len(modulus):
		for i in range(1,len(modulus)):
			if modulus[-i] == '1':
				mult_index = -(i+len(mult)-len(modulus))
				for elem in mult[0]:
					if elem in mult[mult_index]:
						del mult[mult_index][mult[mult_index].index(elem)]
					else:
						mult[mult_index] += ([elem])
		del mult[0]
	return mult

# remove all instances of a character from a list if they appear more than once
def remove_multi_char(mult):
	for elem in mult:
		for i in range(len(elem)-1):
			if i >= len(elem):
				break
			if elem[i] in elem[i+1::]:
				del elem[elem.index(elem[i], i+1, len(elem))]
				del elem[i]

# for finding unknown variables if a list has only one character find its binary equivalent
# else if list is '1' delete list
def if_one_get_val(mult, equiv, inv_lib):
	for i in range(len(mult)):
		if len(mult[i]) == 1:
			if mult[i][0] == '1':
				del mult[i][0]
			else:
				inv_lib[mult[i][0]] = equiv[i]

# check dictionary for entries with a value of '1' or '0' and substitute as appropriate
def check_dict(inv_lib, mult):
	for entry in inv_lib:
		if inv_lib[entry] == '1':
			for sublist in mult:
				if entry in sublist:
					sublist[sublist.index(entry)] = '1'
		elif inv_lib[entry] == '0':
			for sublist in mult:
				if entry in sublist:
					del sublist[sublist.index(entry)]

# if a sublist has a length of two -> index 0 == index 1
# substitute across all other sublists as appropriate
# if necessary replace 2 characters with 1 character
def substitution(mult, inv_lib, larger_sublist = 2):
	for i in range(len(mult)):
		if larger_sublist > 2:
			for j in range(len(mult[i])-1):
				for k in range(j+1,len(mult[i])):
					temp_list = [mult[i][j], mult[i][k]]
					temp_mult = mult[i].copy()
					del temp_mult[k]
					del temp_mult[j]
					while len(temp_mult) > 1:
						temp_list += temp_mult[0]
						del temp_mult[0]
					for l in range(len(mult)):
						if l != i:
							if set(temp_list).issubset(mult[l]):
								for item in temp_list:
									del mult[l][mult[l].index(item)]
								mult[l] += temp_mult
								return (True)
		elif len(mult[i]) == 2:
			# if one value is '1' then the other is also '1' (technically '-1', but only absolutes are needed)
			if '1' in mult[i]:
				inv_lib[mult[i][abs(mult[i].index('1')-1)]] = '1'
				del mult[i][0::]
			elif i < (len(mult)-1): # last sublist == 1, so cannot perform substitution
				replace = mult[i][0]
				replace_with = mult[i][1]
				for j in range(len(mult)):
					if j != i:
						if replace in mult[j]:
							mult[j][mult[j].index(replace)] = replace_with

# obtain multiplicative inverse in a Galois Field (2^8)
def binary_gf_inverse(to_inv = '01010011'):
	uk = ['a','b','c','d','e','f','g','h']												# unknown variables
	mod = ['1','0','0','0','1','1','0','1','1']											# Galois Field modulus
	equiv = ['0','0','0','0','0','0','0','1']											# Quadratic equivalents
	inv_lib = {'a':'-1','b':'-1','c':'-1','d':'-1','e':'-1','f':'-1','g':'-1','h':'-1'} # dictionary of unknowns
	bin_in = [to_inv[i] for i in range(len(to_inv))]
	while bin_in[0] == '0':																# remove leading zeroes (simplifies maths)
		del bin_in[0]
	mult_len = len(uk)+len(bin_in)-1													# length of quadratic equation after multiplication
	# multi-variable multiply
	mult = multi_variable_multiplication(mult_len, bin_in, uk)
	# multi-variable long divide
	mult = multi_variable_divide(mult, mod)
	# find unknown values
	count = 0
	while not empty_lists(mult):
		temp_mult_1 = mult.copy()
		#	if a sublist is 1 long -> find the value of the letter (or remove '1')
		if_one_get_val(mult, equiv, inv_lib)
		#	if a non -1 entry exists, change the mult list of lists
		check_dict(inv_lib, mult)
		#	if len(sublist) == 2 replace ALL instances of index 0 with index 1 [only in all other sublists]
		substitution(mult, inv_lib)
		#	if a character appears twice, remove both
		remove_multi_char(mult)
		#	if a sublist is 1 long -> find the value of the letter (or remove '1')
		if_one_get_val(mult, equiv, inv_lib)
		#	if a non -1 entry exists, change the mult list of lists
		check_dict(inv_lib, mult)
		temp_mult_2 = mult.copy()
		if temp_mult_1 == temp_mult_2:
			count += 1
			sub_result = substitution(mult, inv_lib, larger_sublist = count)
			if sub_result:
				count = 0
				remove_multi_char(mult)
	# replace unknowns with values in dictionary
	for index in range(len(uk)):
		uk[index] = inv_lib[uk[index]]
	return uk

# invert list so that least significant bit is first
def reverse_bits(bin_str):
	reverse = [[] for i in range(len(bin_str))]
	for i in range(len(bin_str)):
		reverse[-(i+1)] = bin_str[i]
	return reverse

# perform bytes substitution
def byte_substitution(bin_str):
	s_matrix = [['1','0','0','0','1','1','1','1'],['1','1','0','0','0','1','1','1'],['1','1','1','0','0','0','1','1'],['1','1','1','1','0','0','0','1'],['1','1','1','1','1','0','0','0'],['0','1','1','1','1','1','0','0'],['0','0','1','1','1','1','1','0'],['0','0','0','1','1','1','1','1']]
	reverse_hex_63 = ['1','1','0','0','0','1','1','0']
	inverse = reverse_bits(multiplicative_inverse_choice(bin_str))
	s_matrix_mult = [xy_add((bin_and(inverse, s_matrix[i]))) for i in range(len(s_matrix))]
	affine_transform = reverse_bits(xor(s_matrix_mult, reverse_hex_63))
	return affine_transform

def key_interpret(key):
	if key.lower() == 'random':
		return key_generation()
	if len(key) < 16:
		key = key.rjust(16,'0')
	elif len(key) > 16:
		key = key[0:16]
	return key.encode('utf-8').hex().upper()

def plain_text_interpret(plain_text):
	if int(len(plain_text)%16) != 0:
		plain_text = plain_text.rjust((int(ceil(len(plain_text)/16))*16), '0')
	plain_text_matrix = []
	for i in range(int(len(plain_text)/16)):
		substring = plain_text[i*16:(i+1)*16].encode('utf-8').hex().upper()
		plain_text_matrix += [to_matrix_array(substring)]
	return plain_text_matrix

def hex_to_utf8(hex_string):
	utf8_string = codecs.decode(hex_string, 'hex').decode('utf-8')
	#for pair in hex_string:
	#	utf8_string += unichr(ord('0x'+pair.lower()))

	return utf8_string

def rijndael_cipher(plain_text_matrix, extended_key, rounds):
	encrypted_text = ''
	for matrix in plain_text_matrix:
		matrix = addRoundKey_step(matrix, extended_key, round = -1)
		for i in range(rounds):
			matrix = byteSubstitution_step(matrix, i)
			sleep(0.5)
			matrix = shiftRow_step(matrix, i)
			sleep(0.5)
			if i != rounds-1:
				matrix = mixColumn_step(matrix, i)
				sleep(0.5)
			matrix = addRoundKey_step(matrix, extended_key, round=i)
			sleep(0.5)
		encrypted_text += from_matrix_array(matrix)
	return encrypted_text

def main():
	plain_text_matrix = plain_text_interpret(input('Please input phrase to be encrypted: '))
	print('')
	cipher_key = to_matrix_array(key_interpret(input('Please input the cipher key (16 characters),\nor type \'random\' for a randomly generated key (which will be printed).\nIf the key is too short it will be padded on the left with zeroes,\ntoo long and it will be truncated with the end removed: ')))
	print('')
	print('Plain Text Matrix:')
	for row in range(len(plain_text_matrix[0])):
		for matrix in plain_text_matrix:
			print(matrix[row], end='')
		print('')
	print('\nOriginal Key:')
	print(*cipher_key, sep='\n', end='\n\n')
	rounds = 10
	extended_key = extend_round_key(cipher_key, rounds)
	print('Extended Key:')
	print(*extended_key, sep='\n', end='\n\n')
	input('Press enter to begin encryption')
	encrypted_text = rijndael_cipher(plain_text_matrix, extended_key, rounds)
	print('Encrypted Text: ')
	print(hex(int(encrypted_text,16)))
main()
