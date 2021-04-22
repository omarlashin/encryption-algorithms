#include<iostream>
#include "DES.h"
using namespace std;

unsigned long long decimal(bool block[], int size)
{
	unsigned long long result = 0, magnitude = 1;
	for (int i = 0; i < size; i++)
	{
		result += block[size - i - 1] * magnitude;
		magnitude *= 2;
	}
	return result;
}

void binary(unsigned long long value, bool result[], int size)
{
	for (int i = 0; i < size; i++)
		result[i] = 0;
	while (value > 0)
	{
		result[size - 1] = value % 2;
		value /= 2;
		size--;
	}
}

void permute(bool block[], bool result[], int size, const int mapping[])
{
	for (int i = 0; i < size; i++)
		result[i] = block[mapping[i] - 1];
}

void sbox(bool block[], bool result[])
{
	bool column_binary[4];
	bool row_binary[2];
	bool result_part[4];
	int column, row;
	
	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 4; j++)
			column_binary[j] = block[i * 6 + j + 1];
		row_binary[0] = block[i * 6];
		row_binary[1] = block[i * 6 + 5];
		
		column = decimal(column_binary, 4);
		row = decimal(row_binary, 2);
		binary(SBOXES[i][row][column], result_part, 4);
		for (int j = 0; j < 4; j++)
			result[i * 4 + j] = result_part[j];
	}
}

void rotate_left(bool block[], int amount, int size)
{
	bool *temp = new bool[amount];
	for (int i = 0; i < amount; i++)
		temp[i] = block[i];
	for (int i = amount; i < size; i++)
		block[i - amount] = block[i];
	for (int i = size - amount; i < size; i++)
		block[i] = temp[i - size + amount];
	delete temp;
}

void split(bool block[], bool left[], bool right[], int size)
{
	for (int i = 0; i < size; i++)
		left[i] = block[i];
	for (int i = 0; i < size; i++)
		right[i] = block[i + size];
}

void merge(bool block[], bool left[], bool right[], int size)
{
	for (int i = 0; i < size; i++)
		block[i] = left[i];
	for (int i = 0; i < size; i++)
		block[i + size] = right[i];
}

void generate(bool key[], bool keys[16][48])
{
	bool permuted_key[56];
	permute(key, permuted_key, 56, PCM1);
	bool c[28];
	bool d[28];
	split(permuted_key, c, d, 28);
	bool temp[56];
	for (int i = 0; i < 16; i++)
	{
		rotate_left(c, SHAMT[i], 28);
		rotate_left(d, SHAMT[i], 28);
		merge(temp, c, d, 28);
		permute(temp, keys[i], 48, PCM2);
	}
}

void assign(bool dst[], bool src[], int size)
{
	for (int i = 0; i < size; i++)
		dst[i] = src[i];
}

void eor(bool a[], bool b[], bool result[], int size)
{
	for (int i = 0; i < size; i++)
		result[i] = a[i] ^ b[i];
}

void encrypt_decrypt(bool input[], bool keys[16][48], bool output[], bool is_encrypting)
{
	bool permuted_input[64];
	permute(input, permuted_input, 64, IPM);
	
	bool l[32];
	bool r[32];
	bool l_new[32];
	bool r_new[32];
	bool permuted_r[48];
	bool eor_result[48];
	bool sbox_result[32];
	bool permuted_result[32];
	split(permuted_input, l, r, 32);
	for (int i = 0; i < 16; i++)
	{
		assign(l_new, r, 32);
		permute(r, permuted_r, 48, RFEPM);
		eor(permuted_r, keys[(is_encrypting) ? i : 16 - i - 1], eor_result, 48);
		sbox(eor_result, sbox_result);
		permute(sbox_result, permuted_result, 32, RFPM);
		eor(permuted_result, l, r_new, 32);
		assign(l, l_new, 32);
		assign(r, r_new, 32);
	}

	bool temp[64];
	merge(temp, r, l, 32);
	permute(temp, output, 64, IIPM);
}

int main()
{
	bool is_encrypting;
	unsigned long long temp;
	bool key[64];
	bool keys[16][48];
	bool input[64];
	bool output[64];
	int times;
	while (1)
	{
		cout << "Enter 1 for encryption, or 0 for decryption: ";
		cin >> is_encrypting;
		cout << "Enter encryption/decryption key in hexadecimal (64 bits):" << endl;
		cin >> hex >> temp;
		binary(temp, key, 64);
		cout << "Enter plaintext/ciphertext in hexadecimal (64 bits):" << endl;
		cin >> hex >> temp;
		binary(temp, input, 64);
		cout << "Enter number of encryptions/decryptions: ";
		cin >> times;
		generate(key, keys);
		for (int i = 0; i < times; i++)
		{
			encrypt_decrypt(input, keys, output, is_encrypting);
			assign(input, output, 64);
		}
		temp = decimal(output, 64);
		cout << "Result (in hexadecimal):" << endl << hex << temp << endl;
	}
}