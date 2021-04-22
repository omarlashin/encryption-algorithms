#include <iostream>
#include "AES.h"
using namespace std;

void sub_bytes(Matrix state, const unsigned char mapping[])
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			state[i][j] = mapping[state[i][j]];
}

void rotate_left(unsigned char row[], int amount)
{
	char *temp = new char[amount];
	for (int i = 0; i < amount; i++)
		temp[i] = row[i];
	for (int i = amount; i < 4; i++)
		row[i - amount] = row[i];
	for (int i = 4 - amount; i < 4; i++)
		row[i] = temp[i - 4 + amount];
	delete temp;
}

void rotate_right(unsigned char row[], int amount)
{
	rotate_left(row, 4 - amount);
}

void shift_rows(Matrix state)
{
	for (int i = 1; i < 4; i++)
		rotate_left(state[i], i);
}

void inv_shift_rows(Matrix state)
{
	for (int i = 1; i < 4; i++)
		rotate_right(state[i], i);
}

void assign(Matrix dst, Matrix src)
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			dst[i][j] = src[i][j];
}

void mix_columns(Matrix state)
{
	unsigned char element;
	Matrix temp;
	assign(temp, state);
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			element = 0;
			for (int k = 0; k < 4; k++)
			{
				if (MCE[j][k] == 0x02)
					element ^= GFM2[temp[k][i]];
				else if (MCE[j][k] == 0x03)
					element ^= GFM3[temp[k][i]];
				else
					element ^= temp[k][i];
			}
			state[j][i] = element;
		}
	}
}

void inv_mix_columns(Matrix state)
{
	unsigned char element;
	Matrix temp;
	assign(temp, state);
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			element = 0;
			for (int k = 0; k < 4; k++)
			{
				if (MCD[j][k] == 0x09)
					element ^= GFM9[temp[k][i]];
				else if (MCD[j][k] == 0x0b)
					element ^= GFM11[temp[k][i]];
				else if (MCD[j][k] == 0x0d)
					element ^= GFM13[temp[k][i]];
				else if (MCD[j][k] == 0x0e)
					element ^= GFM14[temp[k][i]];
			}
			state[j][i] = element;
		}
	}
}

void add_round_key(Matrix state, Matrix key)
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			state[i][j] = state[i][j] ^ key[i][j];
}

void generate(Matrix key, Matrix keys[])
{
	unsigned char last_column[4];
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			keys[0][i][j] = key[i][j];
	for (int i = 1; i < 11; i++)
	{
		for (int j = 0; j < 4; j++)
			last_column[j] = keys[i - 1][j][3];
		rotate_left(last_column, 1);
		for (int j = 0; j < 4; j++)
			last_column[j] = ESBOX[last_column[j]];
		for (int j = 0; j < 4; j++)
			last_column[j] = last_column[j] ^ keys[i - 1][j][0];
		last_column[0] = last_column[0] ^ RC[i - 1];
		for (int j = 0; j < 4; j++)
			keys[i][j][0] = last_column[j];
		for (int j = 1; j < 4; j++)
			for (int k = 0; k < 4; k++)
				keys[i][k][j] = keys[i][k][j - 1] ^ keys[i - 1][k][j];
	}
}

void encrypt(Matrix plaintext, Matrix keys[])
{
	add_round_key(plaintext, keys[0]);
	for (int i = 1; i < 10; i++)
	{
		sub_bytes(plaintext, ESBOX);
		shift_rows(plaintext);
		mix_columns(plaintext);
		add_round_key(plaintext, keys[i]);
	}
	sub_bytes(plaintext, ESBOX);
	shift_rows(plaintext);
	add_round_key(plaintext, keys[10]);
}

void decrypt(Matrix ciphertext, Matrix keys[])
{
	add_round_key(ciphertext, keys[10]);
	for (int i = 1; i < 10; i++)
	{
		sub_bytes(ciphertext, DSBOX);
		inv_shift_rows(ciphertext);
		add_round_key(ciphertext, keys[10 - i]);
		inv_mix_columns(ciphertext);
	}
	sub_bytes(ciphertext, DSBOX);
	inv_shift_rows(ciphertext);
	add_round_key(ciphertext, keys[0]);
}

void convert(unsigned char a[])
{
	for (int i = 0; i < 32; i++)
	{
		switch (a[i])
		{
		case '0': a[i] = 0; break;
		case '1': a[i] = 1; break;
		case '2': a[i] = 2; break;
		case '3': a[i] = 3; break;
		case '4': a[i] = 4; break;
		case '5': a[i] = 5; break;
		case '6': a[i] = 6; break;
		case '7': a[i] = 7; break;
		case '8': a[i] = 8; break;
		case '9': a[i] = 9; break;
		case 'a':
		case 'A': a[i] = 10; break;
		case 'b':
		case 'B': a[i] = 11; break;
		case 'c':
		case 'C': a[i] = 12; break;
		case 'd':
		case 'D': a[i] = 13; break;
		case 'e':
		case 'E': a[i] = 14; break;
		case 'f':
		case 'F': a[i] = 15; break;
		}
	}
}

int main()
{
	int choice;
	unsigned char temp[32];
	Matrix key, input;
	Matrix keys[11];
	while (1)
	{
		cout << "Enter 1 for encryption, or 0 for decryption: ";
		cin >> choice;
		cout << "Enter encryption/decryption key in hexadecimal (128 bits):" << endl;
		for (int i = 0; i < 32; i++)
			cin >> temp[i];
		convert(temp);
		for (int i = 0; i < 32; i += 2)
			key[(i / 2) % 4][i / 8] = (temp[i] << 4) | temp[i + 1];
		cout << "Enter plaintext/ciphertext in hexadecimal (128 bits):" << endl;
		for (int i = 0; i < 32; i++)
			cin >> hex >> temp[i];
		convert(temp);
		for (int i = 0; i < 32; i += 2)
			input[(i / 2) % 4][i / 8] = (temp[i] << 4) | temp[i + 1];
		generate(key, keys);
		if (choice == 0)
			decrypt(input, keys);
		else
			encrypt(input, keys);
		cout << "Result (in hexadecimal):" << endl;
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				cout << hex << (unsigned int)(input[j][i] >> 4);
				cout << hex << (unsigned int)(input[j][i] & 15);
			}
		}
		cout << endl;
	}
}