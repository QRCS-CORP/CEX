#include "Threefish256.h"

void Threefish256::Clear()
{
	if (_expandedKey.size() > 0)
		fill(_expandedKey.begin(), _expandedKey.end(), 0);
	if (_expandedTweak.size() > 0)
		fill(_expandedTweak.begin(), _expandedTweak.end(), 0);
}

void Threefish256::Encrypt(const std::vector<ulong> &Input, std::vector<ulong> &Output)
{
	// Cache the block, key, and tweak
	ulong b0 = Input[0];
	ulong b1 = Input[1];
	ulong b2 = Input[2];
	ulong b3 = Input[3];
	ulong k0 = _expandedKey[0];
	ulong k1 = _expandedKey[1];
	ulong k2 = _expandedKey[2];
	ulong k3 = _expandedKey[3];
	ulong k4 = _expandedKey[4];
	ulong t0 = _expandedTweak[0];
	ulong t1 = _expandedTweak[1];
	ulong t2 = _expandedTweak[2];

	Mix(b0, b1, 14, k0, k1 + t0);
	Mix(b2, b3, 16, k2 + t1, k3);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k1, k2 + t1);
	Mix(b2, b3, 33, k3 + t2, k4 + 1);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);
	Mix(b0, b1, 14, k2, k3 + t2);
	Mix(b2, b3, 16, k4 + t0, k0 + 2);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k3, k4 + t0);
	Mix(b2, b3, 33, k0 + t1, k1 + 3);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);
	Mix(b0, b1, 14, k4, k0 + t1);
	Mix(b2, b3, 16, k1 + t2, k2 + 4);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k0, k1 + t2);
	Mix(b2, b3, 33, k2 + t0, k3 + 5);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);
	Mix(b0, b1, 14, k1, k2 + t0);
	Mix(b2, b3, 16, k3 + t1, k4 + 6);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k2, k3 + t1);
	Mix(b2, b3, 33, k4 + t2, k0 + 7);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);
	Mix(b0, b1, 14, k3, k4 + t2);
	Mix(b2, b3, 16, k0 + t0, k1 + 8);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k4, k0 + t0);
	Mix(b2, b3, 33, k1 + t1, k2 + 9);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);
	Mix(b0, b1, 14, k0, k1 + t1);
	Mix(b2, b3, 16, k2 + t2, k3 + 10);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k1, k2 + t2);
	Mix(b2, b3, 33, k3 + t0, k4 + 11);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);
	Mix(b0, b1, 14, k2, k3 + t0);
	Mix(b2, b3, 16, k4 + t1, k0 + 12);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k3, k4 + t1);
	Mix(b2, b3, 33, k0 + t2, k1 + 13);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);
	Mix(b0, b1, 14, k4, k0 + t2);
	Mix(b2, b3, 16, k1 + t0, k2 + 14);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k0, k1 + t0);
	Mix(b2, b3, 33, k2 + t1, k3 + 15);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);
	Mix(b0, b1, 14, k1, k2 + t1);
	Mix(b2, b3, 16, k3 + t2, k4 + 16);
	Mix(b0, b3, 52);
	Mix(b2, b1, 57);
	Mix(b0, b1, 23);
	Mix(b2, b3, 40);
	Mix(b0, b3, 5);
	Mix(b2, b1, 37);
	Mix(b0, b1, 25, k2, k3 + t2);
	Mix(b2, b3, 33, k4 + t0, k0 + 17);
	Mix(b0, b3, 46);
	Mix(b2, b1, 12);
	Mix(b0, b1, 58);
	Mix(b2, b3, 22);
	Mix(b0, b3, 32);
	Mix(b2, b1, 32);

	Output[0] = b0 + k3;
	Output[1] = b1 + k4 + t0;
	Output[2] = b2 + k0 + t1;
	Output[3] = b3 + k1 + 18;
}

void Threefish256::SetKey(const std::vector<ulong> &Key)
{
	unsigned int i;
	ulong parity = KeyScheduleConst;

	for (i = 0; i < _expandedKey.size() - 1; i++)
	{
		_expandedKey[i] = Key[i];
		parity ^= Key[i];
	}

	_expandedKey[i] = parity;
}

void Threefish256::SetTweak(const std::vector<ulong> &Tweak)
{
	_expandedTweak[0] = Tweak[0];
	_expandedTweak[1] = Tweak[1];
	_expandedTweak[2] = Tweak[0] ^ Tweak[1];
}