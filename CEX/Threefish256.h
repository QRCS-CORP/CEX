// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_THREEFISH256_H
#define CEX_THREEFISH256_H

#include "CexDomain.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

/**
* \internal
*/
class Threefish256
{
private:

	static const size_t BLOCK_SIZE = 32;

	static ulong GetParity(const std::vector<ulong> &Key)
	{
		ulong parity = 0x1BD11BDAA9FC1A22;

		for (size_t i = 0; i < Key.size(); i++)
			parity ^= Key[i];

		return parity;
	}

	inline static void Mix(ulong &A, ulong &B, uint R)
	{
		A += B;
		B = Utility::IntUtils::RotL64(B, R) ^ A;
	}

	inline static void Inject(ulong &A, ulong &B, uint R, ulong K0, ulong K1)
	{
		B += K1;
		A += B + K0;
		B = Utility::IntUtils::RotL64(B, R) ^ A;
	}

public:

	template <typename T>
	static void Transfrom(std::vector<ulong> &Input, size_t InOffset, T &Output)
	{
		// Cache the block, key, and tweak
		ulong b0 = Input[0];
		ulong b1 = Input[1];
		ulong b2 = Input[2];
		ulong b3 = Input[3];
		ulong k0 = Output.S[0];
		ulong k1 = Output.S[1];
		ulong k2 = Output.S[2];
		ulong k3 = Output.S[3];
		ulong k4 = GetParity(Output.S);
		ulong t0 = Output.T[0];
		ulong t1 = Output.T[1];
		ulong t2 = Output.T[0] ^ Output.T[1];

		// 72 rounds
		Inject(b0, b1, 14, k0, k1 + t0);
		Inject(b2, b3, 16, k2 + t1, k3);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k1, k2 + t1);
		Inject(b2, b3, 33, k3 + t2, k4 + 1);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);
		Inject(b0, b1, 14, k2, k3 + t2);
		Inject(b2, b3, 16, k4 + t0, k0 + 2);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k3, k4 + t0);
		Inject(b2, b3, 33, k0 + t1, k1 + 3);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);
		Inject(b0, b1, 14, k4, k0 + t1);
		Inject(b2, b3, 16, k1 + t2, k2 + 4);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k0, k1 + t2);
		Inject(b2, b3, 33, k2 + t0, k3 + 5);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);
		Inject(b0, b1, 14, k1, k2 + t0);
		Inject(b2, b3, 16, k3 + t1, k4 + 6);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k2, k3 + t1);
		Inject(b2, b3, 33, k4 + t2, k0 + 7);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);
		Inject(b0, b1, 14, k3, k4 + t2);
		Inject(b2, b3, 16, k0 + t0, k1 + 8);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k4, k0 + t0);
		Inject(b2, b3, 33, k1 + t1, k2 + 9);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);
		Inject(b0, b1, 14, k0, k1 + t1);
		Inject(b2, b3, 16, k2 + t2, k3 + 10);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k1, k2 + t2);
		Inject(b2, b3, 33, k3 + t0, k4 + 11);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);
		Inject(b0, b1, 14, k2, k3 + t0);
		Inject(b2, b3, 16, k4 + t1, k0 + 12);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k3, k4 + t1);
		Inject(b2, b3, 33, k0 + t2, k1 + 13);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);
		Inject(b0, b1, 14, k4, k0 + t2);
		Inject(b2, b3, 16, k1 + t0, k2 + 14);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k0, k1 + t0);
		Inject(b2, b3, 33, k2 + t1, k3 + 15);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);
		Inject(b0, b1, 14, k1, k2 + t1);
		Inject(b2, b3, 16, k3 + t2, k4 + 16);
		Mix(b0, b3, 52);
		Mix(b2, b1, 57);
		Mix(b0, b1, 23);
		Mix(b2, b3, 40);
		Mix(b0, b3, 5);
		Mix(b2, b1, 37);
		Inject(b0, b1, 25, k2, k3 + t2);
		Inject(b2, b3, 33, k4 + t0, k0 + 17);
		Mix(b0, b3, 46);
		Mix(b2, b1, 12);
		Mix(b0, b1, 58);
		Mix(b2, b3, 22);
		Mix(b0, b3, 32);
		Mix(b2, b1, 32);

		Output.S[0] = b0 + k3;
		Output.S[1] = b1 + k4 + t0;
		Output.S[2] = b2 + k0 + t1;
		Output.S[3] = b3 + k1 + 18;
	}
};

NAMESPACE_DIGESTEND
#endif
