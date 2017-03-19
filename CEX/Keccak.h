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
// along with this program.If not, see <http://www.gnu.org/licenses/>.

#ifndef _CEX_KECCAK_H
#define _CEX_KECCAK_H

#include "CexDomain.h"

NAMESPACE_DIGEST


/**
* \internal
*/
class Keccak
{
private:
	static const ulong C0 = 0x0000000000000001;
	static const ulong C1 = 0x0000000000008082;
	static const ulong C2 = 0x800000000000808a;
	static const ulong C3 = 0x8000000080008000;
	static const ulong C4 = 0x000000000000808b;
	static const ulong C5 = 0x0000000080000001;
	static const ulong C6 = 0x8000000080008081;
	static const ulong C7 = 0x8000000000008009;
	static const ulong C8 = 0x000000000000008a;
	static const ulong C9 = 0x0000000000000088;
	static const ulong C10 = 0x0000000080008009;
	static const ulong C11 = 0x000000008000000a;
	static const ulong C12 = 0x000000008000808b;
	static const ulong C13 = 0x800000000000008b;
	static const ulong C14 = 0x8000000000008089;
	static const ulong C15 = 0x8000000000008003;
	static const ulong C16 = 0x8000000000008002;
	static const ulong C17 = 0x8000000000000080;
	static const ulong C18 = 0x000000000000800a;
	static const ulong C19 = 0x800000008000000a;
	static const ulong C20 = 0x8000000080008081;
	static const ulong C21 = 0x8000000000008080;
	static const ulong C22 = 0x0000000080000001;
	static const ulong C23 = 0x8000000080008008;

public:
	/// <summary>
	/// Process a block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input array</param>
	/// <param name="Offset">The offset index</param>
	/// <param name="State">The state array</param>
	/// <param name="Size">The size of the transform</param>
	static void TransformBlock(const std::vector<byte> &Input, size_t Offset, std::vector<ulong> &State, size_t Size);
};

NAMESPACE_DIGESTEND
#endif
