// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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

#ifndef CEX_SALSA_H
#define CEX_SALSA_H

#include "CexDomain.h"

NAMESPACE_STREAM

/// 
/// internal
/// 
class Salsa
{
public:

#if defined(__AVX__)
	static void PermuteP512V(std::vector<uint> &State);
#else
	static void PermuteP512C(std::vector<uint> &State);
#endif

};

NAMESPACE_STREAMEND
#endif
