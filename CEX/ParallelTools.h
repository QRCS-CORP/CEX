// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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

#ifndef CEX_PARALLELUTILS_H
#define CEX_PARALLELUTILS_H

#include "CexDomain.h"
#include <functional>

NAMESPACE_UTILITY

/// <summary>
/// Parallel functions class
/// </summary> 
class ParallelTools
{
public:

	/// <summary>
	/// A multi-threaded parallel For loop
	/// </summary>
	/// 
	/// <param name="From">The inclusive starting position</param> 
	/// <param name="To">The exclusive ending position</param>
	/// <param name="F">The function delegate</param>
	static void ParallelFor(size_t From, size_t To, const std::function<void(size_t)> &F);

	/// <summary>
	/// Execute a function on a new thread
	/// </summary>
	/// 
	/// <param name="F">The function delegate</param>
	static void ParallelTask(const std::function<void()> &F);

	/// <summary>
	/// Read Only: The number of processors available on the system
	/// </summary>
	static size_t ProcessorCount();

	/// <summary>
	/// An SIMD vectorized For loop (not currently used, requires a higher version of OpenMP)
	/// </summary>
	/// 
	/// <param name="F">The function delegate</param>
	static void Vectorize(const std::function<void()> &F);

};

NAMESPACE_UTILITYEND
#endif
