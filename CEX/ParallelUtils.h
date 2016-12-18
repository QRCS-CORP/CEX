#ifndef _CEX_PARALLELUTILS_H
#define _CEX_PARALLELUTILS_H

#include "CexDomain.h"
#include <functional>

NAMESPACE_UTILITY

/// <summary>
/// Parallel functions class
/// </summary> 
class ParallelUtils
{
public:

	/// <summary>
	/// Get: The number of processors available on the system
	/// </summary>
	static size_t ProcessorCount();

	/// <summary>
	/// A Parallel For loop
	/// </summary>
	/// 
	/// <param name="From">The inclusive starting position</param> 
	/// <param name="To">The exclusive ending position</param>
	/// <param name="F">The function delegate</param>
	static void ParallelFor(size_t From, size_t To, const std::function<void(size_t)> &F);
};

NAMESPACE_UTILITYEND
#endif
