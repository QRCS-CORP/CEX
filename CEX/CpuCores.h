#ifndef CEX_CPUCORES_H
#define CEX_CPUCORES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

// TODO: 1.0.0.4 -revise parallel options the Parallel parameter with this, 
// and make core count assignable through the constructor

/// <summary>
/// Core counts used by ParallelOptions api.
/// <para>The maximum number of CPU cores used by a mutithreaded function.</para>
/// </summary>
enum class CpuCores : byte
{
	/// <summary>
	/// All Cpu cores are used (default)
	/// </summary>
	Auto = 0,
	/// <summary>
	/// Single processor mode
	/// </summary>
	Single = 1,
	/// <summary>
	/// Two cpu cores
	/// </summary>
	CoresX2 = 2,
	/// <summary>
	/// Four cpu cores
	/// </summary>
	CoresX4 = 4,
	/// <summary>
	/// Half of available cores
	/// </summary>
	Half = 5,
	/// <summary>
	/// Six cpu cores
	/// </summary>
	CoresX6 = 6,
	/// <summary>
	/// Eight cpu cores
	/// </summary>
	CoresX8 = 8,
	/// <summary>
	/// Sixteen cpu cores
	/// </summary>
	CoresX16 = 16,
	/// <summary>
	/// Thirty-two cpu cores
	/// </summary>
	CoresX32 = 32,
	/// <summary>
	/// Sixty-four cpu cores
	/// </summary>
	CoresX64 = 64,
};

NAMESPACE_ENUMERATIONEND
#endif