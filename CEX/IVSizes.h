#ifndef _CEX_IVSIZES_H
#define _CEX_IVSIZES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Common Initialization Vector bit sizes.
/// <para> Can be cast as IV byte size integers, i.e. (int sz = IVSizes.V128) is equal to 16.</para>
/// </summary>
enum class IVSizes : uint8_t
{
	/// <summary>
	/// No iv size is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// 64 bit IV
	/// </summary>
	V64 = 8,
	/// <summary>
	/// 128 bit IV
	/// </summary>
	V128 = 16,
	/// <summary>
	/// 256 bit IV
	/// </summary>
	V256 = 32
};

NAMESPACE_ENUMERATIONEND
#endif