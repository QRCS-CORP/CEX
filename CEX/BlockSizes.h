#ifndef _CEX_BLOCKSIZES_H
#define _CEX_BLOCKSIZES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Common symmetric block cipher state bit sizes.
/// <para>Can be cast as Block byte size integers, i.e. (int sz = BlockSizes.B512) is equal to 64.</para>
/// </summary>
enum class BlockSizes : uint8_t
{
	/// <summary>
	/// No block size is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// 128 bit block size
	/// </summary>
	B128 = 16,
	/// <summary>
	/// 256 bit block size
	/// </summary>
	B256 = 32,
	/// <summary>
	/// 512 bit block size
	/// </summary>
	B512 = 64,
	/// <summary>
	/// 1024 bit block size
	/// </summary>
	B1024 = 128
};

NAMESPACE_ENUMERATIONEND
#endif
