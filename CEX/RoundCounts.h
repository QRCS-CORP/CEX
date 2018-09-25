#ifndef CEX_ROUNDCOUNTS_H
#define CEX_ROUNDCOUNTS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Rounds Count enumeration names.
/// <para>Can be cast as round count integers, e.g. (int ct = RoundCounts.R12) is equal to 12.</para>
/// </summary>
enum class RoundCounts : byte
{
	/// <summary>
	/// No round count is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// 8 Rounds: ChaCha256
	/// </summary>
	R8 = 8,
	/// <summary>
	/// 10 Rounds: ChaCha256, RHX
	/// </summary>
	R10 = 10,
	/// <summary>
	/// 12 Rounds: ChaCha256, RHX
	/// </summary>
	R12 = 12,
	/// <summary>
	/// 14 Rounds: ChaCha256, RHX
	/// </summary>
	R14 = 14,
	/// <summary>
	/// 16 Rounds: ChaCha256, RHX
	/// </summary>
	R16 = 16,
	/// <summary>
	/// 18 Rounds: ChaCha256, RHX
	/// </summary>
	R18 = 18,
	/// <summary>
	/// 20 Rounds: ChaCha256, RHX
	/// </summary>
	R20 = 20,
	/// <summary>
	/// 22 Rounds: ChaCha256, RHX
	/// </summary>
	R22 = 22,
	/// <summary>
	/// 24 Rounds: ChaCha256, RHX
	/// </summary>
	R24 = 24,
	/// <summary>
	/// 26 Rounds: ChaCha256, RHX
	/// </summary>
	R26 = 26,
	/// <summary>
	/// 28 Rounds: ChaCha256, RHX
	/// </summary>
	R28 = 28,
	/// <summary>
	/// 30 Rounds: ChaCha256, RHX
	/// </summary>
	R30 = 30,
	/// <summary>
	/// 32 Rounds: RHX, SHX
	/// </summary>
	R32 = 32,
	/// <summary>
	/// 34 Rounds, RHX
	/// </summary>
	R34 = 34,
	/// <summary>
	/// 38 Rounds, RHX
	/// </summary>
	R38 = 38,
	/// <summary>
	/// 40 Rounds: SHX
	/// </summary>
	R40 = 40,
	/// <summary>
	/// 48 Rounds: SHX
	/// </summary>
	R48 = 48,
	/// <summary>
	/// 56 Rounds: SHX
	/// </summary>
	R56 = 56,
	/// <summary>
	/// 64 Rounds: SHX
	/// </summary>
	R64 = 64
};

NAMESPACE_ENUMERATIONEND
#endif
