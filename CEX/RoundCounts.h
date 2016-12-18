#ifndef _CEX_ROUNDCOUNTS_H
#define _CEX_ROUNDCOUNTS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Rounds Count enumeration names.
/// <para>Can be cast as round count integers, e.g. (int ct = RoundCounts.R12) is equal to 12.</para>
/// </summary>
enum class RoundCounts : uint8_t
{
	/// <summary>
	/// No round count is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// 8 Rounds: ChaCha20
	/// </summary>
	R8 = 8,
	/// <summary>
	/// 10 Rounds: ChaCha20, RHX
	/// </summary>
	R10 = 10,
	/// <summary>
	/// 12 Rounds: ChaCha20, RHX
	/// </summary>
	R12 = 12,
	/// <summary>
	/// 14 Rounds: ChaCha20, RHX
	/// </summary>
	R14 = 14,
	/// <summary>
	/// 16 Rounds: ChaCha20, RHX, THX
	/// </summary>
	R16 = 16,
	/// <summary>
	/// 18 Rounds: ChaCha20, RHX, THX
	/// </summary>
	R18 = 18,
	/// <summary>
	/// 20 Rounds: ChaCha20, RHX, THX
	/// </summary>
	R20 = 20,
	/// <summary>
	/// 22 Rounds: ChaCha20, RHX, THX
	/// </summary>
	R22 = 22,
	/// <summary>
	/// 24 Rounds: ChaCha20, RHX, THX
	/// </summary>
	R24 = 24,
	/// <summary>
	/// 26 Rounds: ChaCha20, RHX, THX
	/// </summary>
	R26 = 26,
	/// <summary>
	/// 28 Rounds: ChaCha20, RHX, THX
	/// </summary>
	R28 = 28,
	/// <summary>
	/// 30 Rounds: ChaCha20, RHX, THX
	/// </summary>
	R30 = 30,
	/// <summary>
	/// 32 Rounds: RHX, SHX, THX
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