#ifndef _CEXENGINE_ROUNDCOUNTS_H
#define _CEXENGINE_ROUNDCOUNTS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Rounds Count. Can be cast as round count integers, 
/// i.e. (int ct = RoundCounts.R12) is equal to 12.
/// </summary>
enum class RoundCounts : unsigned int
{
	/// <summary>
	/// 8 Rounds: ChaCha
	/// </summary>
	R8 = 8,
	/// <summary>
	/// 10 Rounds: ChaCha, RHX
	/// </summary>
	R10 = 10,
	/// <summary>
	/// 12 Rounds: ChaCha, RHX
	/// </summary>
	R12 = 12,
	/// <summary>
	/// 14 Rounds: ChaCha, RHX
	/// </summary>
	R14 = 14,
	/// <summary>
	/// 16 Rounds: ChaCha, RHX, THX
	/// </summary>
	R16 = 16,
	/// <summary>
	/// 18 Rounds: ChaCha, RHX, THX
	/// </summary>
	R18 = 18,
	/// <summary>
	/// 20 Rounds: ChaCha, RHX, THX
	/// </summary>
	R20 = 20,
	/// <summary>
	/// 22 Rounds: ChaCha, RHX, THX
	/// </summary>
	R22 = 22,
	/// <summary>
	/// 24 Rounds: ChaCha, RHX, THX
	/// </summary>
	R24 = 24,
	/// <summary>
	/// 26 Rounds: ChaCha, RHX, THX
	/// </summary>
	R26 = 26,
	/// <summary>
	/// 28 Rounds: ChaCha, RHX, THX
	/// </summary>
	R28 = 28,
	/// <summary>
	/// 30 Rounds: ChaCha, RHX, THX
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