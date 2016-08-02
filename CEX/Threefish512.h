#ifndef _CEXENGINE_THREEFISH512_H
#define _CEXENGINE_THREEFISH512_H

#include "Common.h"

/// <summary>
/// Part of Skein512: the Threefish cipher using a 512bit key size.
/// </summary> 
class Threefish512
{
private:
	static constexpr uint CipherSize = 512;
	static constexpr uint CipherQwords = CipherSize / 64;
	static constexpr uint ExpandedKeySize = CipherQwords + 1;
	static constexpr uint ExpandedTweakSize = 3;
	static constexpr ulong KeyScheduleConst = 0x1BD11BDAA9FC1A22;

	std::vector<ulong> m_expandedKey;
	std::vector<ulong> m_expandedTweak;

public:
	/// <summary>
	/// Threefish with a 512 bit block
	/// </summary>
	Threefish512()
		:
		m_expandedTweak(ExpandedTweakSize, 0),
		m_expandedKey(ExpandedKeySize, 0)
	{
		// Create the expanded key array
		m_expandedKey[ExpandedKeySize - 1] = KeyScheduleConst;
	}

	/// <summary>
	/// Reset the state
	/// </summary>
	void Clear();

	/// <summary>
	/// Encrypt a block
	/// </summary>
	/// 
	/// <param name="Input">Input array</param>
	/// <param name="Output">Processed bytes</param>
	void Encrypt(const std::vector<ulong> &Input, std::vector<ulong> &Output);

	/// <summary>
	/// Initialize the key
	/// </summary>
	/// 
	/// <param name="Key">The cipher key</param>
	void SetKey(const std::vector<ulong> &Key);

	/// <summary>
	/// Initialize the tweak
	/// </summary>
	/// 
	/// <param name="Tweak">The cipher tweak</param>
	void SetTweak(const std::vector<ulong> &Tweak);

private:
	static inline void Mix(ulong &A, ulong &B, uint R)
	{
		A += B;
		B = RotL64(B, R) ^ A;
	}

	static inline void Mix(ulong &A, ulong &B, uint R, ulong K0, ulong K1)
	{
		B += K1;
		A += B + K0;
		B = RotL64(B, R) ^ A;
	}

	static inline ulong RotL64(ulong V, uint B)
	{
		return (V << B) | (V >> (64 - B));
	}
};

#endif
