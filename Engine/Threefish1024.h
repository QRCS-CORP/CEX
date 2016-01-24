#ifndef _CEXENGINE_THREEFISH1024_H
#define _CEXENGINE_THREEFISH1024_H

#include "Common.h"

/// <summary>
/// Part of Skein1024: the Threefish cipher using a 1024bit key size.
/// </summary> 
class Threefish1024
{
private:
	static constexpr uint CipherSize = 1024;
	static constexpr uint CipherQwords = CipherSize / 64;
	static constexpr uint ExpandedKeySize = CipherQwords + 1;
	static constexpr uint ExpandedTweakSize = 3;
	static constexpr ulong KeyScheduleConst = 0x1BD11BDAA9FC1A22;

	std::vector<ulong>  _expandedKey;
	std::vector<ulong>  _expandedTweak;

public:
	Threefish1024()
		:
		_expandedTweak(ExpandedTweakSize, 0),
		_expandedKey(ExpandedKeySize, 0)
	{
		// Create the expanded key array
		_expandedKey[ExpandedKeySize - 1] = KeyScheduleConst;
	}

	void Clear();
	void Encrypt(const std::vector<ulong> Input, std::vector<ulong> &Output);
	void SetKey(const std::vector<ulong> Key);
	void SetTweak(const std::vector<ulong> Tweak);

private:
	static inline void Mix(ulong &A, ulong &B, unsigned int R)
	{
		A += B;
		B = RotateLeft64(B, R) ^ A;
	}

	static inline void Mix(ulong &A, ulong &B, unsigned int R, ulong K0, ulong K1)
	{
		B += K1;
		A += B + K0;
		B = RotateLeft64(B, R) ^ A;
	}

	static inline ulong RotateLeft64(ulong V, unsigned int B)
	{
		return (V << B) | (V >> (64 - B));
	}
};


#endif