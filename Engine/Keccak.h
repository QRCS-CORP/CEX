#ifndef _CEXENGINE_KECCAK_H
#define _CEXENGINE_KECCAK_H

#include "Common.h"

/// <summary>
/// Keccak methods and constants
/// </summary> 
class Keccak
{
private:
	static constexpr ulong C0 = 0x0000000000000001;
	static constexpr ulong C1 = 0x0000000000008082;
	static constexpr ulong C2 = 0x800000000000808a;
	static constexpr ulong C3 = 0x8000000080008000;
	static constexpr ulong C4 = 0x000000000000808b;
	static constexpr ulong C5 = 0x0000000080000001;
	static constexpr ulong C6 = 0x8000000080008081;
	static constexpr ulong C7 = 0x8000000000008009;
	static constexpr ulong C8 = 0x000000000000008a;
	static constexpr ulong C9 = 0x0000000000000088;
	static constexpr ulong C10 = 0x0000000080008009;
	static constexpr ulong C11 = 0x000000008000000a;
	static constexpr ulong C12 = 0x000000008000808b;
	static constexpr ulong C13 = 0x800000000000008b;
	static constexpr ulong C14 = 0x8000000000008089;
	static constexpr ulong C15 = 0x8000000000008003;
	static constexpr ulong C16 = 0x8000000000008002;
	static constexpr ulong C17 = 0x8000000000000080;
	static constexpr ulong C18 = 0x000000000000800a;
	static constexpr ulong C19 = 0x800000008000000a;
	static constexpr ulong C20 = 0x8000000080008081;
	static constexpr ulong C21 = 0x8000000000008080;
	static constexpr ulong C22 = 0x0000000080000001;
	static constexpr ulong C23 = 0x8000000080008008;

public:
	static void TransformBlock(const std::vector<byte> &Data, unsigned int Index, std::vector<ulong> &State, unsigned int BlockSize);

	static inline void Word64sToBytes(const std::vector<ulong> &Input, std::vector<byte> &Output)
	{
		Output.resize(Input.size() * sizeof(ulong), 0);
		memcpy(&Output[0], &Input[0], Output.size());
	}

	static inline void BytesToWord64s(const std::vector<byte> &Input, unsigned int Index, unsigned int Length, std::vector<ulong> &Output)
	{
		Output.resize(Length / sizeof(ulong));
		memcpy(&Output[0], &Input[Index], Length);
	}
};

#endif
