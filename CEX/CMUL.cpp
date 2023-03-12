#include "CMUL.h"
#include "IntegerTools.h"
#if defined(CEX_HAS_AVX)
#	include "Intrinsics.h"
#endif

NAMESPACE_NUMERIC

using Tools::IntegerTools;

void CMUL::PermuteR128P128U(std::array<uint64_t, CMUL_STATE_SIZE> &State, std::array<uint8_t, CMUL_BLOCK_SIZE> &Output)
{
	const uint64_t X0 = IntegerTools::BeBytesTo64(Output, 0);
	const uint64_t X1 = IntegerTools::BeBytesTo64(Output, sizeof(uint64_t));
	const uint64_t R = 0xE100000000000000ULL;
	uint64_t T0;
	uint64_t T1;
	uint64_t Z0;
	uint64_t Z1;
	uint64_t mpos;
	uint64_t mask;
	uint64_t carry;

	T0 = State[0];
	T1 = State[1];
	Z0 = 0;
	Z1 = 0;
	mpos = 0x8000000000000000ULL;
	mask = 0;
	carry = 0;

	// round 1
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 2
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 3
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 4
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 5
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 6
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 7
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 8
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 9
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 10
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 11
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 12
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 13
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 14
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 15
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 16
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 17
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 18
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 19
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 20
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 21
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 22
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 23
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 24
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 25
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 26
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 27
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 28
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 29
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 30
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 31
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 32
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 33
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 34
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 35
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 36
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 37
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 38
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 39
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 40
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 41
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 42
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 43
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 44
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 45
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 46
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 47
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 48
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 49
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 50
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 51
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 52
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 53
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 54
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 55
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 56
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 57
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 58
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 59
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 60
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 61
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 62
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 63
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 64
	mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	mpos = 0x8000000000000000ULL;

	// round 64 + 1
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 2
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 3
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 4
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 5
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 6
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 7
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 8
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 9
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 10
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 11
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 12
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 13
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 14
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 15
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 16
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 17
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 18
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 19
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 20
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 21
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 22
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 23
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 24
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 25
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 26
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 27
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 28
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 29
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 30
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 31
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 32
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 33
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 34
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 35
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 36
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 37
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 38
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 39
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 40
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 41
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 42
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 43
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 44
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 45
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 46
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 47
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 48
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 49
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 50
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 51
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 52
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 53
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 54
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 55
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 56
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 57
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 58
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 59
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 60
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 61
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 62
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// round 63
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	mpos >>= 1;
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
	T1 = (T1 >> 1) | (T0 << 63);
	T0 = (T0 >> 1) ^ carry;
	// last round
	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	IntegerTools::Be64ToBytes(Z0, Output, 0);
	IntegerTools::Be64ToBytes(Z1, Output, sizeof(uint64_t));
}

void CMUL::PermuteR128P128C(std::array<uint64_t, CMUL_STATE_SIZE> &State, std::array<uint8_t, CMUL_BLOCK_SIZE> &Output)
{
	const uint64_t X0 = IntegerTools::BeBytesTo64(Output, 0);
	const uint64_t X1 = IntegerTools::BeBytesTo64(Output, sizeof(uint64_t));
	const uint64_t R = 0xE100000000000000ULL;
	uint64_t T0;
	uint64_t T1;
	uint64_t Z0;
	uint64_t Z1;
	uint64_t mask;
	uint64_t mpos;
	uint64_t carry;
	size_t i;

	T0 = State[0];
	T1 = State[1];
	Z0 = 0;
	Z1 = 0;
	mpos = 0x8000000000000000ULL;
	mask = 0;
	carry = 0;

	for (i = 0; i != 64; ++i)
	{
		mask = IntegerTools::ExpandMask<uint64_t>(X0 & mpos);
		mpos >>= 1;
		Z0 ^= T0 & mask;
		Z1 ^= T1 & mask;
		carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
		T1 = (T1 >> 1) | (T0 << 63);
		T0 = (T0 >> 1) ^ carry;
	}

	mpos = 0x8000000000000000ULL;

	for (i = 0; i != 63; ++i)
	{
		mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
		mpos >>= 1;
		Z0 ^= T0 & mask;
		Z1 ^= T1 & mask;
		carry = R & IntegerTools::ExpandMask<uint64_t>(T1 & 1ULL);
		T1 = (T1 >> 1) | (T0 << 63);
		T0 = (T0 >> 1) ^ carry;
	}

	mask = IntegerTools::ExpandMask<uint64_t>(X1 & mpos);
	Z0 ^= T0 & mask;
	Z1 ^= T1 & mask;
	IntegerTools::Be64ToBytes(Z0, Output, 0);
	IntegerTools::Be64ToBytes(Z1, Output, sizeof(uint64_t));
}

void CMUL::PermuteR128P128V(std::array<uint64_t, CMUL_STATE_SIZE> &State, std::array<uint8_t, CMUL_BLOCK_SIZE> &Output)
{
#if defined(CEX_HAS_AVX2)

	const __m128i MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	__m128i A;
	__m128i B;
	__m128i T0;
	__m128i T1;
	__m128i T2;
	__m128i T3;
	__m128i T4;
	__m128i T5;

	A = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Output.data()));
	B = _mm_loadu_si128(reinterpret_cast<const __m128i*>(State.data()));
	A = _mm_shuffle_epi8(A, MASK);
	B = _mm_shuffle_epi8(B, _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7));
	B = _mm_shuffle_epi8(B, MASK);
	T0 = _mm_clmulepi64_si128(A, B, 0x00);
	T1 = _mm_clmulepi64_si128(A, B, 0x01);
	T2 = _mm_clmulepi64_si128(A, B, 0x10);
	T3 = _mm_clmulepi64_si128(A, B, 0x11);
	T1 = _mm_xor_si128(T1, T2);
	T2 = _mm_slli_si128(T1, 8);
	T1 = _mm_srli_si128(T1, 8);
	T0 = _mm_xor_si128(T0, T2);
	T3 = _mm_xor_si128(T3, T1);
	T4 = _mm_srli_epi32(T0, 31);
	T0 = _mm_slli_epi32(T0, 1);
	T5 = _mm_srli_epi32(T3, 31);
	T3 = _mm_slli_epi32(T3, 1);
	T2 = _mm_srli_si128(T4, 12);
	T5 = _mm_slli_si128(T5, 4);
	T4 = _mm_slli_si128(T4, 4);
	T0 = _mm_or_si128(T0, T4);
	T3 = _mm_or_si128(T3, T5);
	T3 = _mm_or_si128(T3, T2);
	T4 = _mm_slli_epi32(T0, 31);
	T5 = _mm_slli_epi32(T0, 30);
	T2 = _mm_slli_epi32(T0, 25);
	T4 = _mm_xor_si128(T4, T5);
	T4 = _mm_xor_si128(T4, T2);
	T5 = _mm_srli_si128(T4, 4);
	T3 = _mm_xor_si128(T3, T5);
	T4 = _mm_slli_si128(T4, 12);
	T0 = _mm_xor_si128(T0, T4);
	T3 = _mm_xor_si128(T3, T0);
	T4 = _mm_srli_epi32(T0, 1);
	T1 = _mm_srli_epi32(T0, 2);
	T2 = _mm_srli_epi32(T0, 7);
	T3 = _mm_xor_si128(T3, T1);
	T3 = _mm_xor_si128(T3, T2);
	T3 = _mm_xor_si128(T3, T4);
	T3 = _mm_shuffle_epi8(T3, MASK);

	_mm_storeu_si128(reinterpret_cast<__m128i*>(Output.data()), T3);

#else
	PermuteR128P128C(State, Output);
#endif
}

NAMESPACE_NUMERICEND