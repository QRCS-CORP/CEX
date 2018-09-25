/*
* A minimal 128-bit integer type for curve25519-donna
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
/*
* 64x64->128 bit multiply operation
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef CEX_DONNA128_H
#define CEX_DONNA128_H

#include "CexDomain.h"

NAMESPACE_NUMERIC

/// <summary>
/// An implementation of a segmented (2*64) 128 bit integer
/// </summary>
class Donna128
{
private:

	uint64_t high;
	uint64_t low;

public:

	/// <summary>
	/// Copy constructor
	/// </summary>
	Donna128(const Donna128&) = default;

	/// <summary>
	/// Copy operator
	/// </summary>
	Donna128& operator = (const Donna128&) = default;

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <param name="Low">The low portion of the integer</param>
	/// <param name="High">The high portion of the integer</param>
	Donna128(uint64_t Low = 0, uint64_t High = 0)
		:
		high(High),
		low(Low)
	{ 
	}

	/// <summary>
	/// The Low portion of the integer
	/// </summary>
	uint64_t Low() const 
	{ 
		return low;
	}

	/// <summary>
	/// The High portion of the integer
	/// </summary>
	uint64_t High() const 
	{ 
		return high;
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	inline static const size_t size() 
	{ 
		return 16; 
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	///
	/// <returns>The shifted value</returns>
	inline Donna128 operator >> (size_t Shift)
	{
		Donna128 z(high, low);

		if (Shift > 0)
		{
			const uint64_t CARRY = z.high << (64 - Shift);
			z.high = (z.high >> Shift);
			z.low = (z.low >> Shift) | CARRY;
		}

		return z;
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	///
	/// <returns>The shifted value</returns>
	inline Donna128 operator << (size_t Shift)
	{
		Donna128 z(high, low);

		if (Shift > 0)
		{
			const uint64_t CARRY = z.low >> (64 - Shift);
			z.low = (z.low << Shift);
			z.high = (z.high << Shift) | CARRY;
		}

		return z;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="Mask">The AND mask</param>
	///
	/// <returns>The AND'd value</returns>
	inline uint64_t operator & (uint64_t Mask)
	{
		return low & Mask;
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="Mask">The AND mask</param>
	///
	/// <returns>The AND'd value</returns>
	inline uint64_t operator &= (uint64_t Mask)
	{
		high = 0;
		low &= Mask;

		return low;
	}

	/// <summary>
	/// Add two 128 bit integers
	/// </summary>
	///
	/// <param name="Y">The value to add</param>
	///
	/// <returns>The sum value</returns>
	inline Donna128 operator + (const Donna128 &Y)
	{
		Donna128 z;

		z = *this;
		z += Y;

		return z;
	}

	/// <summary>
	/// Add a 64 bit integer
	/// </summary>
	///
	/// <param name="Y">The value to add</param>
	///
	/// <returns>The sum value</returns>
	inline Donna128 operator + (uint64_t Y)
	{
		Donna128 z;

		z = *this;
		z += Y;

		return z;
	}

	/// <summary>
	/// Add a 128bit value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	///
	/// <returns>The sum value</returns>
	inline Donna128& operator += (const Donna128 &X)
	{
		low += X.low;
		high += X.high;

		const uint64_t CARRY = (low < X.low);
		high += CARRY;

		return *this;
	}

	/// <summary>
	/// Add a 64bit value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	///
	/// <returns>The sum value</returns>
	inline Donna128& operator += (uint64_t X)
	{
		low += X;
		const uint64_t CARRY = (low < X);
		high += CARRY;

		return *this;
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="Y">The value to multiply</param>
	///
	/// <returns>The sum value</returns>
	inline Donna128 operator * (uint64_t Y)
	{
		uint64_t low;
		uint64_t high;

		low = 0;
		high = 0;

		Donna128::Mul64x64To128(Low(), Y, &low, &high);

		return Donna128(low, high);
	}

	/// <summary>
	/// Bitwise OR of two integers
	/// </summary>
	///
	/// <param name="Y">The value to OR</param>
	///
	/// <returns>The OR'd value</returns>
	inline Donna128 operator | (const Donna128 &Y)
	{
		return Donna128(Low() | Y.Low(), High() | Y.High());
	}

	/// <summary>
	/// Shift right with a carry bit
	/// </summary>
	///
	/// <param name="X">The value to shift</param>
	/// <param name="Shift">The shift register</param>
	///
	/// <returns>The sum value</returns>
	inline static uint64_t CarryShift(Donna128 &X, size_t Shift)
	{
		Donna128 z(X.high, X.low);

		return (z >> Shift).Low();
	}

	/// <summary>
	/// Shift a 64 bit integer right with a carry bit
	/// </summary>
	///
	/// <param name="X">The value to shift</param>
	/// <param name="Shift">The shift register</param>
	///
	/// <returns>The sum value</returns>
	inline static uint64_t CarryShift(uint64_t &X, size_t Shift)
	{
		return X >> Shift;
	}

	/// <summary>
	/// Shift and combine two 128 bit integers
	/// </summary>
	///
	/// <param name="X">The first value to combine</param>
	/// <param name="S1">The first shift register</param>
	/// <param name="Y">The second value to combine</param>
	/// <param name="S2">The second shift register</param>
	///
	/// <returns>The sum value</returns>
	inline static uint64_t CombineLow(Donna128 &X, size_t S1, Donna128 &Y, size_t S2)
	{
		Donna128 z;

		z = (X >> S1) | (Y << S2);

		return z.Low();
	}

#if defined(CEX_NATIVE_UINT128)

	/// <summary>
	/// Shift a 128 bit integer right with a carry bit
	/// </summary>
	///
	/// <param name="X">The value to shift</param>
	/// <param name="Shift">The shift register</param>
	///
	/// <returns>The sum value</returns>
	inline static uint64_t CarryShift(uint128_t X, size_t Shift)
	{
		return static_cast<uint64_t>(X >> Shift);
	}

	/// <summary>
	/// Shift and combine two 128 bit integers
	/// </summary>
	///
	/// <param name="X">The first value to combine</param>
	/// <param name="S1">The first shift register</param>
	/// <param name="Y">The second value to combine</param>
	/// <param name="S2">The second shift register</param>
	///
	/// <returns>The sum value</returns>
	inline static uint64_t CombineLow(uint128_t X, size_t S1, uint128_t Y, size_t S2)
	{
		return static_cast<uint64_t>((X >> S1) | (Y << S2));
	}
#endif

	/// <summary>
	/// Perform a 64x64->128 bit multiplication
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	/// <param name="Y">The factor</param>
	/// <param name="Low">The low return value</param>
	/// <param name="High">The high return value</param>
	inline static void Mul64x64To128(uint64_t X, uint64_t Y, uint64_t* Low, uint64_t* High)
	{
#if defined(CEX_FAST_64X64_MUL)
		CEX_FAST_64X64_MUL(X, Y, Low, High);
#else

		// Do a 64x64->128 multiply using four 32x32->64 multiplies plus
		// some adds and shifts. Last resort for CPUs like UltraSPARC (with
		// 64-bit registers/ALU, but no 64x64->128 multiply) or 32-bit CPUs.
		const size_t HWORD_BITS = 32;
		const uint32_t HWORD_MASK = 0xFFFFFFFFUL;

		const uint32_t ah = (X >> HWORD_BITS);
		const uint32_t al = (X  & HWORD_MASK);
		const uint32_t bh = (Y >> HWORD_BITS);
		const uint32_t bl = (Y  & HWORD_MASK);

		uint64_t x0 = static_cast<uint64_t>(ah) * bh;
		uint64_t x1 = static_cast<uint64_t>(al) * bh;
		uint64_t x2 = static_cast<uint64_t>(ah) * bl;
		uint64_t x3 = static_cast<uint64_t>(al) * bl;

		// this cannot overflow as (2^32-1)^2 + 2^32-1 < 2^64-1
		x2 += x3 >> HWORD_BITS;
		// this one can overflow
		x2 += x1;
		// propagate the carry if any
		x0 += static_cast<uint64_t>(static_cast<bool>(x2 < x1)) << HWORD_BITS;

		*High = x0 + (x2 >> HWORD_BITS);
		*Low = ((x2 & HWORD_MASK) << HWORD_BITS) + (x3 & HWORD_MASK);
#endif
	}
};

NAMESPACE_NUMERICEND
#endif

