#ifndef _CEX_UINT128_H
#define _CEX_UINT128_H

#include "CexDomain.h"
#include "Intrinsics.h"

NAMESPACE_NUMERIC

/// <summary>
/// An SSE 128 intrinsics wrapper
/// </summary>
class UInt128
{
#if defined(__AVX__)

public:

	/// <summary>
	/// The internal m128i register value
	/// </summary>
	__m128i xmm;

	//~~~ Constants~~~//

	/// <summary>
	/// A UInt128 initialized with 4x 32bit integers to the value one
	/// </summary>
	inline static const UInt128 ONE() 
	{
		return UInt128(_mm_set1_epi32(1));
	}

	/// <summary>
	/// A UInt128 initialized with 4x 32bit integers to the value 0
	/// </summary>
	inline static const UInt128 ZERO()
	{
		return UInt128(_mm_set1_epi32(0));
	}

	//~~~ Constructors~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	UInt128() {}

	/// <summary>
	/// Initialize the register with an __m128i value
	/// </summary>
	///
	/// <param name="X">The 128bit register</param>
	explicit UInt128(__m128i const &X)
	{
		xmm = X;
	}

	/// <summary>
	/// Initialize with an 8bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt128(const std::vector<byte> &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 16bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 8 * 16bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt128(const std::vector<ushort> &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 32bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 4 * 32bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt128(const std::vector<uint> &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 64bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 2 * 64bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt128(const std::vector<ulong> &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 4 * 32bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint 0</param>
	/// <param name="X1">uint 1</param>
	/// <param name="X2">uint 2</param>
	/// <param name="X3">uint 3</param>
	explicit UInt128(uint X0, uint X1, uint X2, uint X3)
	{
		xmm = _mm_set_epi32(X0, X1, X2, X3);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	explicit UInt128(uint X)
	{
		xmm = _mm_set1_epi32(X);
	}

	//~~~ Load and Store~~~//

	/// <summary>
	/// Load an array into a register in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	inline void Load(const std::vector<T> &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Load an array into a register in Little Endian format.
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	inline void Load(const std::vector<uint> &Input, size_t Offset)
	{
		xmm = _mm_set_epi32(Input[Offset], Input[Offset + 1], Input[Offset + 2], Input[Offset + 3]);
	}

	/// <summary>
	/// Load an array of T into a register in Little Endian format.
	/// <para>Integers are loaded as 32bit integers regardless the natural size of T</para>
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	inline void LoadT(const std::vector<T> &Input, size_t Offset)
	{
		xmm = _mm_set_epi32((uint)Input[Offset], (uint)Input[Offset + 1], (uint)Input[Offset + 2], (uint)Input[Offset + 3]);
	}

	/// <summary>
	/// Transposes and loads 4 * UInt128 at 32bit boundaries in Little Endian format to an array of T
	/// </summary>
	///
	/// <param name="Input">The data input array</param>
	/// <param name="Offset">The starting position within the input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template <typename T>
	inline static void Load4(const std::vector<T> &Input, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		X0.Load(Input, Offset);
		X1.Load(Input, Offset + sizeof(T));
		X2.Load(Input, Offset + (sizeof(T) * 2));
		X3.Load(Input, Offset + (sizeof(T) * 3));
		Transpose(X0, X1, X2, X3);
	}

	/// <summary>
	/// Store register in a T size integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Output">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	inline void Store(std::vector<T> &Output, size_t Offset) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), xmm);
	}

	/// <summary>
	/// Transposes and stores 4 * UInt128 to a T sized array
	/// </summary>
	///
	/// <param name="Output">The data destination array</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template <typename T>
	inline static void Store4(std::vector<T> &Output, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		Transpose(X0, X1, X2, X3);
		X0.Store(Output, Offset);
		X1.Store(Output, Offset + (16 / sizeof(T)));
		X2.Store(Output, Offset + (32 / sizeof(T)));
		X3.Store(Output, Offset + (48 / sizeof(T)));
	}

	/// <summary>
	/// Transposes and stores 16 * UInt128 to a byte array
	/// </summary>
	///
	/// <param name="Output">The destination data array</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	/// <param name="X4">Operand 4</param>
	/// <param name="X5">Operand 5</param>
	/// <param name="X6">Operand 6</param>
	/// <param name="X7">Operand 7</param>
	/// <param name="X8">Operand 8</param>
	/// <param name="X9">Operand 9</param>
	/// <param name="X10">Operand 10</param>
	/// <param name="X11">Operand 11</param>
	/// <param name="X12">Operand 12</param>
	/// <param name="X13">Operand 13</param>
	/// <param name="X14">Operand 14</param>
	/// <param name="X15">Operand 15</param>
	template <typename T>
	inline static void Store16(std::vector<T> &Output, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3, UInt128 &X4, UInt128 &X5,
		UInt128 &X6, UInt128 &X7, UInt128 &X8, UInt128 &X9, UInt128 &X10, UInt128 &X11, UInt128 &X12, UInt128 &X13, UInt128 &X14, UInt128 &X15)
	{
		__m128i T0 = _mm_unpacklo_epi32(X0.xmm, X1.xmm);
		__m128i T1 = _mm_unpacklo_epi32(X2.xmm, X3.xmm);
		__m128i T2 = _mm_unpacklo_epi32(X4.xmm, X5.xmm);
		__m128i T3 = _mm_unpacklo_epi32(X6.xmm, X7.xmm);
		__m128i T4 = _mm_unpacklo_epi32(X8.xmm, X9.xmm);
		__m128i T5 = _mm_unpacklo_epi32(X10.xmm, X11.xmm);
		__m128i T6 = _mm_unpacklo_epi32(X12.xmm, X13.xmm);
		__m128i T7 = _mm_unpacklo_epi32(X14.xmm, X15.xmm);
		__m128i T8 = _mm_unpackhi_epi32(X0.xmm, X1.xmm);
		__m128i T9 = _mm_unpackhi_epi32(X2.xmm, X3.xmm);
		__m128i T10 = _mm_unpackhi_epi32(X4.xmm, X5.xmm);
		__m128i T11 = _mm_unpackhi_epi32(X6.xmm, X7.xmm);
		__m128i T12 = _mm_unpackhi_epi32(X8.xmm, X9.xmm);
		__m128i T13 = _mm_unpackhi_epi32(X10.xmm, X11.xmm);
		__m128i T14 = _mm_unpackhi_epi32(X12.xmm, X13.xmm);
		__m128i T15 = _mm_unpackhi_epi32(X14.xmm, X15.xmm);

		X0.xmm = _mm_unpacklo_epi64(T0, T1);
		X1.xmm = _mm_unpacklo_epi64(T2, T3);
		X2.xmm = _mm_unpacklo_epi64(T4, T5);
		X3.xmm = _mm_unpacklo_epi64(T6, T7);
		X4.xmm = _mm_unpackhi_epi64(T0, T1);
		X5.xmm = _mm_unpackhi_epi64(T2, T3);
		X6.xmm = _mm_unpackhi_epi64(T4, T5);
		X7.xmm = _mm_unpackhi_epi64(T6, T7);
		X8.xmm = _mm_unpacklo_epi64(T8, T9);
		X9.xmm = _mm_unpacklo_epi64(T10, T11);
		X10.xmm = _mm_unpacklo_epi64(T12, T13);
		X11.xmm = _mm_unpacklo_epi64(T14, T15);
		X12.xmm = _mm_unpackhi_epi64(T8, T9);
		X13.xmm = _mm_unpackhi_epi64(T10, T11);
		X14.xmm = _mm_unpackhi_epi64(T12, T13);
		X15.xmm = _mm_unpackhi_epi64(T14, T15);

		X0.Store(Output, Offset);
		X1.Store(Output, Offset + (16 / sizeof(T)));
		X2.Store(Output, Offset + (32 / sizeof(T)));
		X3.Store(Output, Offset + (48 / sizeof(T)));
		X4.Store(Output, Offset + (64 / sizeof(T)));
		X5.Store(Output, Offset + (80 / sizeof(T)));
		X6.Store(Output, Offset + (96 / sizeof(T)));
		X7.Store(Output, Offset + (112 / sizeof(T)));
		X8.Store(Output, Offset + (128 / sizeof(T)));
		X9.Store(Output, Offset + (144 / sizeof(T)));
		X10.Store(Output, Offset + (160 / sizeof(T)));
		X11.Store(Output, Offset + (176 / sizeof(T)));
		X12.Store(Output, Offset + (192 / sizeof(T)));
		X13.Store(Output, Offset + (208 / sizeof(T)));
		X14.Store(Output, Offset + (224 / sizeof(T)));
		X15.Store(Output, Offset + (240 / sizeof(T)));
	}

	//~~~ Methods~~~//

	/// <summary>
	/// Returns the absolute value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline static UInt128 Abs(const UInt128 &Value)
	{
		return UInt128(_mm_abs_epi32(Value.xmm));
	}

	/// <summary>
	/// Computes the bitwise AND of the 128-bit value in *this* and the bitwise NOT of the 128-bit value in X
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline UInt128 AndNot(const UInt128 &Value)
	{
		return UInt128(_mm_andnot_si128(xmm, Value.xmm));
	}

	/// <summary>
	/// Returns the bitwise negation of 4 32bit integers
	/// </summary>
	///
	/// <param name="Value">The integers to negate</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline static UInt128 Negate(const UInt128 &Value)
	{
		return UInt128(_mm_sub_epi32(_mm_set1_epi32(0), Value.xmm));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotL32(const int Shift)
	{
		xmm = _mm_or_si128(_mm_slli_epi32(xmm, static_cast<int>(Shift)), _mm_srli_epi32(xmm, static_cast<int>(32 - Shift)));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt128</returns>
	inline static UInt128 RotL32(const UInt128 &Value, const int Shift)
	{
		return UInt128(_mm_or_si128(_mm_slli_epi32(Value.xmm, static_cast<int>(Shift)), _mm_srli_epi32(Value.xmm, static_cast<int>(32 - Shift))));
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotR32(const int Shift)
	{
		RotL32(32 - Shift);
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt128</returns>
	inline static UInt128 RotR32(const UInt128 &Value, const int Shift)
	{
		return RotL32(Value, 32 - Shift);
	}

	/// <summary>
	/// Shifts the 4 signed 32-bit integers in a right by count bits while shifting in the sign bit
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline static UInt128 ShiftRA(const UInt128 &Value, const int Shift)
	{
		return UInt128(_mm_sra_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Shifts the 4 signed or unsigned 32-bit integers in a right by count bits while shifting in zeros.
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline static UInt128 ShiftRL(const UInt128 &Value, const int Shift)
	{
		return UInt128(_mm_srl_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UInt128</returns>
	inline UInt128 Swap() const
	{
		__m128i T = xmm;

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1)); // ?
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt128(_mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UInt128 to process</param>
	/// 
	/// <returns>The byte swapped UInt128</returns>
	inline static UInt128 Swap(UInt128 &X)
	{
		__m128i T = X.xmm;

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt128(_mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8)));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	inline static const size_t size() { return sizeof(__m128i); }

	/// <summary>
	/// Shuffles the registers in 4 * UInt128 structures; to create a sequential chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	inline static void Transpose(UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		__m128i T0 = _mm_unpacklo_epi32(X0.xmm, X1.xmm);
		__m128i T1 = _mm_unpacklo_epi32(X2.xmm, X3.xmm);
		__m128i T2 = _mm_unpackhi_epi32(X0.xmm, X1.xmm);
		__m128i T3 = _mm_unpackhi_epi32(X2.xmm, X3.xmm);
		X0.xmm = _mm_unpacklo_epi64(T0, T1);
		X1.xmm = _mm_unpackhi_epi64(T0, T1);
		X2.xmm = _mm_unpacklo_epi64(T2, T3);
		X3.xmm = _mm_unpackhi_epi64(T2, T3);
	}

	//~~~ Operators~~~//

	/// <summary>
	/// Type cast operator
	/// </summary>
	operator __m128i() const
	{
		return xmm;
	}

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline UInt128 operator + (const UInt128 &X) const
	{
		return UInt128(_mm_add_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline void operator += (const UInt128 &X)
	{
		xmm = _mm_add_epi32(xmm, X.xmm);
	}

	/// <summary>
	/// Increase prefix operator
	/// </summary>
	inline UInt128 operator ++ ()
	{
		return UInt128(xmm) + UInt128::ONE();
	}

	/// <summary>
	/// Increase postfix operator
	/// </summary>
	inline UInt128 operator ++ (int)
	{
		return UInt128(xmm) + UInt128::ONE();
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline UInt128 operator - (const UInt128 &X) const
	{
		return UInt128(_mm_sub_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline void operator -= (const UInt128 &X)
	{
		xmm = _mm_sub_epi32(xmm, X.xmm);
	}

	/// <summary>
	/// Decrease prefix operator
	/// </summary>
	inline UInt128 operator -- ()
	{
		return UInt128(xmm) - UInt128::ONE();
	}

	/// <summary>
	/// Decrease postfix operator
	/// </summary>
	inline UInt128 operator -- (int)
	{
		return UInt128(xmm) - UInt128::ONE();
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline UInt128 operator * (const UInt128 &X) const
	{
		return UInt128(_mm_mullo_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline void operator *= (const UInt128 &X)
	{
		xmm = _mm_mullo_epi32(xmm, X.xmm);
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt128 operator / (const UInt128 &X) const
	{
		std::vector<uint> tmpA(4);
		std::vector<uint> tmpB(4);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&tmpA[0]), xmm);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&tmpB[0]), X.xmm);
		return UInt128(tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);
		// TODO: finish this
		//return UInt128(_mm_cvtps_epi32(_mm_round_ps(_mm_div_ps(_mm_cvtepi32_ps(xmm), _mm_cvtepi32_ps(X.xmm)), _MM_FROUND_TO_ZERO)));
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator /= (const UInt128 &X)
	{
		std::vector<uint> tmpA(4);
		std::vector<uint> tmpB(4);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&tmpA[0]), xmm);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&tmpB[0]), X.xmm);
		xmm = _mm_set_epi32(tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);
		// TODO: finish this
		//xmm = _mm_cvtps_epi32(_mm_round_ps(_mm_div_ps(_mm_cvtepi32_ps(xmm), _mm_cvtepi32_ps(X.xmm)), _MM_FROUND_TO_ZERO));
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt128 operator % (const UInt128 &X) const
	{
		return UInt128(UInt128(xmm) - ((UInt128(xmm) / X) * X));
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator %= (const UInt128 &X)
	{
		xmm = UInt128(UInt128(xmm) - ((UInt128(xmm) / X) * X)).xmm;
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline UInt128 operator ^ (const UInt128 &X) const
	{
		return UInt128(_mm_xor_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline void operator ^= (const UInt128 &X)
	{
		xmm = _mm_xor_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Bitwise OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt128 operator | (const UInt128 &X) const
	{
		return UInt128(_mm_or_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Bitwise OR this integer
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline void operator |= (const UInt128 &X)
	{
		xmm = _mm_or_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Logical OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt128 operator || (const UInt128 &X) const
	{
		return UInt128(xmm) | X;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt128 operator & (const UInt128 &X) const
	{
		return UInt128(_mm_and_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline void operator &= (const UInt128 &X)
	{
		xmm = _mm_and_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Logical AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt128 operator && (const UInt128 &X) const
	{
		return UInt128(xmm) & X;
	}

	/// <summary>
	/// Greater than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator > (UInt128 const &X) const
	{
		return UInt128(_mm_cmpgt_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Less than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator < (UInt128 const &X) const
	{
		return UInt128(_mm_cmplt_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Greater than or equal operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator >= (UInt128 const &X) const
	{
		return UInt128(UInt128(~(X > UInt128(xmm))));
	}

	/// <summary>
	/// Less than operator or equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator <= (UInt128 const &X) const
	{
		return X >= UInt128(xmm);
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt128 operator << (const int Shift) const
	{
		return UInt128(_mm_slli_epi32(xmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (const int Shift)
	{
		xmm = _mm_slli_epi32(xmm, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt128 operator >> (const int Shift) const
	{
		return UInt128(_mm_srli_epi32(xmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (const int Shift)
	{
		xmm = _mm_srli_epi32(xmm, Shift);
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline UInt128 operator ~ () const
	{
		return UInt128(_mm_xor_si128(xmm, _mm_set1_epi32(0xFFFFFFFF)));
	}

	/// <summary>
	/// Compare two sets of integers for equality, returns max integer size if equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator == (UInt128 const &X) const
	{
		return UInt128(_mm_cmpeq_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	inline UInt128 operator ! () const
	{
		return UInt128(_mm_cmpeq_epi32(xmm, _mm_setzero_si128()));
	}

	/// <summary>
	/// Compare this integer for inequality, returns max integer size if inequal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator != (const UInt128 &X) const
	{
		return ~UInt128(_mm_cmpeq_epi32(xmm, X.xmm));
	}

#endif
};

NAMESPACE_NUMERICEND
#endif