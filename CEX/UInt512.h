#ifndef _CEX_UINT512_H
#define _CEX_UINT512_H

#include "CexDomain.h"
#include "Intrinsics.h"

NAMESPACE_NUMERIC

// TODO: None of this is tested!

/// <summary>
/// An AVX 512 intrinsics wrapper
/// </summary>
class UInt512
{
#if defined(__AVX512__)

public:

	/// <summary>
	/// The internal m512i register value
	/// </summary>
	__m512i zmm;

	//~~~ Constants~~~//

	/// <summary>
	/// A UInt512 initialized with 16x 32bit integers to the value one
	/// </summary>
	inline static const UInt512 ONE()
	{
		return UInt512(_mm512_set1_epi32(1));
	}

	/// <summary>
	/// A UInt512 initialized with 16x 32bit integers to the value 0
	/// </summary>
	inline static const UInt512 ZERO()
	{
		return UInt512(_mm512_set1_epi32(0));
	}

	//~~~ Constructor~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	UInt512() {}

	/// <summary>
	/// Initialize the register with an __m512i value
	/// </summary>
	///
	/// <param name="Z">The 256bit register</param>
	explicit UInt128(__m128i const &Z)
	{
		zmm = Z;
	}

	explicit UInt512(__m512i Input)
	{
		zmm = Input;
	}

	/// <summary>
	/// Initialize with an 8bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt512(const std::vector<byte> &Input, size_t Offset)
	{
		zmm = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 16bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 * 16bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt512(const std::vector<ushort> &Input, size_t Offset)
	{
		zmm = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 32bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 4 * 32bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt512(const std::vector<uint> &Input, size_t Offset)
	{
		zmm = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 64bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 2 * 64bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt512(const std::vector<ulong> &Input, size_t Offset)
	{
		zmm = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 16 * 32bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint32 0</param>
	/// <param name="X1">uint32 1</param>
	/// <param name="X2">uint32 2</param>
	/// <param name="X3">uint32 3</param>
	/// <param name="X4">uint32 4</param>
	/// <param name="X5">uint32 5</param>
	/// <param name="X6">uint32 6</param>
	/// <param name="X7">uint32 7</param>
	/// <param name="X8">uint32 8</param>
	/// <param name="X9">uint32 9</param>
	/// <param name="X10">uint32 10</param>
	/// <param name="X11">uint32 11</param>
	/// <param name="X12">uint32 12</param>
	/// <param name="X13">uint32 13</param>
	/// <param name="X14">uint32 14</param>
	/// <param name="X15">uint32 15</param>
	explicit UInt512(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7,
		uint X8, uint X9, uint X10, uint X11, uint X12, uint X13, uint X14, uint X15)
	{
		zmm = _mm512_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	explicit UInt512(uint X)
	{
		zmm = _mm512_set1_epi32(X);
	}

	//~~~ Load and Store~~~//

	/// <summary>
	/// Load an array into a register in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 512 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	inline void Load(const std::vector<T> &Input, size_t Offset)
	{
		zmm = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[Offset]));
	}

	/// <summary>
	/// Load with 8 * 32bit unsigned integers in Little Endian format
	/// </summary>
	///
	/// <param name="X0">uint32 0</param>
	/// <param name="X1">uint32 1</param>
	/// <param name="X2">uint32 2</param>
	/// <param name="X3">uint32 3</param>
	/// <param name="X4">uint32 4</param>
	/// <param name="X5">uint32 5</param>
	/// <param name="X6">uint32 6</param>
	/// <param name="X7">uint32 7</param>
	/// <param name="X8">uint32 8</param>
	/// <param name="X9">uint32 9</param>
	/// <param name="X10">uint32 10</param>
	/// <param name="X11">uint32 11</param>
	/// <param name="X12">uint32 12</param>
	/// <param name="X13">uint32 13</param>
	/// <param name="X14">uint32 14</param>
	/// <param name="X15">uint32 15</param>
	inline void Load(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7,
		uint X8, uint X9, uint X10, uint X11, uint X12, uint X13, uint X14, uint X15)
	{
		zmm = _mm512_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15);
	}

	/// <summary>
	/// Load an array of T into a register in Little Endian format.
	/// <para>Integers are loaded as 32bit integers regardless the natural size of T</para>
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 512 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	inline void LoadT(const std::vector<T> &Input, size_t Offset)
	{
		zmm = _mm512_set_epi32((uint)Input[Offset], (uint)Input[Offset + 1], (uint)Input[Offset + 2], (uint)Input[Offset + 3],
			(uint)Input[Offset + 4], (uint)Input[Offset + 5], (uint)Input[Offset + 6], (uint)Input[Offset + 7],
				(uint)Input[Offset + 8], (uint)Input[Offset + 9], (uint)Input[Offset + 10], (uint)Input[Offset + 11], 
					(uint)Input[Offset + 12], (uint)Input[Offset + 13], (uint)Input[Offset + 14], (uint)Input[Offset + 15]);
	}

	/// <summary>
	/// Transposes and loads 4 * UInt512 to a T sized array
	/// </summary>
	///
	/// <param name="Input">The data input array</param>
	/// <param name="Offset">The starting position within the input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template <typename T>
	inline static void Load4(const std::vector<T> &Input, size_t Offset, UInt512 &X0, UInt512 &X1, UInt512 &X2, UInt512 &X3)
	{
		X0.Load(Input, Offset);
		X1.Load(Input, Offset + (64 / sizeof(T)));
		X2.Load(Input, Offset + (128 / sizeof(T)));
		X3.Load(Input, Offset + (192 / sizeof(T)));
		Transpose(X0, X1, X2, X3);
	}

	/// <summary>
	/// Store register in an integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Output">The array containing the data; must be at least 512 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	inline void Store(std::vector<T> &Output, size_t Offset) const
	{
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[Offset]), zmm);
	}

	/// <summary>
	/// Transposes and stores 4 * UInt512 to a T sized array
	/// </summary>
	///
	/// <param name="Output">The T data destination array</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template <typename T>
	inline static void Store4(std::vector<T> &Output, size_t Offset, UInt512 &X0, UInt512 &X1, UInt512 &X2, UInt512 &X3)
	{
		Transpose(X0, X1, X2, X3);
		X0.Store(Output, Offset);
		X1.Store(Output, Offset + (64 / sizeof(T)));
		X2.Store(Output, Offset + (128 / sizeof(T)));
		X3.Store(Output, Offset + (192 / sizeof(T)));
	}

	/// <summary>
	/// Transposes and stores 16 * UInt512 to a T sized array
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
	inline static void Store16(std::vector<T> &Output, size_t Offset, UInt512 &X0, UInt512 &X1, UInt512 &X2, UInt512 &X3, UInt512 &X4, UInt512 &X5,
		UInt512 &X6, UInt512 &X7, UInt512 &X8, UInt512 &X9, UInt512 &X10, UInt512 &X11, UInt512 &X12, UInt512 &X13, UInt512 &X14, UInt512 &X15)
	{
		__m512i T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15;

		T0 = _mm512_unpacklo_epi32(X0, X1);
		T1 = _mm512_unpackhi_epi32(X0, X1);
		T2 = _mm512_unpacklo_epi32(X2, X3);
		T3 = _mm512_unpackhi_epi32(X2, X3);
		T4 = _mm512_unpacklo_epi32(X4, X5);
		T5 = _mm512_unpackhi_epi32(X4, X5);
		T6 = _mm512_unpacklo_epi32(X6, X7);
		T7 = _mm512_unpackhi_epi32(X6, X7);
		T8 = _mm512_unpacklo_epi32(X8, X9);
		T9 = _mm512_unpackhi_epi32(X8, X9);
		T10 = _mm512_unpacklo_epi32(X10, X11);
		T11 = _mm512_unpackhi_epi32(X10, X11);
		T12 = _mm512_unpacklo_epi32(X12, X13);
		T13 = _mm512_unpackhi_epi32(X12, X13);
		T14 = _mm512_unpacklo_epi32(X14, X15);
		T15 = _mm512_unpackhi_epi32(X14, X15);

		X0 = _mm512_unpacklo_epi64(T0, T2);
		X1 = _mm512_unpackhi_epi64(T0, T2);
		X2 = _mm512_unpacklo_epi64(T1, T3);
		X3 = _mm512_unpackhi_epi64(T1, T3);
		X4 = _mm512_unpacklo_epi64(T4, T6);
		X5 = _mm512_unpackhi_epi64(T4, T6);
		X6 = _mm512_unpacklo_epi64(T5, T7);
		X7 = _mm512_unpackhi_epi64(T5, T7);
		X8 = _mm512_unpacklo_epi64(T8, T10);
		X9 = _mm512_unpackhi_epi64(T8, T10);
		X10 = _mm512_unpacklo_epi64(T9, T11);
		X11 = _mm512_unpackhi_epi64(T9, T11);
		X12 = _mm512_unpacklo_epi64(T12, T14);
		X13 = _mm512_unpackhi_epi64(T12, T14);
		X14 = _mm512_unpacklo_epi64(T13, T15);
		X15 = _mm512_unpackhi_epi64(T13, T15);

		T0 = _mm512_shuffle_i32x4(X0, X4, 0x88);
		T1 = _mm512_shuffle_i32x4(X1, X5, 0x88);
		T2 = _mm512_shuffle_i32x4(X2, X6, 0x88);
		T3 = _mm512_shuffle_i32x4(X3, X7, 0x88);
		T4 = _mm512_shuffle_i32x4(X0, X4, 0xdd);
		T5 = _mm512_shuffle_i32x4(X1, X5, 0xdd);
		T6 = _mm512_shuffle_i32x4(X2, X6, 0xdd);
		T7 = _mm512_shuffle_i32x4(X3, X7, 0xdd);
		T8 = _mm512_shuffle_i32x4(X8, X12, 0x88);
		T9 = _mm512_shuffle_i32x4(X9, X13, 0x88);
		T10 = _mm512_shuffle_i32x4(X10, X14, 0x88);
		T11 = _mm512_shuffle_i32x4(X11, X15, 0x88);
		T12 = _mm512_shuffle_i32x4(X8, X12, 0xdd);
		T13 = _mm512_shuffle_i32x4(X9, X13, 0xdd);
		T14 = _mm512_shuffle_i32x4(X10, X14, 0xdd);
		T15 = _mm512_shuffle_i32x4(X11, X15, 0xdd);

		X0 = _mm512_shuffle_i32x4(T0, T8, 0x88);
		X1 = _mm512_shuffle_i32x4(T1, T9, 0x88);
		X2 = _mm512_shuffle_i32x4(T2, T10, 0x88);
		X3 = _mm512_shuffle_i32x4(T3, T11, 0x88);
		X4 = _mm512_shuffle_i32x4(T4, T12, 0x88);
		X5 = _mm512_shuffle_i32x4(T5, T13, 0x88);
		X6 = _mm512_shuffle_i32x4(T6, T14, 0x88);
		X7 = _mm512_shuffle_i32x4(T7, T15, 0x88);
		X8 = _mm512_shuffle_i32x4(T0, T8, 0xdd);
		X9 = _mm512_shuffle_i32x4(T1, T9, 0xdd);
		X10 = _mm512_shuffle_i32x4(T2, T10, 0xdd);
		X11 = _mm512_shuffle_i32x4(T3, T11, 0xdd);
		X12 = _mm512_shuffle_i32x4(T4, T12, 0xdd);
		X13 = _mm512_shuffle_i32x4(T5, T13, 0xdd);
		X14 = _mm512_shuffle_i32x4(T6, T14, 0xdd);
		X15 = _mm512_shuffle_i32x4(T7, T15, 0xdd);

		X0.Store(Output, Offset);
		X1.Store(Output, Offset + (64 / sizeof(T)));
		X2.Store(Output, Offset + (128 / sizeof(T)));
		X3.Store(Output, Offset + (192 / sizeof(T)));
		X4.Store(Output, Offset + (256 / sizeof(T)));
		X5.Store(Output, Offset + (320 / sizeof(T)));
		X6.Store(Output, Offset + (384 / sizeof(T)));
		X7.Store(Output, Offset + (448 / sizeof(T)));
		X8.Store(Output, Offset + (512 / sizeof(T)));
		X9.Store(Output, Offset + (576 / sizeof(T)));
		X10.Store(Output, Offset + (640 / sizeof(T)));
		X11.Store(Output, Offset + (704 / sizeof(T)));
		X12.Store(Output, Offset + (768 / sizeof(T)));
		X13.Store(Output, Offset + (832 / sizeof(T)));
		X14.Store(Output, Offset + (896 / sizeof(T)));
		X15.Store(Output, Offset + (960 / sizeof(T)));
	}

	//~~~ Methods~~~//

	/// <summary>
	/// Returns the absolute value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt512</returns>
	inline static UInt512 Abs(const UInt512 &Value)
	{
		return UInt512(_mm512_abs_epi32(Value.zmm));
	}

	/// <summary>
	/// Computes the bitwise AND of the 512-bit value in *this* and the bitwise NOT of the 512-bit value in X
	/// </summary>
	///
	/// <param name="X">The comparison integer</param>
	/// 
	/// <returns>The processed UInt512</returns>
	inline UInt512 AndNot(const UInt512 &X)
	{
		return UInt512(_mm512_andnot_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	const size_t size() { return sizeof(__m512i); }

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotL32(const int Shift)
	{
		zmm = _mm512_or_si512(_mm512_slli_epi32(zmm, static_cast<int>(Shift)), _mm512_srli_epi32(zmm, static_cast<int>(32 - Shift)));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt512</returns>
	inline static  UInt512 RotL32(const UInt512 &X, const int Shift)
	{
		return UInt512(_mm512_or_si512(_mm512_slli_epi32(X.zmm, static_cast<int>(Shift)), _mm512_srli_epi32(X.zmm, static_cast<int>(32 - Shift))));
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
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt512</returns>
	inline static UInt512 RotR32(const UInt512 &X, const int Shift)
	{
		return RotL32(X, 32 - Shift);
	}

	/// <summary>
	/// Shifts the 16 signed 32-bit integers in a right by count bits while shifting in the sign bit
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt512</returns>
	inline static UInt512 ShiftRA(const UInt512 &Value, const int Shift)
	{
		return UInt512(_mm512_sra_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Shifts the 16 signed or unsigned 32-bit integers in a right by count bits while shifting in zeros
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt512</returns>
	inline static UInt512 ShiftRL(const UInt512 &Value, const int Shift)
	{
		return UInt512(_mm512_srl_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UInt512</returns>
	inline UInt512 Swap() const
	{
		__m512i T = zmm;

		T = _mm512_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm512_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt512(_mm512_or_si512(_mm512_srli_epi16(T, 8), _mm512_slli_epi16(T, 8)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UInt512 to process</param>
	/// 
	/// <returns>The byte swapped UInt512</returns>
	inline static UInt512 Swap(UInt512 &X)
	{
		__m512i T = X.zmm;

		T = _mm512_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm512_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt512(_mm512_or_si512(_mm512_srli_epi16(T, 8), _mm512_slli_epi16(T, 8)));
	}

	/// <summary>
	/// Shuffles the registers in 4 * UInt512 structures; to create a linear chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static void Transpose(UInt512 &X0, UInt512 &X1, UInt512 &X2, UInt512 &X3)
	{
		__m512i T0 = _mm512_unpacklo_epi32(X0.zmm, X1.zmm);
		__m512i T1 = _mm512_unpacklo_epi32(X2.zmm, X3.zmm);
		__m512i T2 = _mm512_unpackhi_epi32(X0.zmm, X1.zmm);
		__m512i T3 = _mm512_unpackhi_epi32(X2.zmm, X3.zmm);
		X0.zmm = _mm512_unpacklo_epi64(T0, T1);
		X1.zmm = _mm512_unpackhi_epi64(T0, T1);
		X2.zmm = _mm512_unpacklo_epi64(T2, T3);
		X3.zmm = _mm512_unpackhi_epi64(T2, T3);
	}

	//~~~ Operators~~~//

	/// <summary>
	/// Type cast operator
	/// </summary>
	operator __m512i() const
	{
		return zmm;
	}

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline UInt512 operator + (const UInt512 &X) const
	{
		return UInt512(_mm512_add_epi32(zmm, X.zmm));
	}

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline void operator += (const UInt512 &X)
	{
		zmm = _mm512_add_epi32(zmm, X.zmm);
	}

	/// <summary>
	/// Increase prefix operator
	/// </summary>
	inline UInt512 operator ++ ()
	{
		return UInt512(zmm) + UInt512::ONE();
	}

	/// <summary>
	/// Increase postfix operator
	/// </summary>
	inline UInt512 operator ++ (int)
	{
		return UInt512(zmm) + UInt512::ONE();
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline UInt512 operator - (const UInt512 &X) const
	{
		return UInt512(_mm512_sub_epi32(zmm, X.zmm));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline void operator -= (const UInt512 &X)
	{
		zmm = _mm512_sub_epi32(zmm, X.zmm);
	}

	/// <summary>
	/// Decrease prefix operator
	/// </summary>
	inline UInt512 operator -- ()
	{
		return UInt512(zmm) - ZMM1();
	}

	/// <summary>
	/// Decrease postfix operator
	/// </summary>
	inline UInt512 operator -- (int)
	{
		return UInt512(zmm) - UInt512::ONE();
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline UInt512 operator * (const UInt512 &X) const
	{
		return UInt512(_mm512_mullo_epi32(zmm, X.zmm));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline void operator *= (const UInt512 &X)
	{
		zmm = _mm512_mullo_epi32(zmm, X.zmm);
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt512 operator / (const UInt512 &X) const
	{
		std::vector<uint> tmpA(16);
		std::vector<uint> tmpB(16);
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpA[0]), zmm);
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpB[0]), X.zmm);
		return UInt512(tmpA[15] / tmpB[15], tmpA[14] / tmpB[14], tmpA[13] / tmpB[13], tmpA[12] / tmpB[12],
			tmpA[11] / tmpB[11], tmpA[10] / tmpB[10], tmpA[9] / tmpB[9], tmpA[8] / tmpB[8],
			tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4],
			tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);

		// TODO: finish this
		//return UInt512(_mm512_cvtps_epi32(_mm512_div_ps(_mm512_cvtepi32_ps(zmm), _mm512_cvtepi32_ps(X.zmm))));
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator /= (const UInt512 &X)
	{
		std::vector<uint> tmpA(16);
		std::vector<uint> tmpB(16);
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpA[0]), zmm);
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpB[0]), X.zmm);
		zmm = _mm512_set_epi32(tmpA[15] / tmpB[15], tmpA[14] / tmpB[14], tmpA[13] / tmpB[13], tmpA[12] / tmpB[12],
			tmpA[11] / tmpB[11], tmpA[10] / tmpB[10], tmpA[9] / tmpB[9], tmpA[8] / tmpB[8],
			tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4],
			tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);

		// TODO: finish this
		//zmm = _mm512_cvtps_epi32(_mm512_div_ps(_mm512_cvtepi32_ps(zmm), _mm512_cvtepi32_ps(X.zmm)));
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt512 operator % (const UInt512 &X) const
	{
		return UInt512(UInt512(zmm) - ((UInt512(zmm) / X) * X));
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator %= (const UInt512 &X)
	{
		zmm = UInt512(UInt512(zmm) - ((UInt512(zmm) / X) * X)).zmm;
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline UInt512 operator ^ (const UInt512 &X) const
	{
		return UInt512(_mm512_xor_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline void operator ^= (const UInt512 &X)
	{
		zmm = _mm512_xor_si512(zmm, X.zmm);
	}

	/// <summary>
	/// OR two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt512 operator | (const UInt512 &X)
	{
		return UInt512(_mm512_or_si512(zmm, X.zmm));
	}

	/// <summary>
	/// OR this integer
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline void operator |= (const UInt512 &X)
	{
		zmm = _mm512_or_si512(zmm, X.zmm);
	}

	/// <summary>
	/// Logical OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt512 operator || (const UInt512 &X) const
	{
		return UInt512(zmm) | X;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt512 operator & (const UInt512 &X)
	{
		return UInt512(_mm512_and_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline void operator &= (const UInt512 &X)
	{
		zmm = _mm512_and_si512(zmm, X.zmm);
	}

	/// <summary>
	/// Logical AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt512 operator && (const UInt512 &X) const
	{
		return UInt512(zmm) & X;
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt512 operator << (const int Shift) const
	{
		return UInt512(_mm512_slli_epi32(zmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (const int Shift)
	{
		zmm = _mm512_slli_epi32(zmm, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt512 operator >> (const int Shift) const
	{
		return UInt512(_mm512_srli_epi32(zmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (const int Shift)
	{
		zmm = _mm512_srli_epi32(zmm, Shift);
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline UInt512 operator ~ () const
	{
		return UInt512(_mm512_xor_epi32(zmm, _mm512_set1_epi32(-1)));
	}

	/// <summary>
	/// Greater than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator > (UInt512 const &X) const
	{
		return UInt512(_mm512_cmpgt_epi32_mask(zmm, X.zmm));
	}

	/// <summary>
	/// Less than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator < (UInt512 const &X) const
	{
		return UInt512(_mm512_cmpgt_epi32_mask(X.zmm, zmm));
	}

	/// <summary>
	/// Greater than or equal operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator >= (UInt512 const &X) const
	{
		return UInt512(UInt512(~(X > UInt512(zmm))));
	}

	/// <summary>
	/// Less than operator or equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator <= (UInt512 const &X) const
	{
		return X >= UInt512(zmm);
	}

	/// <summary>
	/// Compare two sets of integers for equality, returns max integer size if equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator == (UInt512 const &X) const
	{
		return UInt512(_mm512_cmpeq_epi32_mask(zmm, X.zmm));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	inline UInt512 operator ! () const
	{
		return UInt512(_mm512_cmpeq_epi32(zmm, _mm512_setzero_si512()));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator != (const UInt512 &X) const
	{
		return ~UInt512(_mm512_cmpneq_epi32_mask(zmm, X.zmm));
	}

#endif
};

NAMESPACE_NUMERICEND
#endif