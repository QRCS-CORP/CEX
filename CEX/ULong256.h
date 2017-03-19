#ifndef _CEX_UINT256_H
#define _CEX_UINT256_H

#include "CexDomain.h"
#include "Intrinsics.h"

NAMESPACE_NUMERIC

	/// <summary>
	/// An AVX-256 intrinsics wrapper for unsigned 64bit integer operations
	/// </summary>
	class ULong256
	{
	public:

		/// <summary>
		/// The internal m256i register value
		/// </summary>
		__m256i Register;

		//~~~Constructor~~~//

		/// <summary>
		/// Default constructor; does not initialize the register
		/// </summary>
		explicit ULong256()
		{
		}

		/// <summary>
		/// Initialize with an __m256i integer
		/// </summary>
		///
		/// <param name="Input">The register to copy</param>
		explicit ULong256(__m256i Input)
		{
			this->Register = Input;
		}

		/// <summary>
		/// Initialize with an 8bit unsigned integer array
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		explicit ULong256(const std::vector<byte> &Input, size_t Offset)
		{
			Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
		}

		/// <summary>
		/// Initialize with a 64bit unsigned integer array
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 2 * 64bit uints</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		explicit ULong256(const std::vector<ulong> &Input, size_t Offset)
		{
			Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
		}

		/// <summary>
		/// Initialize with 4 * 64bit unsigned integers
		/// </summary>
		///
		/// <param name="X0">ulong 0</param>
		/// <param name="X1">ulong 1</param>
		/// <param name="X2">ulong 2</param>
		/// <param name="X3">ulong 3</param>
		explicit ULong256(ulong X0, ulong X1, ulong X2, ulong X3)
		{
			Register = _mm256_set_epi64x(X0, X1, X2, X3);
		}

		/// <summary>
		/// Initialize with 1 * 64bit unsigned integer
		/// </summary>
		///
		/// <param name="X">The uint to add</param>
		explicit ULong256(ulong X)
		{
			Register = _mm256_set1_epi64x(X);
		}

		//~~~Load and Store~~~//

		/// <summary>
		/// Load an array into a register in Big Endian format
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		template <typename T>
		void LoadBE(const std::vector<T> &Input, size_t Offset)
		{
			Swap().LoadLE(Input, Offset);
		}

		/// <summary>
		/// Initialize with 4 * 64bit unsigned integers in Big Endian format
		/// </summary>
		///
		/// <param name="X0">uint64 0</param>
		/// <param name="X1">uint64 1</param>
		/// <param name="X2">uint64 2</param>
		/// <param name="X3">uint64 3</param>
		void LoadBE(ulong X0, ulong X1, ulong X2, ulong X3);

		/// <summary>
		/// Load an array into a register in Little Endian format
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		template <typename T>
		void LoadLE(const std::vector<T> &Input, size_t Offset)
		{
			Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
		}

		/// <summary>
		/// Load with 4 * 64bit unsigned integers in Little Endian format
		/// </summary>
		///
		/// <param name="X0">uint64 0</param>
		/// <param name="X1">uint64 1</param>
		/// <param name="X2">uint64 2</param>
		/// <param name="X3">uint64 3</param>
		void LoadLE(ulong X0, ulong X1, ulong X2, ulong X3);

		/// <summary>
		/// Store register in an integer array in Big Endian format
		/// </summary>
		///
		/// <param name="Output">The array containing the data; must be at least 256 bits in length</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		template <typename T>
		void StoreBE(std::vector<T> &Output, size_t Offset) const
		{
			Swap().StoreLE(Output, Offset);
		}

		/// <summary>
		/// Store register in an integer array in Little Endian format
		/// </summary>
		///
		/// <param name="Output">The array containing the data; must be at least 256 bits in length</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		template <typename T>
		void StoreLE(std::vector<T> &Output, size_t Offset) const
		{
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), Register);
		}

		//~~~Public Functions~~~//

		/// <summary>
		/// Computes the bitwise AND of the 256-bit value in *this* and the bitwise NOT of the 256-bit value in Value
		/// </summary>
		///
		/// <param name="Value">The comparison integer</param>
		/// 
		/// <returns>The processed ULong256</returns>
		ULong256 AndNot(const ULong256 &Value);

		/// <summary>
		/// Returns the length of the register in bytes
		/// </summary>
		///
		/// <returns>The registers size</returns>
		static const size_t Length();

		/// <summary>
		/// Computes the 64 bit left rotation of four unsigned integers
		/// </summary>
		///
		/// <param name="Shift">The shift degree; maximum is 64</param>
		void RotL64(const int Shift);

		/// <summary>
		/// Computes the 64 bit left rotation of four unsigned integers
		/// </summary>
		///
		/// <param name="Value">The integer to rotate</param>
		/// <param name="Shift">The shift degree; maximum is 64</param>
		/// 
		/// <returns>The rotated ULong256</returns>
		static ULong256 RotL64(const ULong256 &Value, const int Shift);

		/// <summary>
		/// Computes the 64 bit right rotation of four unsigned integers
		/// </summary>
		///
		/// <param name="Shift">The shift degree; maximum is 64</param>
		void RotR64(const int Shift);

		/// <summary>
		/// Computes the 64 bit right rotation of four unsigned integers
		/// </summary>
		///
		/// <param name="Value">The integer to rotate</param>
		/// <param name="Shift">The shift degree; maximum is 64</param>
		/// 
		/// <returns>The rotated ULong256</returns>
		static ULong256 RotR64(const ULong256 &Value, const int Shift);

		/// <summary>
		/// Load a Uint256 in Big Endian format using uint staggered at multiples of the shift factor
		/// </summary>
		///
		/// <param name="Input">The input byte array</param>
		/// <param name="Offset">The starting offset within the input array</param>
		/// <param name="Shift">The shift factor</param>
		/// 
		/// <returns>A populated UInt128</returns>
		static ULong256 ShuffleLoadBE(const std::vector<byte> &Input, size_t Offset, size_t Shift);

		/// <summary>
		/// Load a Uint256 in Little Endian format using uint staggered at multiples of the shift factor
		/// </summary>
		///
		/// <param name="Input">The input byte array</param>
		/// <param name="Offset">The starting offset within the input array</param>
		/// <param name="Shift">The shift factor</param>
		/// 
		/// <returns>A populated UInt128</returns>
		static ULong256 ShuffleLoadLE(const std::vector<byte> &Input, size_t Offset, size_t Shift);

		/// <summary>
		/// Performs a byte swap on 4 unsigned integers
		/// </summary>
		/// 
		/// <returns>The byte swapped ULong256</returns>
		ULong256 Swap() const;

		/// <summary>
		/// Performs a byte swap on 4 unsigned integers
		/// </summary>
		/// 		
		/// <param name="X">The ULong256 to process</param>
		/// 
		/// <returns>The byte swapped ULong256</returns>
		static ULong256 Swap(ULong256 &X);

		/// <summary>
		/// Copies the register uint8 array to an output array
		/// </summary>
		///
		/// <param name="Output">The output byte array</param>
		/// <param name="Offset">The starting offset within the output array</param>
		void ToUint8(std::vector<byte> &Output, size_t Offset);

		/// <summary>
		/// Copies the register uint16 array to an output array
		/// </summary>
		///
		/// <param name="Output">The output byte array</param>
		/// <param name="Offset">The starting offset within the output array</param>
		void ToUint16(std::vector<ushort> &Output, size_t Offset);

		/// <summary>
		/// Copies the register uint32 array to an output array
		/// </summary>
		///
		/// <param name="Output">The output byte array</param>
		/// <param name="Offset">The starting offset within the output array</param>
		void ToUint32(std::vector<uint> &Output, size_t Offset);

		/// <summary>
		/// Copies the register uint64 array to an output array
		/// </summary>
		///
		/// <param name="Output">The output byte array</param>
		/// <param name="Offset">The starting offset within the output array</param>
		void ToUint64(std::vector<ulong> &Output, size_t Offset);

		//~~~Operators~~~//

		/// <summary>
		/// Add a value to this integer
		/// </summary>
		///
		/// <param name="Value">The value to add</param>
		inline void operator += (const ULong256 &Value)
		{
			Register = _mm256_add_epi64(Register, Value.Register);
		}

		/// <summary>
		/// Add two integers
		/// </summary>
		///
		/// <param name="Value">The value to add</param>
		inline ULong256 operator + (const ULong256 &Value) const
		{
			return ULong256(_mm256_add_epi64(Register, Value.Register));
		}

		/// <summary>
		/// Subtract a value from this integer
		/// </summary>
		///
		/// <param name="Value">The value to subtract</param>
		inline void operator -= (const ULong256 &Value)
		{
			Register = _mm256_sub_epi64(Register, Value.Register);
		}

		/// <summary>
		/// Subtract two integers
		/// </summary>
		///
		/// <param name="Value">The value to subtract</param>
		inline ULong256 operator - (const ULong256 &Value) const
		{
			return ULong256(_mm256_sub_epi64(Register, Value.Register));
		}

		/// <summary>
		/// Multiply a value with this integer
		/// </summary>
		///
		/// <param name="Value">The value to multiply</param>
		inline void operator *= (const ULong256 &Value)
		{
			__m256i tmp1 = _mm256_mul_epu32(Register, Value.Register);
			__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(Register, 4), _mm256_srli_si256(Value.Register, 4));
			Register = _mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0)));
		}

		/// <summary>
		/// Multiply two integers
		/// </summary>
		///
		/// <param name="Value">The value to multiply</param>
		inline ULong256 operator * (const ULong256 &Value) const
		{
			__m256i tmp1 = _mm256_mul_epu32(Register, Value.Register);
			__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(Register, 4), _mm256_srli_si256(Value.Register, 4));
			return ULong256(_mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0))));
		}

		/// <summary>
		/// Divide this integer by a value
		/// </summary>
		///
		/// <param name="Value">The divisor value</param>
		inline void operator /= (const ULong256 &Value)
		{
			// ToDo: fix this
			Register.m256i_u64[0] /= Value.Register.m256i_u64[0];
			Register.m256i_u64[1] /= Value.Register.m256i_u64[1];
			Register.m256i_u64[2] /= Value.Register.m256i_u64[2];
			Register.m256i_u64[3] /= Value.Register.m256i_u64[3];

		}

		/// <summary>
		/// Divide two integers
		/// </summary>
		///
		/// <param name="Value">The divisor value</param>
		inline ULong256 operator / (const ULong256 &Value) const
		{
			// ToDo: fix this
			return ULong256(
				Register.m256i_u64[0] / Value.Register.m256i_u64[0],
				Register.m256i_u64[1] / Value.Register.m256i_u64[1],
				Register.m256i_u64[2] / Value.Register.m256i_u64[2],
				Register.m256i_u64[3] / Value.Register.m256i_u64[3]
			);
		}

		/// <summary>
		/// Get the remainder from a division operation
		/// </summary>
		///
		/// <param name="Value">The divisor value</param>
		inline void operator %= (const ULong256 &Value)
		{
			// ToDo: fix this
			Register.m256i_u64[0] %= Value.Register.m256i_u64[0];
			Register.m256i_u64[1] %= Value.Register.m256i_u64[1];
			Register.m256i_u64[2] %= Value.Register.m256i_u64[2];
			Register.m256i_u64[3] %= Value.Register.m256i_u64[3];
		}

		/// <summary>
		/// Get the remainder from a division operation between two integers
		/// </summary>
		///
		/// <param name="Value">The divisor value</param>
		inline ULong256 operator % (const ULong256 &Value) const
		{
			// ToDo: fix this
			return ULong256(
				Register.m256i_u64[0] % Value.Register.m256i_u64[0],
				Register.m256i_u64[1] % Value.Register.m256i_u64[1],
				Register.m256i_u64[2] % Value.Register.m256i_u64[2],
				Register.m256i_u64[3] % Value.Register.m256i_u64[3]
			);
		}

		/// <summary>
		/// Xor this integer by a value
		/// </summary>
		///
		/// <param name="Value">The value to Xor</param>
		inline void operator ^= (const ULong256 &Value)
		{
			Register = _mm256_xor_si256(Register, Value.Register);
		}

		/// <summary>
		/// Xor two integers
		/// </summary>
		///
		/// <param name="Value">The value to Xor</param>
		inline ULong256 operator ^ (const ULong256 &Value) const
		{
			return ULong256(_mm256_xor_si256(Register, Value.Register));
		}

		/// <summary>
		/// OR this integer
		/// </summary>
		///
		/// <param name="Value">The value to OR</param>
		inline void operator |= (const ULong256 &Value)
		{
			Register = _mm256_or_si256(Register, Value.Register);
		}

		/// <summary>
		/// OR two integers
		/// </summary>
		///
		/// <param name="Value">The value to OR</param>
		inline ULong256 operator | (const ULong256 &Value)
		{
			return ULong256(_mm256_or_si256(Register, Value.Register));
		}

		/// <summary>
		/// AND this integer
		/// </summary>
		///
		/// <param name="Value">The value to AND</param>
		inline void operator &= (const ULong256 &Value)
		{
			Register = _mm256_and_si256(Register, Value.Register);
		}

		/// <summary>
		/// AND two integers
		/// </summary>
		///
		/// <param name="Value">The value to AND</param>
		inline ULong256 operator & (const ULong256 &Value)
		{
			return ULong256(_mm256_and_si256(Register, Value.Register));
		}

		/// <summary>
		/// Left shift this integer
		/// </summary>
		///
		/// <param name="Shift">The shift position</param>
		inline void operator <<= (const int Shift)
		{
			Register = _mm256_slli_epi64(Register, Shift);
		}

		/// <summary>
		/// Left shift two integers
		/// </summary>
		///
		/// <param name="Shift">The shift position</param>
		inline ULong256 operator << (const int Shift) const
		{
			return ULong256(_mm256_slli_epi64(Register, Shift));
		}

		/// <summary>
		/// Right shift this integer
		/// </summary>
		///
		/// <param name="Shift">The shift position</param>
		inline void operator >>= (const int Shift)
		{
			Register = _mm256_srli_epi64(Register, Shift);
		}

		/// <summary>
		/// Right shift two integers
		/// </summary>
		///
		/// <param name="Shift">The shift position</param>
		inline ULong256 operator >> (const int Shift) const
		{
			return ULong256(_mm256_srli_epi64(Register, Shift));
		}

		/// <summary>
		/// Bitwise NOT this integer
		/// </summary>
		inline ULong256 operator ~ () const
		{
			return ULong256(_mm256_xor_si256(Register, _mm256_set1_epi32(0xFFFFFFFF)));
		}
	};

NAMESPACE_NUMERICEND
#endif