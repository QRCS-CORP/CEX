#ifndef _CEX_ARRAYUTILS_H
#define _CEX_ARRAYUTILS_H

#include "CexDomain.h"
#include "SecureRandom.h"
#include <algorithm>
#include <iterator>

NAMESPACE_UTILITY

/// <summary>
/// Array functions class
/// </summary>
class ArrayUtils
{
public:

	/// <summary>
	/// Append an integer to an integer array
	/// </summary>
	/// 
	/// <param name="Value">The source integer value</param>
	/// <param name="Output">The destination byte array</param>
	/// 
	/// <returns>The number of bytes added</returns>
	template <typename T, typename U>
	static size_t Append(T Value, std::vector<U> &Output)
	{
		const size_t TSIZE = sizeof(T);
		const size_t USIZE = sizeof(U);

		if (TSIZE > USIZE)
		{
			size_t cnt = (TSIZE / USIZE) + (TSIZE % USIZE);
			size_t pos = Output.size() * USIZE;
			Output.resize(Output.size() + cnt);
			memcpy(&Output[pos], &Value, TSIZE);
		}
		else
		{
			Output.resize(Output.size() + 1);
			memcpy(&Output[Output.size() - 1], &Value, TSIZE);
		}

		return TSIZE;
	}

	/// <summary>
	/// Append an integer to an integer array
	/// </summary>
	/// 
	/// <param name="Value">The source integer value</param>
	/// <param name="Output">The destination byte array</param>
	/// 
	/// <returns>The number of bytes added</returns>
	template <typename T>
	static size_t Append(std::string Value, std::vector<T> &Output)
	{
		const size_t SSIZE = Value.size();
		const size_t TSIZE = sizeof(T);

		std::vector<byte> tmp(0);
		std::transform(std::begin(Value), std::end(Value), std::back_inserter(tmp), [](char c)
		{
			return c - '0';
		});

		size_t pos = Output.size();
		Output.resize(pos + (tmp.size() / TSIZE));
		if (tmp.size() != 0)
			memcpy(&Output[pos], &tmp[0], tmp.size());

		return SSIZE;
	}

	/// <summary>
	/// Append an integer array to another integer array
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="Output">The destination byte array</param>
	/// 
	/// <returns>The number of bytes added</returns>
	template <typename T, typename U>
	static size_t Append(const std::vector<T> &Input, std::vector<U> &Output)
	{
		if (Input.size() == 0)
			return 0;

		const size_t TSIZE = sizeof(T) * Input.size();
		const size_t USIZE = sizeof(U) * Output.size();

		Output.resize(TSIZE + USIZE);
		memcpy(&Output[USIZE], &Input[0], TSIZE);

		return TSIZE;
	}

	/*! \cond PRIVATE */
	CEX_OPTIMIZE_IGNORE
	/*! \endcond */
	/// <summary>
	/// Clear nested arrays of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	template <typename T>
	static void ClearArray(std::vector<std::vector<T>> &Obj)
	{
		if (Obj.size() == 0)
			return;

		for (size_t i = 0; i < Obj.size(); i++)
			ClearVector(Obj[i]);

		Obj.clear();
	}
	/*! \cond PRIVATE */
	CEX_OPTIMIZE_RESUME
	/*! \endcond */

	/// <summary>
	/// Clear an array of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	/*! \cond PRIVATE */
	CEX_OPTIMIZE_IGNORE
	/*! \endcond */
	template <typename T>
	static void ClearVector(std::vector<T> &Obj)
	{
		if (Obj.capacity() == 0)
			return;

		if (Obj.size() != 0)
		{
			static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
			memset_v(Obj.data(), 0, Obj.size() * sizeof(T));
		}

		Obj.clear();
	}
	/*! \cond PRIVATE */
	CEX_OPTIMIZE_RESUME
	/*! \endcond */

	/// <summary>
	/// Constant time comparison of two arrays
	/// </summary>
	/// 
	/// <param name="A">The first array to compare</param>
	/// <param name="B">The second array to compare</param>
	/// 
	/// <returns>True if arrays are equivalant</returns>
	template <typename T>
	static bool Compare(const std::vector<T> &A, const std::vector<T> &B)
	{
		if (A, size() != B.size())
			return false;

		return Compare<T>(A, 0, B, 0, A.size());
	}

	/// <summary>
	/// Constant time comparison of two arrays segments with a length parameter
	/// </summary>
	/// 
	/// <param name="A">The first array to compare</param>
	/// <param name="B">The first array to compare</param>
	/// <param name="Length">The number of elements to compare</param>
	/// 
	/// <returns>True if arrays are equivalant</returns>
	template <typename T>
	static bool Compare(const std::vector<T> &A, const std::vector<T> &B, size_t Length)
	{
		return Compare<T>(A, 0, B, 0, Length);
	}

	/// <summary>
	/// Constant time comparison of two arrays segments with offset and length parameters
	/// </summary>
	/// 
	/// <param name="A">The first array to compare</param>
	/// <param name="AOffset">The starting offset within the 'A' array</param>
	/// <param name="B">The second array to compare</param>
	/// <param name="BOffset">The starting offset within the 'B' array</param>
	/// <param name="Length">The number of elements to compare</param>
	/// 
	/// <returns>True if arrays are equivalant</returns>
	template <typename T>
	static bool Compare(const std::vector<T> &A, size_t AOffset, const std::vector<T> &B, size_t BOffset, size_t Length)
	{
		size_t delta = 0;

		for (size_t i = 0; i < Length; ++i)
			delta |= (A[AOffset + i] ^ B[BOffset + i]);

		return (delta == 0);
	}

	/// <summary>
	/// Return true if the char array contains the value
	/// </summary>
	/// 
	/// <param name="Container">The vector array of values</param>
	/// <param name="Value">The value to find</param>
	/// 
	/// <returns>True if the value exists</returns>
	static bool Contains(const char* Container, char Value);

	/// <summary>
	/// Return true if the vector array contains the value
	/// </summary>
	/// 
	/// <param name="Container">The vector array of values</param>
	/// <param name="Value">The value to find</param>
	/// 
	/// <returns>True if the value exists</returns>
	template <typename T>
	static bool Contains(const std::vector<T> &Container, T Value)
	{
		return std::find(Container.begin(), Container.end(), Value) != Container.end();
	}

	/// <summary>
	/// Treats the array as a large Big Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The vector array of values</param>
	template <typename T>
	static void Increment(std::vector<T> &Counter)
	{
		size_t i = Counter.size();
		while (--i >= 0 && ++Counter[i] == 0) {}
	}

	/// <summary>
	/// Treats a byte array as a large Big Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The vector array of values</param>
	static inline void IncrementBE8(std::vector<byte> &Counter)
	{
		size_t i = Counter.size();
		while (--i >= 0 && ++Counter[i] == 0) {}
	}

	/// <summary>
	/// Treats a byte array as a large Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The vector array of values</param>
	static inline void ArrayUtils::IncrementLE8(std::vector<byte> &Counter)
	{
		int i = -1;
		while (++i < static_cast<int>(Counter.size()) && ++Counter[i] == 0) {}
	}

	/// <summary>
	/// Treats a 2x 64bit integer array as a large Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The counter array to increment</param>
	static inline void IncrementLE32(std::vector<uint> &Counter)
	{
		if (++Counter[0] == 0)
			++Counter[1];
	}

	/// <summary>
	/// Treats a 2x 64bit integer array as a large Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The counter array to increment</param>
	static inline void IncrementLE64(std::vector<ulong> &Counter)
	{
		if (++Counter[0] == 0)
			++Counter[1];
	}

	/// <summary>
	/// Treats an 8bit integer array as a large Big Endian integer, incrementing the total value by a defined length
	/// </summary>
	/// 
	/// <param name="Input">The initial array of bytes</param>
	/// <param name="Output">The modified output array</param>
	/// <param name="Length">The number to increase by</param>
	static inline void IncreaseBE8(const std::vector<byte> &Input, std::vector<byte> &Output, const size_t Length)
	{
		const size_t CTRSZE = Output.size() - 1;
		uint32_t ctrLen = static_cast<uint>(Length);
		std::vector<byte> ctrInc(sizeof(ctrLen));
		memcpy(&ctrInc[0], &ctrLen, ctrInc.size());
		memcpy(&Output[0], &Input[0], Input.size());
		byte carry = 0;

		for (size_t i = CTRSZE; i > 0; --i)
		{
			byte odst = Output[i];
			byte osrc = CTRSZE - i < ctrInc.size() ? ctrInc[CTRSZE - i] : (byte)0;
			byte ndst = (byte)(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[i] = ndst;
		}
	}

	/// <summary>
	/// Treats a 2x 32bit integer array as a large Little Endian integer, incrementing the total value by a defined length
	/// </summary>
	/// 
	/// <param name="Input">The initial array of bytes</param>
	/// <param name="Output">The modified output array</param>
	/// <param name="Length">The number to increase by</param>
	static inline void IncreaseLE32(const std::vector<uint> &Input, std::vector<uint> &Output, const size_t Length)
	{
		memcpy(&Output[0], &Input[0], Input.size() * sizeof(uint));
		Output[0] += static_cast<uint>(Length);
		if (Output[0] < Input[0])
			++Output[1];
	}

	/// <summary>
	/// Treats a 2x 64bit integer array as a large Little Endian integer, incrementing the total value by a defined length
	/// </summary>
	/// 
	/// <param name="Input">The initial array of bytes</param>
	/// <param name="Output">The modified output array</param>
	/// <param name="Length">The number to increase by</param>
	static inline void IncreaseLE64(const std::vector<ulong> &Input, std::vector<ulong> &Output, const size_t Length)
	{
		memcpy(&Output[0], &Input[0], Input.size() * sizeof(ulong));
		Output[0] += static_cast<uint>(Length);
		if (Output[0] < Input[0])
			++Output[1];
	}

	/// <summary>
	/// Shuffle array values to randomly chosen positions
	/// </summary>
	/// 
	/// <param name="Output">The integer array to shuffle</param>
	template <typename T>
	static inline void RandomShuffle(std::vector<T> &Output)
	{
		Prng::SecureRandom rnd;
		const size_t CEIL = Output.size() - 1;

		for (size_t i = 0; i != CEIL; ++i)
		{
			uint32_t pos = rnd.NextUInt32(0, CEIL);
			if (i != pos)
				std::swap(Output[i], Output[pos]);
		}
	}

	/// <summary>
	/// Remove all instances of an integer value from an array
	/// </summary>
	/// 
	/// <param name="Value">The value to remove</param>
	/// <param name="Output">The output integer array</param>
	/// 
	/// <returns>The number of integers in the new array</returns>
	template <typename T>
	static inline size_t Remove(T Value, std::vector<T> &Output)
	{
		std::vector<T> tmp;
		for (size_t i = 0; i < Output.size(); ++i)
		{
			if (Output[i] != Value)
				tmp.push_back(Output[i]);
		}

		Output = tmp;

		return tmp.size();
	}

	/// <summary>
	/// Left shift an array of integers (OCB mode)
	/// </summary>
	/// 
	/// <param name="Input">The value array to shift</param>
	/// <param name="Output">The output integer array</param>
	/// 
	/// <returns>The bit count</returns>
	static inline uint ShiftLeft(const std::vector<byte> &Input, std::vector<byte> &Output)
	{
		size_t ctr = Input.size();
		uint bit = 0;

		do
		{
			--ctr;
			uint b = Input[ctr];
			Output[ctr] = (byte)((b << 1) | bit);
			bit = (b >> 7) & 1;
		} 
		while (ctr > 0);

		return bit;
	}

	/// <summary>
	/// Split a string into a vector of strings
	/// </summary>
	/// 
	/// <param name="Input">The string to split</param>
	/// <param name="Delim">The delimiting character</param>
	/// <param name="Output">The array of split strings</param>
	static void Split(const std::string &Input, char Delim, std::vector<std::string> &Output);

	/// <summary>
	/// Split a string into a vector of strings
	/// </summary>
	/// 
	/// <param name="Input">The string to split</param>
	/// <param name="Delim">The delimiting character</param>
	/// 
	/// <returns>The vector array of split strings</returns>
	static std::vector<std::string> Split(const std::string &Input, char Delim);

	/// <summary>
	/// Convert an integer array to an 8bit byte array
	/// </summary>
	/// 
	/// <param name="Input">The array to convert</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// 
	/// <returns>The vector array of bytes</returns>
	template <typename T>
	static std::vector<byte> ToByteArray(T* Input, size_t Length)
	{
		if (Length == 0 || !Input)
			return std::vector<byte>(0);

		const size_t ESIZE = sizeof(Input[0]);
		const size_t BVLEN = Length * ESIZE;

		std::vector<byte> elems(BVLEN);
		memcpy(&elems[0], &Input[0], BVLEN);

		return elems;
	}

	/// <summary>
	/// Convert an integer array to a string
	/// </summary>
	/// 
	/// <param name="Input">The array to convert</param>
	/// 
	/// <returns>The string representation</returns>
	template <typename T>
	static std::string ToString(T* Input)
	{
		if (!Input)
			return "";

		size_t len = strlen(reinterpret_cast<char*>(Input));
		std::string str(reinterpret_cast<char*>(Input), len);

		return str;
	}

	/// <summary>
	/// Convert an integer vector array to a string
	/// </summary>
	/// 
	/// <param name="Input">The vector array to convert</param>
	/// 
	/// <returns>The string representation</returns>
	template <typename T>
	static std::string ToString(const std::vector<T> &Input)
	{
		if (!Input)
			return "";

		std::string tmp(Input.begin(), Input.end());

		return tmp;
	}
};

NAMESPACE_UTILITYEND
#endif