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

		const size_t TSIZE = sizeof(T);
		const size_t USIZE = sizeof(U);

		Output.resize(Output.size() + ((Input.size() * TSIZE) / USIZE));
		memcpy(&Output[Output.size() - (Input.size() * TSIZE)], &Input[0], Input.size() * TSIZE);

		return Input.size() * TSIZE;
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
	static inline bool Contains(const std::vector<T> &Container, T Value)
	{
		return std::find(Container.begin(), Container.end(), Value) != Container.end();
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