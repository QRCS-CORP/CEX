#ifndef CEXEXAMPLE_EXAMPLEUTILS_H
#define CEXEXAMPLE_EXAMPLEUTILS_H

#include "Common.h"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace Example
{
	class ExampleUtils final
	{
	public:

		/// <summary>
		/// Waits for and outputs the user response
		/// </summary>
		static std::string GetResponse();

		/// <summary>
		/// Outputs the current time in milliseconds
		/// </summary>
		static uint64_t GetTimeMs64();

		/// <summary>
		/// Outputs a string to console
		/// </summary>
		/// 
		/// <param name="Data">The string to print</param>
		static void Print(const std::string &Data);

		/// <summary>
		/// Outputs a formatted hex integer array to console
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Size">The number of integers to convert</param>
		/// <param name="Suffix">The integer type suffix</param>
		template<typename Array>
		static void PrintHex(Array &Data, size_t Size, std::string &Prefix = std::string("0x"), std::string &Suffix = std::string(", "))
		{
			for (size_t i = 0; i < Size; i++)
			{
				std::cout << Prefix << std::hex << std::uppercase << Data[i] << Suffix;
				if (i != 0 && (i + 1) % 16 == 0)
				{
					std::cout << std::endl;
				}
			}
		}

		/// <summary>
		/// Pre-size the console
		/// </summary>
		static void SizeConsole();

		static bool StringContains(const std::string &Content, const std::string &Term);

		/// <summary>
		/// Outputs formatted hex integer array to a string
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Size">The number of integers to convert</param>
		/// <param name="Suffix">The integer type suffix</param>
		template<typename Array>
		static std::string ToHex(const Array &Data, size_t Size, const std::string &Suffix)
		{
			std::string ret = "";
			std::ostringstream oss;

			for (size_t i = 0; i < Size; ++i)
			{
				oss << std::hex << std::uppercase << std::string("0x") << Data[i] << Suffix;
				ret += oss.str();
			}

			return ret;
		}

		/// <summary>
		/// Convert an integer to a string
		/// </summary>
		/// 
		/// <param name="Value">The integer value</param>
		/// 
		/// <returns>The string representation</returns>
		template<typename T>
		static std::string ToString(const T &Value)
		{
			std::ostringstream oss;
			oss << Value;
			return oss.str();
		}

		/// <summary>
		/// Pause the console until user input is received
		/// </summary>
		static void WaitForInput();

		/// <summary>
		/// Write a line of text and line-break to the console
		/// </summary>
		/// 
		/// <param name="Data">The string to write</param>
		static void WriteLine(const std::string &Data);
	};
}
#endif
