#ifndef CEXTEST_TESTUTILS_H
#define CEXTEST_TESTUTILS_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using CEX::Key::Symmetric::SymmetricKey;

	class TestUtils
	{
	public:

		static std::string RandomReadableString(size_t Length)
		{
			std::vector<byte> fill(1);
			CEX::Prng::SecureRandom rnd;
			std::string rtxt = "";
			size_t ctr = 0;

			while (ctr < Length)
			{
				rnd.Generate(fill);

				if (fill[0] > 31 && fill[0] < 123 && (fill[0] != 39 || fill[0] != 40 || fill[0] != 41))
				{

					rtxt += static_cast<unsigned char>(fill[0]);
					++ctr;
				}
			}

			return rtxt;
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
		/// Outputs a formatted hex byte array to console
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Size">The number of integers to convert</param>
		/// <param name="Suffix">The integer type suffix</param>
		static void PrintHex(byte* Data, size_t Size)
		{
			std::cout << ToHex(Data, Size);
		}

		/// <summary>
		/// Outputs a delineated, formatted hex byte array to console
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Length">The number of bytes to write</param>
		/// <param name="LineSize">The bumber of bytes to print in each line</param>
		template<typename Array>
		static void PrintHex8(const Array &Data, size_t Length, size_t LineSize)
		{
			for (size_t i = 0; i < Length; ++i)
			{
				if (i != 0 && i % LineSize == 0)
				{
					printf("\n");
				}

				printf("0x%02X, ", Data[i]);
			}
		}

		/// <summary>
		/// Outputs a delineated, formatted hex byte array to console
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Length">The number of bytes to write</param>
		/// <param name="LineSize">The bumber of bytes to print in each line</param>
		template<typename Array>
		static void PrintHex16(const Array &Data, size_t Length, size_t LineSize)
		{
			for (size_t i = 0; i < Length; ++i)
			{
				if (i != 0 && i % LineSize == 0)
				{
					printf("\n");
				}

				printf("0x%04X, ", Data[i]);
			}
		}

		/// <summary>
		/// Outputs a formatted hex byte array to a string
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Size">The number of integers to convert</param>
		/// <param name="Suffix">The integer type suffix</param>
		static std::string ToHex(const byte* Data, size_t Size)
		{
			char const HEXCHR[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
			std::string ret = "";

			for (size_t i = 0; i < Size; ++i)
			{
				const byte val = Data[i];
				ret += std::string("0x");
				ret += HEXCHR[(val & 0xF0) >> 4];
				ret += HEXCHR[(val & 0x0F) >> 0];
				ret += std::string(", ");
			}

			return ret;
		}

		/// <summary>
		/// Outputs formatted hex integer array to a string
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Size">The number of integers to convert</param>
		/// <param name="Suffix">The integer type suffix</param>
		template<typename Array>
		static std::string ToHex(const Array &Data, size_t Size, std::string &Suffix)
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
		/// Outputs formatted hex integer array to a string
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Size">The number of integers to convert</param>
		/// <param name="Suffix">The integer type suffix</param>
		template<typename Array>
		static std::string ToHex(const Array &Data, size_t Size, std::string &Prefix, std::string &Suffix)
		{
			std::string ret = "";
			std::ostringstream oss;

			for (size_t i = 0; i < Size; ++i)
			{
				oss << std::hex << std::uppercase << Prefix << Data[i] << Suffix;
				ret += oss.str();
			}

			return ret;
		}

		static double MeanValue(std::vector<byte> &Input);
		static double ChiSquare(std::vector<byte> &Input);
		static void CopyVector(const std::vector<int> &SrcArray, size_t SrcIndex, std::vector<int> &DstArray, size_t DstIndex, size_t Length);
		static bool IsEqual(std::vector<byte> &A, std::vector<byte> &B);
		static uint64_t GetTimeMs64();
		static SymmetricKey* GetRandomKey(size_t KeySize, size_t IvSize);
		static void GetRandom(std::vector<byte> &Data);

		static bool Read(const std::string &FilePath, std::string &Contents);
		static std::vector<byte> Reduce(std::vector<byte> Seed);
		static void Reverse(std::vector<byte> &Data);

	private:
		// maximum meaningful z value
		const static double Z_MAX;
		// log (sqrt (pi))
		const static double LOG_SQRT_PI;
		// 1 / sqrt (pi)
		const static double I_SQRT_PI;
         // max value to represent exp (x)
		const static double BIGX;
		static double PoChiSq(const double Ax, const int Df);
		static double Poz(const double Z);
	};
}
#endif
