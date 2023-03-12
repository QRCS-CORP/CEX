#ifndef CEXTEST_TESTUTILS_H
#define CEXTEST_TESTUTILS_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using CEX::Cipher::SymmetricKey;

	class TestUtils final
	{
	private:

		// maximum meaningful z value
		static const double Z_MAX;
		// log (sqrt (pi))
		static const double LOG_SQRT_PI;
		// 1 / sqrt (pi)
		static const double I_SQRT_PI;
		// max value to represent exp (x)
		static const double BIGX;

	public:

		/// <summary>
		/// Fill a string with random charactors
		/// </summary>
		/// 
		/// <param name="Length">The number of random charactors</param>
		static std::string GetRandomString(size_t Length);

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
		/// Outputs a formatted hex uint8_t array to console
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Size">The number of integers to convert</param>
		/// <param name="Suffix">The integer type suffix</param>
		static void PrintHex(uint8_t* Data, size_t Size);

		/// <summary>
		/// Prints a hex-formatted 8-bit unsigned integer array
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Prefix">The integer prefix</param>
		/// <param name="Suffix">The integer suffix</param>
		/// <param name="RowLength">The number of integers in each row</param>
		static void PrintHex8(const std::vector<uint8_t> &Data, const std::string &Prefix, const std::string &Suffix, size_t RowLength = 32)
		{
			const size_t ZERLEN = 2;
			std::string tmp = "";
			size_t i;
			size_t j;

			for (i = 1; i < Data.size() + 1; ++i)
			{
				std::ostringstream oss;
				oss << std::hex << std::uppercase << Data[i - 1];
				tmp = oss.str();

				if (tmp.size() < ZERLEN)
				{
					for (j = tmp.size(); j < ZERLEN; ++j)
					{
						tmp = std::string("0") + tmp;
					}
				}

				tmp = Prefix + tmp + Suffix;
				printf("%s", tmp.c_str());
				tmp.clear();

				if (i % RowLength == 0)
				{
					printf("\n");
				}
			}
		}

		/// <summary>
		/// Prints a hex-formatted 16-bit unsigned integer array
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Prefix">The integer prefix</param>
		/// <param name="Suffix">The integer suffix</param>
		/// <param name="RowLength">The number of integers in each row</param>
		static void PrintHex16(const std::vector<uint16_t> &Data, const std::string &Prefix = std::string("0x"), const std::string &Suffix = std::string("U, "), size_t RowLength = 16)
		{
			const size_t ZERLEN = 4;
			std::string tmp = "";
			size_t i;
			size_t j;

			for (i = 1; i < Data.size() + 1; ++i)
			{
				std::ostringstream oss;
				oss << std::hex << std::uppercase << Data[i - 1];
				tmp = oss.str();

				if (tmp.size() < ZERLEN)
				{
					for (j = tmp.size(); j < ZERLEN; ++j)
					{
						tmp = std::string("0") + tmp;
					}
				}

				tmp = Prefix + tmp + Suffix;
				printf("%s", tmp.c_str());
				tmp.clear();

				if (i % RowLength == 0)
				{
					printf("\n");
				}
			}
		}

		/// <summary>
		/// Prints a hex-formatted 32-bit unsigned integer array
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Prefix">The integer prefix</param>
		/// <param name="Suffix">The integer suffix</param>
		/// <param name="RowLength">The number of integers in each row</param>
		static void PrintHex32(const std::vector<uint32_t> &Data, const std::string &Prefix = std::string("0x"), const std::string &Suffix = std::string("UL, "), size_t RowLength = 8)
		{
			const size_t ZERLEN = 8;
			std::string tmp = "";
			size_t i;
			size_t j;

			for (i = 1; i < Data.size() + 1; ++i)
			{
				std::ostringstream oss;
				oss << std::hex << std::uppercase << Data[i - 1];
				tmp = oss.str();

				if (tmp.size() < ZERLEN)
				{
					for (j = tmp.size(); j < ZERLEN; ++j)
					{
						tmp = std::string("0") + tmp;
					}
				}

				tmp = Prefix + tmp + Suffix;
				printf("%s", tmp.c_str());
				tmp.clear();

				if (i % RowLength == 0)
				{
					printf("\n");
				}
			}
		}

		/// <summary>
		/// Prints a hex-formatted 64-bit unsigned integer array
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Prefix">The integer prefix</param>
		/// <param name="Suffix">The integer suffix</param>
		/// <param name="RowLength">The number of integers in each row</param>
		static void PrintHex64(const std::vector<uint64_t> &Data, const std::string &Prefix = std::string("0x"), const std::string &Suffix = std::string("ULL, "), size_t RowLength = 4)
		{
			const size_t ZERLEN = 16;
			std::string tmp = "";
			size_t i;
			size_t j;

			for (i = 1; i < Data.size() + 1; ++i)
			{
				std::ostringstream oss;
				oss << std::hex << std::uppercase << Data[i - 1];
				tmp = oss.str();

				if (tmp.size() < ZERLEN)
				{
					for (j = tmp.size(); j < ZERLEN; ++j)
					{
						tmp = std::string("0") + tmp;
					}
				}

				tmp = Prefix + tmp + Suffix;
				printf("%s", tmp.c_str());
				tmp.clear();

				if (i % RowLength == 0)
				{
					printf("\n");
				}
			}
		}

		/// <summary>
		/// Outputs a formatted hex uint8_t array to a string
		/// </summary>
		/// 
		/// <param name="Data">The array to convert</param>
		/// <param name="Size">The number of integers to convert</param>
		/// <param name="Suffix">The integer type suffix</param>
		static std::string ToHex(const uint8_t* Data, size_t Size)
		{
			char const HEXCHR[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
			std::string ret = "";

			for (size_t i = 0; i < Size; ++i)
			{
				const uint8_t val = Data[i];
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

		/// Internal ///

		static double ChiSquare(std::vector<uint8_t> &Input);
		static void CopyVector(const std::vector<int32_t> &SrcArray, size_t SrcIndex, std::vector<int32_t> &DstArray, size_t DstIndex, size_t Length);
		static void FileClose(std::ifstream& Stream);
		static std::ifstream FileOpen(std::string& FilePath);
		static size_t FileRead(const std::string& FilePath, std::string& Contents);
		static size_t FileReadLine(std::ifstream& Stream, std::string& Line);
		static bool IsEqual(std::vector<uint8_t> &A, std::vector<uint8_t> &B);
		static uint64_t GetTimeMs64();
		static SymmetricKey* GetRandomKey(size_t KeySize, size_t IvSize);
		static void GetRandom(std::vector<uint8_t> &Data);
		static double MeanValue(std::vector<uint8_t> &Input);
		static bool OrderedRuns(const std::vector<uint8_t> &Input, size_t Threshold = 6);
		static std::string RandomReadableString(size_t Length);
		static std::vector<uint8_t> Reduce(std::vector<uint8_t> Seed);
		static void Reverse(std::vector<uint8_t> &Data);
		static bool SuccesiveZeros(const std::vector<uint8_t> &Input, size_t Threshold = 4);

private:

		static double PoChiSq(const double Ax, const int32_t Df);
		static double Poz(const double Z);
	};
}
#endif
