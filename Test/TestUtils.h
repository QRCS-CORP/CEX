#ifndef _CEXTEST_TESTUTILS_H
#define _CEXTEST_TESTUTILS_H

#include <algorithm>
#include <sstream>
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using CEX::Key::Symmetric::SymmetricKey;

	class TestUtils
	{
	public:

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

		static double MeanValue(std::vector<byte> &Input);
		static double ChiSquare(std::vector<byte> &Input);
		static void CopyVector(const std::vector<int> &SrcArray, size_t SrcIndex, std::vector<int> &DstArray, size_t DstIndex, size_t Length);
		static bool IsEqual(std::vector<byte> &A, std::vector<byte> &B);
		static uint64_t GetTimeMs64();
		static SymmetricKey GetRandomKey(size_t KeySize, size_t IvSize);
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
