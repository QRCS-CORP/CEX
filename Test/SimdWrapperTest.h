#ifndef CEXTEST_SIMDWRAPPERTEST_H
#define CEXTEST_SIMDWRAPPERTEST_H

#include "ITest.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

#if defined(__AVX512__)
#	include "../CEX/UInt512.h"
#elif defined(__AVX2__)
#	include "../CEX/UInt256.h"
#elif defined(__AVX__)
#	include "../CEX/UInt128.h"
#endif

namespace Test
{
	/// <summary>
	/// Tests the SIMD wrapper implementations
	/// </summary>
	class SimdWrapperTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize this class
		/// </summary>
		SimdWrapperTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SimdWrapperTest();

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

	private:

		static std::vector<uint> Convert(std::vector<byte> &Input)
		{
			std::vector<uint> ret(Input.size() / sizeof(uint));

			for (size_t i = 0; i < ret.size(); ++i)
			{
				ret[i] = Tools::IntegerTools::LeBytesTo32(Input, i * sizeof(uint));
			}

			return ret;
		}

		template <class T>
		bool SimdEquals(T &A, T &B)
		{
			bool res = false;

#if defined(__AVX512__)
			res = 65535 == _mm512_cmpeq_epi32_mask(A.zmm, B.zmm);
#elif defined(__AVX2__)
			res = 255 == _mm256_movemask_ps(_mm256_cvtepi32_ps(_mm256_cmpeq_epi32(A.ymm, B.ymm)));
#elif defined(__AVX__)
			res = 15 == _mm_movemask_ps(_mm_cvtepi32_ps(_mm_cmpeq_epi32(A.xmm, B.xmm)));
#	endif

			return res;
		}

		template <class T>
		void SimdMathCheck()
		{
			T A, B, C, D, Q;
			Prng::SecureRandom rnd;
			std::vector<uint> tmpA(A.size() / sizeof(uint));
			std::vector<uint> tmpB(tmpA.size());
			std::vector<uint> tmpQ(tmpA.size());
			std::vector<byte> tmpR1;
			std::vector<byte> tmpR2;

			for (size_t i = 0; i < 100; ++i)
			{
				tmpR1 = rnd.Generate(A.size());
				tmpA = Convert(tmpR1);
				tmpR2 = rnd.Generate(B.size());
				tmpB = Convert(tmpR2);

				A = T(tmpA, 0);
				B = T(tmpB, 0);

				for (size_t j = 0; j < tmpA.size(); ++j)
				{
					tmpQ[j] = tmpA[j] + tmpB[j];
				}

				Q = T(tmpQ, 0);
				C = A + B;
				D = A;
				D += B;

				if (!SimdEquals(C, Q) || !SimdEquals(D, Q))
				{
					throw TestException(std::string("SimdMathCheck"), std::string("Add"), std::string("Addition test failed! -SS1"));
				}

				for (size_t j = 0; j < tmpA.size(); ++j)
				{
					tmpQ[j] = tmpA[j] * tmpB[j];
				}

				Q = T(tmpQ, 0);
				C = A * B;
				D = A;
				D *= B;

				if (!SimdEquals(C, Q) || !SimdEquals(D, Q))
				{
					throw TestException(std::string("SimdMathCheck"), std::string("Multiply"), std::string("Multiplication test failed! -SS2"));
				}

				for (size_t j = 0; j < tmpA.size(); ++j)
				{
					tmpQ[j] = tmpA[j] - tmpB[j];
				}

				Q = T(tmpQ, 0);
				C = A - B;
				D = A;
				D -= B;

				if (!SimdEquals(C, Q) || !SimdEquals(D, Q))
				{
					throw TestException(std::string("SimdMathCheck"), std::string("Subtract"), std::string("Subtraction test failed! -SS3"));
				}

				for (size_t j = 0; j < tmpA.size(); ++j)
				{
					tmpQ[j] = tmpA[j] / tmpB[j];
				}

				Q = T(tmpQ, 0);
				C = A / B;
				D = A;
				D /= B;

				if (!SimdEquals(C, Q) || !SimdEquals(D, Q))
				{
					throw TestException(std::string("SimdMathCheck"), std::string("Divide"), std::string("Division test failed! -SS4"));
				}

				for (size_t j = 0; j < tmpA.size(); ++j)
				{
					tmpQ[j] = tmpA[j] % tmpB[j];
				}

				Q = T(tmpQ, 0);
				C = A % B;
				D = A;
				D %= B;

				if (!SimdEquals(C, Q) || !SimdEquals(D, Q))
				{
					throw TestException(std::string("SimdMathCheck"), std::string("Modulus"), std::string("Modulus test failed! -SS5"));
				}
			}
		}

		void OnProgress(const std::string &Data);
	};
}

#endif
