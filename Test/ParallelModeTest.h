#ifndef _CEXTEST_PARALLELMODETEST_H
#define _CEXTEST_PARALLELMODETEST_H

#include "ITest.h"
#include "../CEX/IBlockCipher.h"
#include "../CEX/ICipherMode.h"
#include "../CEX/IStreamCipher.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;
	using namespace Cipher::Symmetric::Stream;
	using namespace Cipher::Symmetric::Block::Mode;

    /// <remarks>
    /// Kat, integrity, and output comparisons, targeting multi-threaded and SIMD cipher mode operations
    /// </remarks>
    class ParallelModeTest : public ITest
    {
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const size_t MIN_ALLOC = 1024;
		static const size_t MAX_ALLOC = 4096;
		static const size_t DEF_BLOCK = 64000;
#if defined(_DEBUG)
		static const size_t TEST_LOOPS = 10;
#else
		static const size_t TEST_LOOPS = 100;
#endif

		bool m_hasAESNI;
		bool m_hasAVX;
		std::vector<std::vector<byte>> m_katExpected;
		size_t m_processorCount;
		TestEventHandler m_progressEvent;

    public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		/// <remarks>
		/// Compares Output between linear and parallel Cipher Modes
		/// </remarks>
		ParallelModeTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~ParallelModeTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:

#if defined(__AVX__)
		// Looping integrity test verifies the SIMD extensions in CTR and CBC modes using AHX
		void CompareAhxSimd();
#endif
		// Looping reduction Kat, compares parallel CTR with vectors generated in sequential mode
		void CompareBcrKat(IBlockCipher* Engine, std::vector<byte> Expected);
		// Looping integrity test, compares CTR multi-threaded/SIMD with sequentially generated output
		void CompareBcrSimd(IBlockCipher* Engine);
		// Looping integrity tests, compares CBC Decrypt multi-threaded/SIMD with sequentially generated output
		void CompareCbcDecrypt(IBlockCipher* Engine1, IBlockCipher* Engine2);
		// Looping CBC/CFB/CTR integrity tests, compares sequential to parallel output
		void CompareParallelLoop();
		// Compares CBC/CFB/CTR output check, compares output across each block access method 
		void CompareParallelOutput();
		// Looping reduction Kat, compares parallel Salsa/Chacha with vectors generated in sequential mode
		void CompareStmKat(IStreamCipher* Engine, std::vector<byte> Expected);
		// Looping integrity test, compares Salsa/Chacha multi-threaded/SIMD with sequentially generated output
		void CompareStmSimd(IStreamCipher* Engine);
		// test each cipher modes access methods, e.g. sequential and parallel Transform() api
		void AccessCheck(ICipherMode* Cipher);

		void BlockCTR(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockDecrypt(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockEncrypt(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void GetBytes(size_t Size, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(std::string Data);
		void ParallelCTR(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void ParallelDecrypt(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		// buffered blocks: t(in, out)
		void Transform1(Mode::ICipherMode *Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output);
		// loop through: t(in, inoff, out, outoff)
		void Transform2(Mode::ICipherMode *Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output);
		// whole array: t(in, inoff, out, outoff, len)
		void Transform3(Mode::ICipherMode* Cipher, std::vector<byte> &Input, std::vector<byte> &Output);
    };
}

#endif

