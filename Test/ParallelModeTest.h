#ifndef _CEXTEST_PARALLELMODETEST_H
#define _CEXTEST_PARALLELMODETEST_H

#include "ITest.h"
#include "../CEX/IBlockCipher.h"
#include "../CEX/ICipherMode.h"
#include "../CEX/IStreamCipher.h"

namespace Test
{
    /// <remarks>
    /// Kat, integrity, and output comparisons, targeting multi-threaded and SIMD cipher mode operations
    /// </remarks>
    class ParallelModeTest : public ITest
    {
	private:
		const std::string DESCRIPTION = "Compares output from parallel and linear modes for equality.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Parallel tests have executed succesfully.";
		const unsigned int MIN_ALLOC = 1024;
		const unsigned int MAX_ALLOC = 4096;
		const unsigned int DEF_BLOCK = 64000;
#if defined(_DEBUG)
		const unsigned int TEST_LOOPS = 10;
#else
		const unsigned int TEST_LOOPS = 100;
#endif

		TestEventHandler m_progressEvent;
		std::vector<std::vector<byte>> m_katExpected;
		unsigned int m_processorCount;
		bool m_hasAESNI;
		bool m_hasSSE;

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
		ParallelModeTest() 
			:
			m_hasAESNI(false),
			m_hasSSE(false),
			m_processorCount(1)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~ParallelModeTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		// Looping integrity test verifies the SIMD extensions in CTR and CBC modes using AHX
		void CompareAhxSimd();
		// Looping reduction Kat, compares parallel CTR with vectors generated in sequential mode
		void CompareBcrKat(CEX::Cipher::Symmetric::Block::IBlockCipher* Engine, std::vector<byte> Expected);
		// Looping integrity test, compares CTR multi-threaded/SIMD with sequentially generated output
		void CompareBcrSimd(CEX::Cipher::Symmetric::Block::IBlockCipher* Engine);
		// Looping integrity tests, compares CBC Decrypt multi-threaded/SIMD with sequentially generated output
		void CompareCbcDecrypt(CEX::Cipher::Symmetric::Block::IBlockCipher* Engine1, CEX::Cipher::Symmetric::Block::IBlockCipher* Engine2);
		// Looping integrity test, compares CBC Wide Block Vectors encryption/decryption output
		void CompareCbcWide(CEX::Cipher::Symmetric::Block::IBlockCipher* Engine);
		// Looping CBC/CFB/CTR integrity tests, compares sequential to parallel output
		void CompareParallelLoop();
		// Compares CBC/CFB/CTR output check, compares output across each block access method 
		void CompareParallelOutput();
		// Looping reduction Kat, compares parallel Salsa/Chacha with vectors generated in sequential mode
		void CompareStmKat(CEX::Cipher::Symmetric::Stream::IStreamCipher* Engine, std::vector<byte> Expected);
		// Looping integrity test, compares Salsa/Chacha multi-threaded/SIMD with sequentially generated output
		void CompareStmSimd(CEX::Cipher::Symmetric::Stream::IStreamCipher* Engine);

		void BlockCTR(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockDecrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockEncrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void GetBytes(size_t Size, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(char* Data);
		void ParallelCTR(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void ParallelDecrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void Transform1(CEX::Cipher::Symmetric::Block::Mode::ICipherMode *Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output);
		void Transform2(CEX::Cipher::Symmetric::Block::Mode::ICipherMode *Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output);
    };
}

#endif

