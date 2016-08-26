#ifndef _CEXTEST_PARALLELMODETEST_H
#define _CEXTEST_PARALLELMODETEST_H

#include "ITest.h"
#include "../CEX/IBlockCipher.h"
#include "../CEX/ICipherMode.h"
#include "../CEX/IPadding.h"
#include "../CEX/IStreamCipher.h"

namespace Test
{
    /// <remarks>
    /// Compares the output of modes processed in parallel with their linear counterparts
    /// </remarks>
    class ParallelModeTest : public ITest
    {
	private:
		const std::string DESCRIPTION = "Compares output from parallel and linear modes for equality.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Parallel tests have executed succesfully.";
		const unsigned int MIN_ALLOC = 512;
		const unsigned int MAX_ALLOC = 4096;
		const unsigned int DEF_BLOCK = 64000;
#if defined(_DEBUG)
		const unsigned int TEST_LOOPS = 10;
#else
		const unsigned int TEST_LOOPS = 100;
#endif


		TestEventHandler m_progressEvent;
		std::vector<std::vector<byte>> m_katExpected;
		std::vector<byte> m_cipherText;
		std::vector<byte> m_decText;
		std::vector<byte> m_iv;
		std::vector<byte> m_key;
		std::vector<byte> m_plnText;
		unsigned int m_parallelBlockSize;
		unsigned int m_processorCount;

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
			m_cipherText(MAX_ALLOC),
			m_decText(MAX_ALLOC),
			m_iv(16),
			m_key(32),
			m_parallelBlockSize(DEF_BLOCK),
			m_plnText(MAX_ALLOC),
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
		void CompareCbcDecrypt(CEX::Cipher::Symmetric::Block::IBlockCipher* Engine1, CEX::Cipher::Symmetric::Block::IBlockCipher* Engine2);
		void CompareAhxSimd();
		void CompareBcrSimd(CEX::Cipher::Symmetric::Block::IBlockCipher* Engine);
		void CompareStmSimd(CEX::Cipher::Symmetric::Stream::IStreamCipher* Engine);
		void CompareBcrKat(CEX::Cipher::Symmetric::Block::IBlockCipher* Engine, std::vector<byte> Expected);
		void CompareStmKat(CEX::Cipher::Symmetric::Stream::IStreamCipher* Engine, std::vector<byte> Expected);
		void BlockCTR(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockDecrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding,
		const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockEncrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding,
		const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void CompareParallel();
		void GetBytes(size_t Size, std::vector<byte> &Output);
		void Initialize();
		void ParallelCTR(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void ParallelDecrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input,
		size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void ParallelIntegrity();
		void OnProgress(char* Data);
		void Transform1(CEX::Cipher::Symmetric::Block::Mode::ICipherMode *Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output);
		void Transform2(CEX::Cipher::Symmetric::Block::Mode::ICipherMode *Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output);
    };
}

#endif

