#ifndef _CEXTEST_STREAMCIPHERTEST_H
#define _CEXTEST_STREAMCIPHERTEST_H

#include "ITest.h"
#include "../CEX/ICipherMode.h"
#include "../CEX/IStreamCipher.h"
#include "../CEX/IPadding.h"
#include "../CEX/CipherDescription.h"

namespace Test
{
	/// <summary>
	/// Tests the CipherStream Processer
	/// </summary>
	class CipherStreamTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "CipherStream Processer Tests.";
		const std::string FAILURE = "FAILURE: ";
		const std::string SUCCESS = "SUCCESS! CipherStream tests have executed succesfully.";
		const int32_t MIN_ALLOC = 4096;
		const int32_t MAX_ALLOC = 8192;
		const int32_t DEF_BLOCK = 64000;

		TestEventHandler m_progressEvent;
		std::vector<byte> m_cmpText;
		std::vector<byte> m_decText;
		std::vector<byte> m_encText;
		std::vector<byte> m_iv;
		std::vector<byte> m_key;
		std::vector<byte> m_plnText;
		size_t m_processorCount;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		CipherStreamTest()
			:
			m_encText(MAX_ALLOC),
			m_cmpText(MAX_ALLOC),
			m_decText(MAX_ALLOC),
			m_iv(16),
			m_key(32),
			m_plnText(MAX_ALLOC),
			m_processorCount(1)
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CbcModeTest();
		void CfbModeTest();
		void CtrModeTest();
		void DescriptionTest(Processing::CipherDescription* Description);
		void FileStreamTest();
		void Initialize();
		void MemoryStreamTest();
		void ParametersTest();
		void OfbModeTest();
		void SerializeStructTest();
		void StreamTest();
		void StreamModesTest(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, Cipher::Symmetric::Block::Padding::IPadding* Padding);
		void StreamingTest(Cipher::Symmetric::Stream::IStreamCipher* Cipher);

		size_t AllocateRandom(std::vector<byte> &Data, size_t Size = 0, size_t NonAlign = 0);
		void BlockCTR(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockDecrypt(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockEncrypt(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void OnProgress(char* Data);
		void ProcessStream(Cipher::Symmetric::Stream::IStreamCipher* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	};
}

#endif

