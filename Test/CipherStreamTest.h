#ifndef _CEXTEST_STREAMCIPHERTEST_H
#define _CEXTEST_STREAMCIPHERTEST_H

#include "ITest.h"
#include "../CEX/CipherDescription.h"
#include "../CEX/ICipherMode.h"
#include "../CEX/IPadding.h"
#include "../CEX/IStreamCipher.h"

namespace Test
{
	/// <summary>
	/// Tests the CipherStream Processer
	/// </summary>
	class CipherStreamTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const int32_t MIN_ALLOC = 4096;
		static const int32_t MAX_ALLOC = 8192;
		static const int32_t DEF_BLOCK = 64000;

		std::vector<byte> m_cmpText;
		std::vector<byte> m_decText;
		std::vector<byte> m_encText;
		std::vector<byte> m_iv;
		std::vector<byte> m_key;
		std::vector<byte> m_plnText;
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

		/// <summary>
		/// Initialize this class
		/// </summary>
		CipherStreamTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~CipherStreamTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		size_t AllocateRandom(std::vector<byte> &Data, size_t Size = 0, size_t NonAlign = 0);
		void BlockCTR(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockDecrypt(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void BlockEncrypt(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void CbcModeTest();
		void CfbModeTest();
		void CtrModeTest();
		void DescriptionTest(Processing::CipherDescription* Description);
		void FileStreamTest();
		void Initialize();
		void MemoryStreamTest();
		void OnProgress(std::string Data);
		void ParametersTest();
		void ProcessStream(Cipher::Symmetric::Stream::IStreamCipher* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
		void OfbModeTest();
		void SerializeStructTest();
		void StreamTest();
		void StreamModesTest(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, Cipher::Symmetric::Block::Padding::IPadding* Padding);
		void StreamingTest(Cipher::Symmetric::Stream::IStreamCipher* Cipher);
	};
}

#endif

