#ifndef _CEXTEST_STREAMCIPHERTEST_H
#define _CEXTEST_STREAMCIPHERTEST_H

#include "ITest.h"
#include "ICipherMode.h"
#include "IStreamCipher.h"
#include "IPadding.h"
#include "CipherDescription.h"

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
		const unsigned int MIN_ALLOC = 512;
		const unsigned int MAX_ALLOC = 4096;
		const unsigned int DEF_BLOCK = 64000;

		TestEventHandler _progressEvent;
		std::vector<byte> _cmpText;
		std::vector<byte> _decText;
		std::vector<byte> _encText;
		std::vector<byte> _iv;
		std::vector<byte> _key;
		std::vector<byte> _plnText;
		unsigned int _processorCount;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		CipherStreamTest()
			:
			_encText(0),
			_cmpText(0),
			_decText(0),
			_iv(16),
			_key(32),
			_plnText(0),
			_processorCount(1)
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		// *** Tests *** //
		void CbcModeTest();
		void CfbModeTest();
		void CtrModeTest();
		void DescriptionTest(CEX::Common::CipherDescription* Description);
		void Initialize();
		void MemoryStreamTest();
		void ParametersTest();
		void OfbModeTest();
		void SerializeStructTest();
		void StreamTest();
		void StreamModesTest(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding);
		void StreamingTest(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher);
		// *** Helpers *** //
		int AllocateRandom(std::vector<byte> &Data, unsigned int Size = 0, int NonAlign = 0);
		void BlockCTR(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
		void BlockDecrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
		void BlockEncrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
		void OnProgress(char* Data);
		void ProcessStream(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
	};
}

#endif

