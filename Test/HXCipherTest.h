#ifndef CEXTEST_HXCIPHERTEST_H
#define CEXTEST_HXCIPHERTEST_H

#include "ITest.h"
#include "../CEX/ICipherMode.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block::Mode;

	/// <summary>
	/// HX Cipher monte carlo KAT tests; tests every extended form of each cipher.
	/// <para>Original vectors generated with the CEX++ library.</para>
	/// </summary>
	class HXCipherTest final : public ITest
	{
	private:

		const size_t MONTECARLO_ROUNDS = 100;
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<byte> m_iv;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_rhxExp;
		std::vector<std::vector<byte>> m_shxExp;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer HX Cipher vectors for equality
		/// </summary>
		HXCipherTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~HXCipherTest();

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

		void Initialize();
		void MonteCarloDecrypt(ICipherMode* Cipher, std::vector<byte> &Input, std::vector<byte> &Output);
		void MonteCarloEncrypt(ICipherMode* Cipher, std::vector<byte> &Input, std::vector<byte> &Output);
		void OnProgress(std::string Data);
		void CipherMonteCarlo(Enumeration::BlockCiphers BlockCipherType, Enumeration::BlockCipherExtensions CipherExtensionType, std::vector<byte> &Key, std::vector<byte> &Expected);
	};
}

#endif
