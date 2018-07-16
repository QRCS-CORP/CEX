#ifndef CEXTEST_CHACHATEST_H
#define CEXTEST_CHACHATEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// ChaCha20 implementation vector comparison tests.
	/// <para>Using the BouncyCastle vectors:
    /// <see href="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/ChaChaTest.java"/></para>
	/// </summary>
	class ChaChaTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_cipherText;
		std::vector<std::vector<byte>> m_iv;
		std::vector<std::vector<byte>> m_key;
		std::vector<byte> m_plainText;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer ChaCha20 vectors for equality
		/// </summary>
		ChaChaTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~ChaChaTest();

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

		void CompareParallel();
		void CompareOutput(int Rounds, std::vector<byte> &Key, std::vector<byte> &Vector, std::vector<byte> &Input, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(std::string Data);
	};
}

#endif
