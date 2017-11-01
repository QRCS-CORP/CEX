#ifndef CEXTEST_CIPHERMODETEST_H
#define CEXTEST_CIPHERMODETEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
	/// Cipher Mode implementations vector comparison test sets.
    /// <para>Using vectors from :NIST Special Publication 800-38A:
    /// <see href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf"/></para>
    /// </summary>
    class CipherModeTest final : public ITest
    {
    private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

        std::vector<std::vector<std::vector<byte>>> m_input;
        std::vector<std::vector<byte>> m_keys;
        std::vector<std::vector<std::vector<byte>>> m_output;
		TestEventHandler m_progressEvent;
        std::vector<std::vector<byte>> m_vectors;

    public:

		/// <summary>
		/// Compares known answer Cipher Mode vectors for equality (NIST 800-38A)
		/// </summary>
		CipherModeTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~CipherModeTest();

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

		void CompareCBC(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void CompareCFB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void CompareCTR(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void CompareECB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void CompareOFB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void Initialize();
		void OnProgress(std::string Data);
    };
}

#endif
