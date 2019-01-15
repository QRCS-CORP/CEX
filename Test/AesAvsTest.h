#ifndef CEXTEST_AESAVSTEST_H
#define CEXTEST_AESAVSTEST_H

#include "ITest.h"
#include "../CEX/IBlockCipher.h"

namespace Test
{
	using Cipher::Block::IBlockCipher;

    /// <summary>
    /// Tests the Rijndael implementation using the NIST AESAVS vectors.
    /// <para>Using vector sets from: AESAVS certification package: <see href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf"/></para>
    /// </summary>
    class AesAvsTest final : public ITest
    {
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;
		bool m_testNI;

    public:

		//~~~Constructor~~~//

		/// <summary>
		/// NIST AESAVS known answer vector tests
		/// </summary>
		explicit AesAvsTest(bool TestAesNi = false);

		/// <summary>
		/// Destructor
		/// </summary>
		~AesAvsTest();

		//~~~Accessors~~~//

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

		void Kat(IBlockCipher* Cipher, std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void OnProgress(const std::string &Data);
    };
}

#endif
