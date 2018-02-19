#ifndef CEXTEST_MODULELWETEST_H
#define CEXTEST_MODULELWETEST_H

#include "ITest.h"
#include "../CEX/BCR.h"

namespace Test
{
	/// <summary>
	/// ModuleLWE key generation, encryption, and decryption tests
	/// </summary>
	class ModuleLWETest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;
		Prng::BCR* m_rngPtr;

	public:

		/// <summary>
		///  Constructor
		/// </summary>
		ModuleLWETest();

		/// <summary>
		/// Destructor
		/// </summary>
		~ModuleLWETest();

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

		void CipherTextIntegrity();
		void MessageAuthentication();
		void PublicKeyIntegrity();
		void OnProgress(std::string Data);
		void StressLoop();
		void SerializationCompare();
	};
}

#endif
