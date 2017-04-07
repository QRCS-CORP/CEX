#include "SymmetricKeyGeneratorTest.h"
#include "../CEX/SymmetricKeyGenerator.h"
#include "../CEX/CpuDetect.h"

namespace Test
{
	using Common::CpuDetect;
	using namespace Key::Symmetric;

	std::string SymmetricKeyGeneratorTest::Run()
	{
		try
		{
			CheckInit();
			OnProgress(std::string("SymmetricKeyGenerator: Passed initialization tests.."));
			CheckAccess();
			OnProgress(std::string("SymmetricKeyGenerator: Passed output comparison tests.."));

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void SymmetricKeyGeneratorTest::CheckAccess()
	{
		// test each provider/digest for valid output
		SymmetricKeySize keySize(64, 16, 64);
		SymmetricKeyGenerator keyGen;

		SymmetricKey symKey = keyGen.GetSymmetricKey(keySize);
		if (!IsValidKey(symKey))
			throw TestException("CheckAccess: The key is invalid!");

		SymmetricSecureKey secKey = keyGen.GetSecureKey(keySize);
		if (!IsValidKey(secKey))
			throw TestException("CheckAccess: The key is invalid!");

		std::vector<byte> data(128);
		keyGen.GetBytes(data);
		if (!IsGoodRun(data))
			throw TestException("CheckAccess: The key is invalid!");

		data = keyGen.GetBytes(data.size());
		if (!IsGoodRun(data))
			throw TestException("CheckAccess: The key is invalid!");
	}

	void SymmetricKeyGeneratorTest::CheckInit()
	{
		// test each access interface for valid output
		SymmetricKeySize keySize(32, 16, 64);
		CpuDetect detect;
		// check for rdtscp
		if (detect.RDTSCP())
		{
			SymmetricKeyGenerator keyGen1(Digests::SHA256, Providers::CJP);
			SymmetricKey symKey1 = keyGen1.GetSymmetricKey(keySize);
			if (!IsValidKey(symKey1))
				throw TestException("CheckInit: Key generation has failed!");
		}

		SymmetricKeyGenerator keyGen2(Digests::Blake512, Providers::CSP);
		SymmetricKey symKey2 = keyGen2.GetSymmetricKey(keySize);
		if (!IsValidKey(symKey2))
			throw TestException("CheckInit: Key generation has failed!");

		SymmetricKeyGenerator keyGen3(Digests::Keccak256, Providers::ECP);
		SymmetricKey symKey3 = keyGen3.GetSymmetricKey(keySize);
		if (!IsValidKey(symKey3))
			throw TestException("CheckInit: Key generation has failed!");

		SymmetricKeyGenerator keyGen4(Digests::Skein512, Providers::RDP);
		SymmetricKey symKey4 = keyGen4.GetSymmetricKey(keySize);
		if (!IsValidKey(symKey4))
			throw TestException("CheckInit: Key generation has failed!");
	}

	bool SymmetricKeyGeneratorTest::IsGoodRun(const std::vector<byte> &Input)
	{
		// indicates zeroed output or bad run
		for (size_t i = 0; i < Input.size() - 4; ++i)
		{
			if (Input[i] == Input[i + 1] &&
				Input[i + 1] == Input[i + 2] &&
				Input[i + 2] == Input[i + 3])
				return false;
		}
		return true;
	}

	bool SymmetricKeyGeneratorTest::IsValidKey(ISymmetricKey &KeyParam)
	{
		if (KeyParam.Key().size() != 0)
		{
			if (!IsGoodRun(KeyParam.Key()))
				return false;
		}
		if (KeyParam.Nonce().size() != 0)
		{
			if (!IsGoodRun(KeyParam.Nonce()))
				return false;
		}
		if (KeyParam.Info().size() != 0)
		{
			if (!IsGoodRun(KeyParam.Info()))
				return false;
		}

		return true;
	}

	void SymmetricKeyGeneratorTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}