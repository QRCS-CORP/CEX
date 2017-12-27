#include "KDF2Test.h"
#include "../CEX/KDF2.h"
#include "../CEX/SHA256.h"

namespace Test
{
	const std::string KDF2Test::DESCRIPTION = "KDF2 Drbg SHA-2 test vectors.";
	const std::string KDF2Test::FAILURE = "FAILURE! ";
	const std::string KDF2Test::SUCCESS = "SUCCESS! All KDF2 Drbg tests have executed succesfully.";

	KDF2Test::KDF2Test()
		:
		m_progressEvent()
	{
		Initialize();
	}

	KDF2Test::~KDF2Test()
	{
	}

	const std::string KDF2Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KDF2Test::Progress()
	{
		return m_progressEvent;
	}

	std::string KDF2Test::Run()
	{
		try
		{
			TestInit();
			OnProgress(std::string("KDF2Test: Passed initialization tests.."));
			CompareVector(m_key, m_output);
			OnProgress(std::string("KDF2Test: Passed 256 bit vectors test.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	void KDF2Test::CompareVector(std::vector<byte> &Key, std::vector<byte> &Expected)
	{
		std::vector<byte> output(Expected.size());
		Digest::SHA256* dgt = new Digest::SHA256();
		Kdf::KDF2 gen(dgt);
		gen.Initialize(Key);
		gen.Generate(output, 0, output.size());
		delete dgt;

		if (output != Expected)
		{
			throw TestException("KDF2: Values are not equal!");
		}
	}

	void KDF2Test::Initialize()
	{
		HexConverter::Decode(std::string("032E45326FA859A72EC235ACFF929B15D1372E30B207255F0611B8F785D764374152E0AC009E509E7BA30CD2F1778E113B64E135CF4E2292C75EFE5288EDFDA4"), m_key);
		HexConverter::Decode(std::string("10A2403DB42A8743CB989DE86E668D168CBE6046E23FF26F741E87949A3BBA1311AC179F819A3D18412E9EB45668F2923C087C1299005F8D5FD42CA257BC93E8FEE0C5A0D2A8AA70185401FBBD99379EC76C663E9A29D0B70F3FE261A59CDC24875A60B4AACB1319FA11C3365A8B79A44669F26FBA933D012DB213D7E3B16349"), m_output);
	}

	void KDF2Test::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void KDF2Test::TestInit()
	{
		std::vector<byte> outBytes(128, 0);

		// enum access
		Kdf::KDF2 gen(Enumeration::Digests::SHA256);
		gen.Initialize(m_key);
		gen.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output)
		{
			throw TestException("KDF2: Initialization test failed!");
		}

		// test reset
		gen.Reset();
		gen.Initialize(m_key);
		gen.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output)
		{
			throw TestException("KDF2: Initialization test failed!");
		}
	}
}