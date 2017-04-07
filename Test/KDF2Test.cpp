#include "KDF2Test.h"
#include "../CEX/KDF2.h"
#include "../CEX/SHA256.h"

namespace Test
{
	std::string KDF2Test::Run()
	{
		try
		{
			Initialize();

			TestInit();
			OnProgress(std::string("KDF2Test: Passed initialization tests.."));
			CompareVector(m_key, m_output);
			OnProgress(std::string("KDF2Test: Passed 256 bit vectors test.."));

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

	void KDF2Test::CompareVector(std::vector<byte> &Key, std::vector<byte> &Expected)
	{
		std::vector<byte> output(Expected.size());
		Digest::SHA256* dgt = new Digest::SHA256();
		Kdf::KDF2 gen(dgt);
		gen.Initialize(Key);
		gen.Generate(output, 0, output.size());
		delete dgt;

		if (output != Expected)
			throw TestException("KDF2: Values are not equal!");
	}

	void KDF2Test::Initialize()
	{
		HexConverter::Decode("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4", m_key);
		HexConverter::Decode("10a2403db42a8743cb989de86e668d168cbe6046e23ff26f741e87949a3bba1311ac179f819a3d18412e9eb45668f2923c087c1299005f8d5fd42ca257bc93e8fee0c5a0d2a8aa70185401fbbd99379ec76c663e9a29d0b70f3fe261a59cdc24875a60b4aacb1319fa11c3365a8b79a44669f26fba933d012db213d7e3b16349", m_output);
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
			throw TestException("KDF2: Initialization test failed!");

		// test reset
		gen.Reset();
		gen.Initialize(m_key);
		gen.Generate(outBytes, 0, outBytes.size());
		if (outBytes != m_output)
			throw TestException("KDF2: Initialization test failed!");

	}
}