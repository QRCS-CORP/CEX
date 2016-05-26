#include "KDF2DrbgTest.h"
#include "KDF2Drbg.h"
#include "SHA256.h"

namespace Test
{
	std::string KDF2DrbgTest::Run()
	{
		try
		{
			Initialize();
			CompareVector(_salt, _output);
			OnProgress("KDF2DrbgTest: Passed 256 bit vectors test..");

			return SUCCESS;
		}
		catch (std::string const& ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void KDF2DrbgTest::CompareVector(std::vector<byte> &Salt, std::vector<byte> &Expected)
	{
		std::vector<byte> output(Expected.size());
		CEX::Digest::SHA256* dgt = new CEX::Digest::SHA256();
		CEX::Generator::KDF2Drbg gen(dgt);
		gen.Initialize(Salt);
		gen.Generate(output, 0, output.size());
		delete dgt;

		if (output != Expected)
			throw std::string("KDF2Drbg: Values are not equal!");
	}

	void KDF2DrbgTest::Initialize()
	{
		HexConverter::Decode("10a2403db42a8743cb989de86e668d168cbe6046e23ff26f741e87949a3bba1311ac179f819a3d18412e9eb45668f2923c087c1299005f8d5fd42ca257bc93e8fee0c5a0d2a8aa70185401fbbd99379ec76c663e9a29d0b70f3fe261a59cdc24875a60b4aacb1319fa11c3365a8b79a44669f26fba933d012db213d7e3b16349", _output);
		HexConverter::Decode("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4", _salt);
	}

	void KDF2DrbgTest::OnProgress(char* Data)
	{
		_progressEvent(Data);
	}
}