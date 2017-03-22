#include "SHA2Test.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"

namespace Test
{
	using namespace Digest;

	std::string SHA2Test::Run()
	{
		try
		{
			Initialize();

			TreeParamsTest();
			OnProgress("Passed SHA2Params parameter serialization test..");

			SHA256* sha256 = new SHA256();
			CompareVector(sha256, m_message[0], m_expected256[0]);
			CompareVector(sha256, m_message[1], m_expected256[1]);
			CompareVector(sha256, m_message[2], m_expected256[2]);
			CompareVector(sha256, m_message[3], m_expected256[3]);
			delete sha256;
			OnProgress("Sha2Test: Passed SHA-2 256 bit digest vector tests..");

			SHA512* sha512 = new SHA512();
			CompareVector(sha512, m_message[0], m_expected512[0]);
			CompareVector(sha512, m_message[1], m_expected512[1]);
			CompareVector(sha512, m_message[2], m_expected512[2]);
			CompareVector(sha512, m_message[3], m_expected512[3]);
			delete sha512;
			OnProgress("Sha2Test: Passed SHA-2 512 bit digest vector tests..");

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

	void SHA2Test::CompareVector(IDigest *Digest, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> hash(Digest->DigestSize(), 0);

		Digest->Update(Input, 0, Input.size());
		Digest->Finalize(hash, 0);

		if (Expected != hash)
			throw std::exception("SHA2: Expected hash is not equal!");

		Digest->Compute(Input, hash);
		if (Expected != hash)
			throw std::exception("SHA2: Expected hash is not equal!");
	}

	void SHA2Test::Initialize()
	{
		const char* messageEncoded[4] =
		{
			("616263"),
			(""),
			("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
			("61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475")
		};
		HexConverter::Decode(messageEncoded, 4, m_message);

		const char* exp256Encoded[4] =
		{
			("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
			("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
			("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
		};
		HexConverter::Decode(exp256Encoded, 4, m_expected256);

		const char* exp512Encoded[4] =
		{
			("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
			("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
			("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"),
			("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
		};
		HexConverter::Decode(exp512Encoded, 4, m_expected512);
	}

	void SHA2Test::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}

	void SHA2Test::TreeParamsTest()
	{
		std::vector<byte> code1(8, 7);

		SHA2Params tree1(32, 32, 8);
		tree1.DistributionCode() = code1;
		std::vector<uint8_t> tres = tree1.ToBytes();
		SHA2Params tree2(tres);

		if (!tree1.Equals(tree2))
			throw std::string("SHA2Test: Tree parameters test failed!");

		std::vector<byte> code2(20, 7);
		SHA2Params tree3(0, 64, 1, 128, 8, 1, code2);
		tres = tree3.ToBytes();
		SHA2Params tree4(tres);

		if (!tree3.Equals(tree4))
			throw std::string("SHA2Test: Tree parameters test failed!");
	}
}