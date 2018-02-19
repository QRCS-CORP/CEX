#include "KeccakTest.h"
#include "../CEX/Keccak256.h"
#include "../CEX/Keccak512.h"
#include "../CEX/Keccak1024.h"

namespace Test
{
	using namespace Digest;
	using CEX::Key::Symmetric::SymmetricKey;

	const std::string KeccakTest::DESCRIPTION = "SHA-3 Vector KATs; tests the 256, 512, and 1024 versions of Keccak.";
	const std::string KeccakTest::FAILURE = "FAILURE! ";
	const std::string KeccakTest::SUCCESS = "SUCCESS! All Keccak tests have executed succesfully.";

	KeccakTest::KeccakTest()
		:
		m_progressEvent()
	{
		Initialize();
	}

	KeccakTest::~KeccakTest()
	{
	}

	const std::string KeccakTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KeccakTest::Progress()
	{
		return m_progressEvent;
	}

	std::string KeccakTest::Run()
	{
		try
		{
			SHA3256KatTest();
			OnProgress(std::string("KeccakTest: Passed SHA3 256 bit digest vector tests.."));

			SHA3512KatTest();
			OnProgress(std::string("KeccakTest: Passed SHA3 512 bit digest vector tests.."));

			Keccak1024KatTest();
			OnProgress(std::string("KeccakTest: Passed Keccak 1024 bit digest vector tests.."));

			TreeParamsTest();
			OnProgress(std::string("KeccakTest: Passed KeccakParams parameter serialization test.."));

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

	void KeccakTest::SHA3256KatTest()
	{
		std::vector<byte> output(32);
		Keccak256 dgt(false);

		dgt.Update(m_message[0], 0, m_message[0].size());
		dgt.Finalize(output, 0);

		if (output != m_exp256[0])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Update(m_message[1], 0, m_message[1].size());
		dgt.Finalize(output, 0);

		if (output != m_exp256[1])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Compute(m_message[2], output);

		if (output != m_exp256[2])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Compute(m_message[3], output);

		if (output != m_exp256[3])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}
	}

	void KeccakTest::SHA3512KatTest()
	{
		std::vector<byte> output(64);
		Keccak512 dgt(false);

		dgt.Update(m_message[0], 0, m_message[0].size());
		dgt.Finalize(output, 0);

		if (output != m_exp512[0])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Update(m_message[1], 0, m_message[1].size());
		dgt.Finalize(output, 0);

		if (output != m_exp512[1])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Compute(m_message[2], output);

		if (output != m_exp512[2])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Compute(m_message[3], output);

		if (output != m_exp512[3])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}
	}

	void KeccakTest::Keccak1024KatTest()
	{
		std::vector<byte> output(128);
		Keccak1024 dgt(false);

		dgt.Update(m_message[0], 0, m_message[0].size());
		dgt.Finalize(output, 0);

		if (output != m_exp1024[0])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Update(m_message[1], 0, m_message[1].size());
		dgt.Finalize(output, 0);

		if (output != m_exp1024[1])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Compute(m_message[2], output);

		if (output != m_exp1024[2])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		dgt.Compute(m_message[3], output);

		if (output != m_exp1024[3])
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}
	}

	void KeccakTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> exp256 =
		{
			std::string("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"),
			std::string("3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532"),
			std::string("41C0DBA2A9D6240849100376A8235E2C82E1B9998A999E21DB32DD97496D3376"),
			std::string("79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787")
		};
		HexConverter::Decode(exp256, 4, m_exp256);

		const std::vector<std::string> exp512 =
		{
			std::string("A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A6"
				"15B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26"),
			std::string("B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E"
				"10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0"),
			std::string("04A371E84ECFB5B8B77CB48610FCA8182DD457CE6F326A0FD3D7EC2F1E91636D"
				"EE691FBE0C985302BA1B0D8DC78C086346B533B49C030D99A27DAF1139D6E75E"),
			std::string("E76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA8"
				"1B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00")
		};
		HexConverter::Decode(exp512, 4, m_exp512);

		const std::vector<std::string> exp1024 =
		{
			std::string("8865E419509F0CFBB8366F0AE6742BCB2B519FB490E2D0B65E553BBFAF109631"
				"4F85EA9D571963ADF4FE178C62402AE4C19D890C58547A12A5EA54EE256B9295"
				"4F20257829A51A3F4AE039D699CA7DD280849DE3CD0EFDF53CC4306D22D98172"
				"BE81D5A2ED864AF9FE66962D25A992212D1841493D5B705DDD9A7015B1D7F77F"),
			std::string("FDF6E604576AC811ED4C56B622ED96DB05DB69009CBE6BC1F3FD6290E28DC45E"
				"618C5B121F21A104007763F42A845FE07717D5397C926E15C1358A0145BAE19A"
				"6A9C686095C6AEDDC82A694B822BD7196611F6FF47097D26FCCF6E6FC0A62F43"
				"3B61B879B1E455AECEF8CBF05877B064951DF191DF7C7F03B650A7BA97DC364C"),
			std::string("7A249A8B16A498972251B3E1505AE7643E11298D3906A9109D8B8879C9FB2780"
				"0A99E7D1E35DAEBA15EC8E5F197050EEE06A754DA93CA734756363DC7C71587C"
				"2532479B27AD5C98B943293397AB0D18AE2CEA7650E6F3F5768EAC6724943BBD"
				"118FF0D90F09C56391DAE15F3F09D0D42480EA9F55CD1E2A308CA915E9D1F7CA"),
			std::string("8AB191D915937401AD20EA293A5CC133D701E3D6839589BF817DE4974B2636AC"
				"9D9028BBE219B62F02CDB2862182CD252712C4886D7165F627E3D43487EDBBD5"
				"7ECE1F528B7BF214F0168BA89DDD91880A1EFEFF29AFB7EAFF3E62D5BCE43D24"
				"BA3A2659C2843D22D6A183C68E7432F28C34DC2597B958D80452B22F21AA9D40")
		};
		HexConverter::Decode(exp1024, 4, m_exp1024);

		const std::vector<std::string> message =
		{
			std::string(""),
			std::string("616263"),
			std::string("6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"),
			std::string("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
				"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
				"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3")
		};
		HexConverter::Decode(message, 4, m_message);
		/*lint -restore */
	}

	void KeccakTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void KeccakTest::TreeParamsTest()
	{
		std::vector<byte> code1(8, 7);

		KeccakParams tree1(32, 32, 8);
		tree1.DistributionCode() = code1;
		std::vector<byte> tres = tree1.ToBytes();
		KeccakParams tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw std::string("KeccakTest: Tree parameters test failed!");
		}

		std::vector<byte> code2(20, 7);
		KeccakParams tree3(0, 64, 1, 128, 8, 1, code2);
		tres = tree3.ToBytes();
		KeccakParams tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw std::string("KeccakTest: Tree parameters test failed!");
		}
	}
}
