#include "GMACTest.h"
#include "../CEX/GMAC.h"
#include "../CEX/RHX.h"

namespace Test
{
	using Cipher::Symmetric::Block::RHX;
	using Cipher::Symmetric::Block::IBlockCipher;

	std::string GMACTest::Run()
	{
		try
		{
			Initialize();

			size_t N = 9; // P: 0-4, 9
			GMACCompare(m_key[N], m_nonce[N], m_plainText[N], m_expectedCode[N]);

			for (size_t i = 0; i < m_key.size(); ++i)
				GMACCompare(m_key[i], m_nonce[i], m_plainText[i], m_expectedCode[i]);
			OnProgress(std::string("GMACTest: Passed GMAC known answer vector tests.."));

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

	void GMACTest::GMACCompare(std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &PlainText, std::vector<byte> &MacCode)
	{
		Mac::GMAC gen(Enumeration::BlockCiphers::Rijndael);
		Key::Symmetric::SymmetricKey kp(Key, Nonce);
		gen.Initialize(kp);
		gen.Update(PlainText, 0, PlainText.size());

		std::vector<byte> code(16);
		gen.Finalize(code, 0);
		code.resize(MacCode.size());

		if (MacCode != code)
			throw TestException("GMAC: Tags do not match!");
	}

	void GMACTest::Initialize()
	{
		const char* keyEncoded[11] =
		{
			("11754cd72aec309bf52f7687212e8957"),
			("272f16edb81a7abbea887357a58c1917"),
			("81b6844aab6a568c4556a2eb7eae752f"),
			("cde2f9a9b1a004165ef9dc981f18651b"),
			("b01e45cc3088aaba9fa43d81d481823f"),
			("77be63708971c4e240d1cb79e8d77feb"),
			("bea48ae4980d27f357611014d4486625"),
			("99e3e8793e686e571d8285c564f75e2b"),
			("c77acd1b0918e87053cb3e51651e7013"),
			("d0f1f4defa1e8c08b4b26d576392027c"),
			("3cce72d37933394a8cac8a82deada8f0")
		};
		HexConverter::Decode(keyEncoded, 11, m_key);

		const char* nonceEncoded[11] =
		{
			("3c819d9a9bed087615030b65"),
			("794ec588176c703d3d2a7a07"),
			("ce600f59618315a6829bef4d"),
			("29512c29566c7322e1e33e8e"),
			("5a2c4a66468713456a4bd5e1"),
			("e0e00f19fed7ba0136a797f3"),
			("32bddb5c3aa998a08556454c"),
			("c2dd0ab868da6aa8ad9c0d23"),
			("39ff857a81745d10f718ac00"),
			("42b4f01eb9f5a1ea5b1eb73b0fb0baed54f387ecaa0393c7d7dffc6af50146ecc021abf7eb9038d4303d91f8d741a11743166c0860208bcc02c6258fd9511a2fa626f96d60b72fcff773af4e88e7a923506e4916ecbd814651e9f445adef4ad6a6b6c7290cc13b956130eef5b837c939fcac0cbbcc9656cd75b13823ee5acdac"),
			("aa2f0d676d705d9733c434e481972d4888129cf7ea55c66511b9c0d25a92a174b1e28aa072f27d4de82302828955aadcb817c4907361869bd657b45ff4a6f323871987fcf9413b0702d46667380cd493ed24331a28b9ce5bbfa82d3a6e7679fcce81254ba64abcad14fd18b22c560a9d2c1cd1d3c42dac44c683edf92aced894")
		};
		HexConverter::Decode(nonceEncoded, 11, m_nonce);

		const char* plainEncoded[11] =
		{
			(""),
			(""),
			(""),
			(""),
			(""),
			("7a43ec1d9c0a5a78a0b16533a6213cab"),
			("8a50b0b8c7654bced884f7f3afda2ead"),
			("b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c5917ee476541809ac6867a8c399309fc"),
			("407992f82ea23b56875d9a3cb843ceb83fd27cb954f7c5534d58539fe96fb534502a1b38ea4fac134db0a42de4be1137"),
			(""),
			("5686b458e9c176f4de8428d9ebd8e12f569d1c7595cf49a4b0654ab194409f86c0dd3fdb8eb18033bb4338c70f0b97d1")
		};
		HexConverter::Decode(plainEncoded, 11, m_plainText);

		const char* codeEncoded[11] =
		{
			("250327c674aaf477aef2675748cf6971"),
			("b6e6f197168f5049aeda32dafbdaeb"),
			("89b43e9dbc1b4f597dbbc7655bb5"),
			("2e58ce7dabd107c82759c66a75"),
			("014280f944f53c681164b2ff"),
			("209fcc8d3675ed938e9c7166709dd946"),
			("8e0f6d8bf05ffebe6f500eb1"),
			("3f4fba100eaf1f34b0baadaae9995d85"),
			("2a5dc173285375dc82835876"),
			("7ab49b57ddf5f62c427950111c5c4f0d"),
			("a3a9444b21f330c3df64c8b6")
		};
		HexConverter::Decode(codeEncoded, 11, m_expectedCode);
	}

	void GMACTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}