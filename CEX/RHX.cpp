#include "RHX.h"
#include "Rijndael.h"
#include "IntUtils.h"
#include "KdfFromName.h"

NAMESPACE_BLOCK

const std::string RHX::CIPHER_NAME("Rijndael");
const std::string RHX::CLASS_NAME("RHX");
const std::string RHX::DEF_DSTINFO("information string RHX version 1");

//~~~Constructor~~~//

RHX::RHX(BlockCipherExtensions CipherExtension)
	:
	m_cprExtension(CipherExtension),
	m_destroyEngine(true),
	m_expKey(0),
	m_kdfGenerator(CipherExtension == BlockCipherExtensions::None ? nullptr :
		CipherExtension == BlockCipherExtensions::Custom ? throw CryptoSymmetricCipherException("RHX:CTor", "The Kdf can not be null!") :
		Helper::KdfFromName::GetInstance(static_cast<Enumeration::Kdfs>(CipherExtension))),
	m_kdfInfo(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_kdfInfoMax(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0)
{
	LoadState();
}

RHX::RHX(Kdf::IKdf* Kdf)
	:
	m_cprExtension(BlockCipherExtensions::Custom),
	m_destroyEngine(false),
	m_expKey(0),
	m_kdfGenerator(Kdf != nullptr ? Kdf :
		throw CryptoSymmetricCipherException("RHX:CTor", "The Kdf can not be null!")),
	m_kdfInfo(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_kdfInfoMax(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0)
{
	LoadState();
}

RHX::~RHX()
{
	if (!m_isDestroyed)
	{
		m_cprExtension = BlockCipherExtensions::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_kdfInfoMax = 0;
		m_rndCount = 0;

		Utility::IntUtils::ClearVector(m_expKey);
		Utility::IntUtils::ClearVector(m_kdfInfo);
		Utility::IntUtils::ClearVector(m_legalKeySizes);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_kdfGenerator != nullptr)
			{
				m_kdfGenerator.reset(nullptr);
			}
		}
		else
		{
			if (m_kdfGenerator != nullptr)
			{
				m_kdfGenerator.release();
			}
		}
	}
}

//~~~Accessors~~~//

const size_t RHX::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCipherExtensions RHX::CipherExtension()
{
	return m_cprExtension;
}

std::vector<byte> &RHX::DistributionCode()
{
	return m_kdfInfo;
}

const size_t RHX::DistributionCodeMax()
{
	return m_kdfInfoMax;
}

const BlockCiphers RHX::Enumeral()
{
	return (m_cprExtension == BlockCipherExtensions::None) ? BlockCiphers::Rijndael : BlockCiphers::RHX;
}

const bool RHX::IsEncryption()
{
	return m_isEncryption;
}

const bool RHX::IsInitialized()
{
	return m_isInitialized;
}

const std::vector<SymmetricKeySize> &RHX::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string RHX::Name()
{
	std::string txtName = "";

	if (m_cprExtension == BlockCipherExtensions::SHAKE256)
	{
		txtName = CIPHER_NAME + std::string("-SHAKE-256");
	}
	else if (m_cprExtension == BlockCipherExtensions::SHAKE512)
	{
		txtName = CLASS_NAME + std::string("-SHAKE512-");
	}
	else if (m_cprExtension == BlockCipherExtensions::HKDF256)
	{
		txtName = CLASS_NAME + std::string("-HKDF-SHA2-256");
	}
	else if (m_cprExtension == BlockCipherExtensions::HKDF512)
	{
		txtName = CLASS_NAME + std::string("-HKDF-SHA2-512");
	}
	else
	{
		txtName = CIPHER_NAME;
	}

	return txtName;
}

const size_t RHX::Rounds()
{
	return m_rndCount;
}

const size_t RHX::StateCacheSize()
{
	return STATE_PRECACHED;
}

//~~~Public Functions~~~//

void RHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void RHX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void RHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void RHX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void RHX::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, KeyParams.Key().size()))
	{
		throw CryptoSymmetricCipherException("RHX:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	}
	if (m_cprExtension != BlockCipherExtensions::None && KeyParams.Info().size() > m_kdfInfoMax)
	{
		throw CryptoSymmetricCipherException("RHX:Initialize", "Invalid info size! Info parameter must be no longer than DistributionCodeMax size.");
	}

	if (KeyParams.Info().size() > 0)
	{
		m_kdfInfo = KeyParams.Info();
	}

	m_isEncryption = Encryption;

	// expand the key
	ExpandKey(Encryption, KeyParams.Key());

#if defined(CEX_PREFETCH_RHX_TABLES)
	Prefetch();
#endif

	// ready to transform data
	m_isInitialized = true;
}

void RHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_isEncryption)
	{
		Encrypt128(Input, 0, Output, 0);
	}
	else
	{
		Decrypt128(Input, 0, Output, 0);
	}
}

void RHX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
	{
		Encrypt128(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt128(Input, InOffset, Output, OutOffset);
	}
}

void RHX::Transform512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
	{
		Encrypt512(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt512(Input, InOffset, Output, OutOffset);
	}
}

void RHX::Transform1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
	{
		Encrypt1024(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt1024(Input, InOffset, Output, OutOffset);
	}
}

void RHX::Transform2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
	{
		Encrypt2048(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt2048(Input, InOffset, Output, OutOffset);
	}
}

//~~~Key Schedule~~~//

void RHX::ExpandKey(bool Encryption, const std::vector<byte> &Key)
{
	if (m_cprExtension != BlockCipherExtensions::None)
	{
		// hkdf key expansion
		SecureExpand(Key);
	}
	else
	{
		// standard rijndael key expansion + k512
		StandardExpand(Key);
	}

	// inverse cipher
	if (!Encryption)
	{
		size_t blkWords = BLOCK_SIZE / 4;

		// reverse key
		for (size_t i = 0, k = m_expKey.size() - blkWords; i < k; i += blkWords, k -= blkWords)
		{
			for (size_t j = 0; j < blkWords; j++)
			{
				uint temp = m_expKey[i + j];
				m_expKey[i + j] = m_expKey[k + j];
				m_expKey[k + j] = temp;
			}
		}
		// sbox inversion
		for (size_t i = blkWords; i < m_expKey.size() - blkWords; i++)
		{
			m_expKey[i] = IT0[SBox[(m_expKey[i] >> 24)]] ^
				IT1[SBox[static_cast<byte>(m_expKey[i] >> 16)]] ^
				IT2[SBox[static_cast<byte>(m_expKey[i] >> 8)]] ^
				IT3[SBox[static_cast<byte>(m_expKey[i])]];
		}
	}
}

void RHX::SecureExpand(const std::vector<byte> &Key)
{
	// rounds: k256=22, k512=30, k1024=38
	m_rndCount = Key.size() != 128 ? (Key.size() / 4) + 14 : 38;
	// round-key array size
	size_t keySize = ((BLOCK_SIZE / 4) * (m_rndCount + 1));
	std::vector<byte> rawKey(keySize * sizeof(uint), 0);
	// salt is not used
	std::vector<byte> salt(0);
	// initialize the generator
	m_kdfGenerator->Initialize(Key, salt, m_kdfInfo);
	// generate the keying material
	m_kdfGenerator->Generate(rawKey);
	// initialize round-key array
	m_expKey.resize(keySize, 0);

	// copy bytes to working key
	for (size_t i = 0; i < m_expKey.size(); ++i)
	{
		m_expKey[i] = Utility::IntUtils::LeBytesTo32(rawKey, i * sizeof(uint));
	}
}

void RHX::StandardExpand(const std::vector<byte> &Key)
{
	// key in 32 bit words
	size_t keyWords = Key.size() / 4;
	// rounds calculation, 512 gets 22 rounds
	m_rndCount = keyWords + 6;
	// setup expanded key
	m_expKey.resize((BLOCK_SIZE / 4) * (m_rndCount + 1), 0);

	if (keyWords == 16)
	{
		m_expKey[0] = Utility::IntUtils::BeBytesTo32(Key, 0);
		m_expKey[1] = Utility::IntUtils::BeBytesTo32(Key, 4);
		m_expKey[2] = Utility::IntUtils::BeBytesTo32(Key, 8);
		m_expKey[3] = Utility::IntUtils::BeBytesTo32(Key, 12);
		m_expKey[4] = Utility::IntUtils::BeBytesTo32(Key, 16);
		m_expKey[5] = Utility::IntUtils::BeBytesTo32(Key, 20);
		m_expKey[6] = Utility::IntUtils::BeBytesTo32(Key, 24);
		m_expKey[7] = Utility::IntUtils::BeBytesTo32(Key, 28);
		m_expKey[8] = Utility::IntUtils::BeBytesTo32(Key, 32);
		m_expKey[9] = Utility::IntUtils::BeBytesTo32(Key, 36);
		m_expKey[10] = Utility::IntUtils::BeBytesTo32(Key, 40);
		m_expKey[11] = Utility::IntUtils::BeBytesTo32(Key, 44);
		m_expKey[12] = Utility::IntUtils::BeBytesTo32(Key, 48);
		m_expKey[13] = Utility::IntUtils::BeBytesTo32(Key, 52);
		m_expKey[14] = Utility::IntUtils::BeBytesTo32(Key, 56);
		m_expKey[15] = Utility::IntUtils::BeBytesTo32(Key, 60);

		// k512 R: 16,24,32,40,48,56,64,72,80,88, S: 20,28,36,44,52,60,68,76,84
		ExpandRotBlock(m_expKey, 16, 16, 1);
		ExpandSubBlock(m_expKey, 20, 16);
		ExpandRotBlock(m_expKey, 24, 16, 2);
		ExpandSubBlock(m_expKey, 28, 16);
		ExpandRotBlock(m_expKey, 32, 16, 3);
		ExpandSubBlock(m_expKey, 36, 16);
		ExpandRotBlock(m_expKey, 40, 16, 4);
		ExpandSubBlock(m_expKey, 44, 16);
		ExpandRotBlock(m_expKey, 48, 16, 5);
		ExpandSubBlock(m_expKey, 52, 16);
		ExpandRotBlock(m_expKey, 56, 16, 6);
		ExpandSubBlock(m_expKey, 60, 16);
		ExpandRotBlock(m_expKey, 64, 16, 7);
		ExpandSubBlock(m_expKey, 68, 16);
		ExpandRotBlock(m_expKey, 72, 16, 8);
		ExpandSubBlock(m_expKey, 76, 16);
		ExpandRotBlock(m_expKey, 80, 16, 9);
		ExpandSubBlock(m_expKey, 84, 16);
		ExpandRotBlock(m_expKey, 88, 16, 10);
	}
	else if (keyWords == 8)
	{
		m_expKey[0] = Utility::IntUtils::BeBytesTo32(Key, 0);
		m_expKey[1] = Utility::IntUtils::BeBytesTo32(Key, 4);
		m_expKey[2] = Utility::IntUtils::BeBytesTo32(Key, 8);
		m_expKey[3] = Utility::IntUtils::BeBytesTo32(Key, 12);
		m_expKey[4] = Utility::IntUtils::BeBytesTo32(Key, 16);
		m_expKey[5] = Utility::IntUtils::BeBytesTo32(Key, 20);
		m_expKey[6] = Utility::IntUtils::BeBytesTo32(Key, 24);
		m_expKey[7] = Utility::IntUtils::BeBytesTo32(Key, 28);

		// k256 R: 8,16,24,32,40,48,56 S: 12,20,28,36,44,52
		ExpandRotBlock(m_expKey, 8, 8, 1);
		ExpandSubBlock(m_expKey, 12, 8);
		ExpandRotBlock(m_expKey, 16, 8, 2);
		ExpandSubBlock(m_expKey, 20, 8);
		ExpandRotBlock(m_expKey, 24, 8, 3);
		ExpandSubBlock(m_expKey, 28, 8);
		ExpandRotBlock(m_expKey, 32, 8, 4);
		ExpandSubBlock(m_expKey, 36, 8);
		ExpandRotBlock(m_expKey, 40, 8, 5);
		ExpandSubBlock(m_expKey, 44, 8);
		ExpandRotBlock(m_expKey, 48, 8, 6);
		ExpandSubBlock(m_expKey, 52, 8);
		ExpandRotBlock(m_expKey, 56, 8, 7);
	}
	else if (keyWords == 6)
	{
		m_expKey[0] = Utility::IntUtils::BeBytesTo32(Key, 0);
		m_expKey[1] = Utility::IntUtils::BeBytesTo32(Key, 4);
		m_expKey[2] = Utility::IntUtils::BeBytesTo32(Key, 8);
		m_expKey[3] = Utility::IntUtils::BeBytesTo32(Key, 12);
		m_expKey[4] = Utility::IntUtils::BeBytesTo32(Key, 16);
		m_expKey[5] = Utility::IntUtils::BeBytesTo32(Key, 20);

		// // k192 R: 6,12,18,24,30,36,42,48
		ExpandRotBlock(m_expKey, 6, 6, 1);
		m_expKey[10] = m_expKey[4] ^ m_expKey[9];
		m_expKey[11] = m_expKey[5] ^ m_expKey[10];
		ExpandRotBlock(m_expKey, 12, 6, 2);
		m_expKey[16] = m_expKey[10] ^ m_expKey[15];
		m_expKey[17] = m_expKey[11] ^ m_expKey[16];
		ExpandRotBlock(m_expKey, 18, 6, 3);
		m_expKey[22] = m_expKey[16] ^ m_expKey[21];
		m_expKey[23] = m_expKey[17] ^ m_expKey[22];
		ExpandRotBlock(m_expKey, 24, 6, 4);
		m_expKey[28] = m_expKey[22] ^ m_expKey[27];
		m_expKey[29] = m_expKey[23] ^ m_expKey[28];
		ExpandRotBlock(m_expKey, 30, 6, 5);
		m_expKey[34] = m_expKey[28] ^ m_expKey[33];
		m_expKey[35] = m_expKey[29] ^ m_expKey[34];
		ExpandRotBlock(m_expKey, 36, 6, 6);
		m_expKey[40] = m_expKey[34] ^ m_expKey[39];
		m_expKey[41] = m_expKey[35] ^ m_expKey[40];
		ExpandRotBlock(m_expKey, 42, 6, 7);
		m_expKey[46] = m_expKey[40] ^ m_expKey[45];
		m_expKey[47] = m_expKey[41] ^ m_expKey[46];
		ExpandRotBlock(m_expKey, 48, 6, 8);
	}
	else
	{
		m_expKey[0] = Utility::IntUtils::BeBytesTo32(Key, 0);
		m_expKey[1] = Utility::IntUtils::BeBytesTo32(Key, 4);
		m_expKey[2] = Utility::IntUtils::BeBytesTo32(Key, 8);
		m_expKey[3] = Utility::IntUtils::BeBytesTo32(Key, 12);

		// k128 R: 4,8,12,16,20,24,28,32,36,40
		ExpandRotBlock(m_expKey, 4, 4, 1);
		ExpandRotBlock(m_expKey, 8, 4, 2);
		ExpandRotBlock(m_expKey, 12, 4, 3);
		ExpandRotBlock(m_expKey, 16, 4, 4);
		ExpandRotBlock(m_expKey, 20, 4, 5);
		ExpandRotBlock(m_expKey, 24, 4, 6);
		ExpandRotBlock(m_expKey, 28, 4, 7);
		ExpandRotBlock(m_expKey, 32, 4, 8);
		ExpandRotBlock(m_expKey, 36, 4, 9);
		ExpandRotBlock(m_expKey, 40, 4, 10);
	}
}

void RHX::ExpandRotBlock(std::vector<uint> &Key, size_t KeyIndex, size_t KeyOffset, size_t RconIndex)
{
	size_t subKey = KeyIndex - KeyOffset;

	Key[KeyIndex] = Key[subKey] ^ SubByte(static_cast<uint>(Key[KeyIndex - 1] << 8) | static_cast<uint>(Key[KeyIndex - 1] >> 24) & 0xFF) ^ Rcon[RconIndex];
	++KeyIndex;
	++subKey;
	Key[KeyIndex] = Key[subKey] ^ Key[KeyIndex - 1];
	++KeyIndex;
	++subKey;
	Key[KeyIndex] = Key[subKey] ^ Key[KeyIndex - 1];
	++KeyIndex;
	++subKey;
	Key[KeyIndex] = Key[subKey] ^ Key[KeyIndex - 1];
}

void RHX::ExpandSubBlock(std::vector<uint> &Key, size_t KeyIndex, size_t KeyOffset)
{
	size_t subKey = KeyIndex - KeyOffset;

	Key[KeyIndex] = SubByte(Key[KeyIndex - 1]) ^ Key[subKey];
	++KeyIndex;
	++subKey;
	Key[KeyIndex] = Key[subKey] ^ Key[KeyIndex - 1];
	++KeyIndex;
	++subKey;
	Key[KeyIndex] = Key[subKey] ^ Key[KeyIndex - 1];
	++KeyIndex;
	++subKey;
	Key[KeyIndex] = Key[subKey] ^ Key[KeyIndex - 1];
}

//~~~Rounds Processing~~~//

void RHX::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t RNDCNT = m_expKey.size() - 4;

	// round 0
	uint X0 = Utility::IntUtils::BeBytesTo32(Input, InOffset) ^ m_expKey[0];
	uint X1 = Utility::IntUtils::BeBytesTo32(Input, InOffset + 4) ^ m_expKey[1];
	uint X2 = Utility::IntUtils::BeBytesTo32(Input, InOffset + 8) ^ m_expKey[2];
	uint X3 = Utility::IntUtils::BeBytesTo32(Input, InOffset + 12) ^ m_expKey[3];

	// round 1
	uint Y0 = IT0[(X0 >> 24)] ^ IT1[static_cast<byte>(X3 >> 16)] ^ IT2[static_cast<byte>(X2 >> 8)] ^ IT3[static_cast<byte>(X1)] ^ m_expKey[4];
	uint Y1 = IT0[(X1 >> 24)] ^ IT1[static_cast<byte>(X0 >> 16)] ^ IT2[static_cast<byte>(X3 >> 8)] ^ IT3[static_cast<byte>(X2)] ^ m_expKey[5];
	uint Y2 = IT0[(X2 >> 24)] ^ IT1[static_cast<byte>(X1 >> 16)] ^ IT2[static_cast<byte>(X0 >> 8)] ^ IT3[static_cast<byte>(X3)] ^ m_expKey[6];
	uint Y3 = IT0[(X3 >> 24)] ^ IT1[static_cast<byte>(X2 >> 16)] ^ IT2[static_cast<byte>(X1 >> 8)] ^ IT3[static_cast<byte>(X0)] ^ m_expKey[7];

	size_t keyCtr = 8;
	// rounds loop
	while (keyCtr != RNDCNT)
	{
		X0 = IT0[(Y0 >> 24)] ^ IT1[static_cast<byte>(Y3 >> 16)] ^ IT2[static_cast<byte>(Y2 >> 8)] ^ IT3[static_cast<byte>(Y1)] ^ m_expKey[keyCtr];
		X1 = IT0[(Y1 >> 24)] ^ IT1[static_cast<byte>(Y0 >> 16)] ^ IT2[static_cast<byte>(Y3 >> 8)] ^ IT3[static_cast<byte>(Y2)] ^ m_expKey[keyCtr + 1];
		X2 = IT0[(Y2 >> 24)] ^ IT1[static_cast<byte>(Y1 >> 16)] ^ IT2[static_cast<byte>(Y0 >> 8)] ^ IT3[static_cast<byte>(Y3)] ^ m_expKey[keyCtr + 2];
		X3 = IT0[(Y3 >> 24)] ^ IT1[static_cast<byte>(Y2 >> 16)] ^ IT2[static_cast<byte>(Y1 >> 8)] ^ IT3[static_cast<byte>(Y0)] ^ m_expKey[keyCtr + 3];

		Y0 = IT0[(X0 >> 24)] ^ IT1[static_cast<byte>(X3 >> 16)] ^ IT2[static_cast<byte>(X2 >> 8)] ^ IT3[static_cast<byte>(X1)] ^ m_expKey[keyCtr + 4];
		Y1 = IT0[(X1 >> 24)] ^ IT1[static_cast<byte>(X0 >> 16)] ^ IT2[static_cast<byte>(X3 >> 8)] ^ IT3[static_cast<byte>(X2)] ^ m_expKey[keyCtr + 5];
		Y2 = IT0[(X2 >> 24)] ^ IT1[static_cast<byte>(X1 >> 16)] ^ IT2[static_cast<byte>(X0 >> 8)] ^ IT3[static_cast<byte>(X3)] ^ m_expKey[keyCtr + 6];
		Y3 = IT0[(X3 >> 24)] ^ IT1[static_cast<byte>(X2 >> 16)] ^ IT2[static_cast<byte>(X1 >> 8)] ^ IT3[static_cast<byte>(X0)] ^ m_expKey[keyCtr + 7];
		keyCtr += 8;
	}

	// final round
	Output[OutOffset] = static_cast<byte>(ISBox[static_cast<byte>(Y0 >> 24)] ^ static_cast<byte>(m_expKey[keyCtr] >> 24));
	Output[OutOffset + 1] = static_cast<byte>(ISBox[static_cast<byte>(Y3 >> 16)] ^ static_cast<byte>(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = static_cast<byte>(ISBox[static_cast<byte>(Y2 >> 8)] ^ static_cast<byte>(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = static_cast<byte>(ISBox[static_cast<byte>(Y1)] ^ static_cast<byte>(m_expKey[keyCtr]));
	++keyCtr;
	Output[OutOffset + 4] = static_cast<byte>(ISBox[static_cast<byte>(Y1 >> 24)] ^ static_cast<byte>(m_expKey[keyCtr] >> 24));
	Output[OutOffset + 5] = static_cast<byte>(ISBox[static_cast<byte>(Y0 >> 16)] ^ static_cast<byte>(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = static_cast<byte>(ISBox[static_cast<byte>(Y3 >> 8)] ^ static_cast<byte>(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = static_cast<byte>(ISBox[static_cast<byte>(Y2)] ^ static_cast<byte>(m_expKey[keyCtr]));
	++keyCtr;
	Output[OutOffset + 8] = static_cast<byte>(ISBox[static_cast<byte>(Y2 >> 24)] ^ static_cast<byte>(m_expKey[keyCtr] >> 24));
	Output[OutOffset + 9] = static_cast<byte>(ISBox[static_cast<byte>(Y1 >> 16)] ^ static_cast<byte>(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = static_cast<byte>(ISBox[static_cast<byte>(Y0 >> 8)] ^ static_cast<byte>(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = static_cast<byte>(ISBox[static_cast<byte>(Y3)] ^ static_cast<byte>(m_expKey[keyCtr]));
	++keyCtr;
	Output[OutOffset + 12] = static_cast<byte>(ISBox[static_cast<byte>(Y3 >> 24)] ^ static_cast<byte>(m_expKey[keyCtr] >> 24));
	Output[OutOffset + 13] = static_cast<byte>(ISBox[static_cast<byte>(Y2 >> 16)] ^ static_cast<byte>(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = static_cast<byte>(ISBox[static_cast<byte>(Y1 >> 8)] ^ static_cast<byte>(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = static_cast<byte>(ISBox[static_cast<byte>(Y0)] ^ static_cast<byte>(m_expKey[keyCtr]));
}

void RHX::Decrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
}

void RHX::Decrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt512(Input, InOffset, Output, OutOffset);
	Decrypt512(Input, InOffset + 64, Output, OutOffset + 64);
}

void RHX::Decrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt1024(Input, InOffset, Output, OutOffset);
	Decrypt1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void RHX::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t RNDCNT = m_expKey.size() - 4;

	// round 0
	uint X0 = Utility::IntUtils::BeBytesTo32(Input, InOffset) ^ m_expKey[0];
	uint X1 = Utility::IntUtils::BeBytesTo32(Input, InOffset + 4) ^ m_expKey[1];
	uint X2 = Utility::IntUtils::BeBytesTo32(Input, InOffset + 8) ^ m_expKey[2];
	uint X3 = Utility::IntUtils::BeBytesTo32(Input, InOffset + 12) ^ m_expKey[3];

	// round 1
	uint Y0 = T0[static_cast<byte>(X0 >> 24)] ^ T1[static_cast<byte>(X1 >> 16)] ^ T2[static_cast<byte>(X2 >> 8)] ^ T3[static_cast<byte>(X3)] ^ m_expKey[4];
	uint Y1 = T0[static_cast<byte>(X1 >> 24)] ^ T1[static_cast<byte>(X2 >> 16)] ^ T2[static_cast<byte>(X3 >> 8)] ^ T3[static_cast<byte>(X0)] ^ m_expKey[5];
	uint Y2 = T0[static_cast<byte>(X2 >> 24)] ^ T1[static_cast<byte>(X3 >> 16)] ^ T2[static_cast<byte>(X0 >> 8)] ^ T3[static_cast<byte>(X1)] ^ m_expKey[6];
	uint Y3 = T0[static_cast<byte>(X3 >> 24)] ^ T1[static_cast<byte>(X0 >> 16)] ^ T2[static_cast<byte>(X1 >> 8)] ^ T3[static_cast<byte>(X2)] ^ m_expKey[7];

	size_t keyCtr = 8;
	while (keyCtr != RNDCNT)
	{
		X0 = T0[static_cast<byte>(Y0 >> 24)] ^ T1[static_cast<byte>(Y1 >> 16)] ^ T2[static_cast<byte>(Y2 >> 8)] ^ T3[static_cast<byte>(Y3)] ^ m_expKey[keyCtr];
		X1 = T0[static_cast<byte>(Y1 >> 24)] ^ T1[static_cast<byte>(Y2 >> 16)] ^ T2[static_cast<byte>(Y3 >> 8)] ^ T3[static_cast<byte>(Y0)] ^ m_expKey[keyCtr + 1];
		X2 = T0[static_cast<byte>(Y2 >> 24)] ^ T1[static_cast<byte>(Y3 >> 16)] ^ T2[static_cast<byte>(Y0 >> 8)] ^ T3[static_cast<byte>(Y1)] ^ m_expKey[keyCtr + 2];
		X3 = T0[static_cast<byte>(Y3 >> 24)] ^ T1[static_cast<byte>(Y0 >> 16)] ^ T2[static_cast<byte>(Y1 >> 8)] ^ T3[static_cast<byte>(Y2)] ^ m_expKey[keyCtr + 3];
		Y0 = T0[static_cast<byte>(X0 >> 24)] ^ T1[static_cast<byte>(X1 >> 16)] ^ T2[static_cast<byte>(X2 >> 8)] ^ T3[static_cast<byte>(X3)] ^ m_expKey[keyCtr + 4];
		Y1 = T0[static_cast<byte>(X1 >> 24)] ^ T1[static_cast<byte>(X2 >> 16)] ^ T2[static_cast<byte>(X3 >> 8)] ^ T3[static_cast<byte>(X0)] ^ m_expKey[keyCtr + 5];
		Y2 = T0[static_cast<byte>(X2 >> 24)] ^ T1[static_cast<byte>(X3 >> 16)] ^ T2[static_cast<byte>(X0 >> 8)] ^ T3[static_cast<byte>(X1)] ^ m_expKey[keyCtr + 6];
		Y3 = T0[static_cast<byte>(X3 >> 24)] ^ T1[static_cast<byte>(X0 >> 16)] ^ T2[static_cast<byte>(X1 >> 8)] ^ T3[static_cast<byte>(X2)] ^ m_expKey[keyCtr + 7];
		keyCtr += 8;
	}

	// final round
	Output[OutOffset] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 24)] ^ static_cast<byte>(m_expKey[keyCtr] >> 24));
	Output[OutOffset + 1] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 16)] ^ static_cast<byte>(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 8)] ^ static_cast<byte>(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = static_cast<byte>(SBox[static_cast<byte>(Y3)] ^ static_cast<byte>(m_expKey[keyCtr]));
	++keyCtr;
	Output[OutOffset + 4] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 24)] ^ static_cast<byte>(m_expKey[keyCtr] >> 24));
	Output[OutOffset + 5] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 16)] ^ static_cast<byte>(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 8)] ^ static_cast<byte>(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = static_cast<byte>(SBox[static_cast<byte>(Y0)] ^ static_cast<byte>(m_expKey[keyCtr]));
	++keyCtr;
	Output[OutOffset + 8] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 24)] ^ static_cast<byte>(m_expKey[keyCtr] >> 24));
	Output[OutOffset + 9] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 16)] ^ static_cast<byte>(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 8)] ^ static_cast<byte>(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = static_cast<byte>(SBox[static_cast<byte>(Y1)] ^ static_cast<byte>(m_expKey[keyCtr]));
	++keyCtr;
	Output[OutOffset + 12] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 24)] ^ static_cast<byte>(m_expKey[keyCtr] >> 24));
	Output[OutOffset + 13] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 16)] ^ static_cast<byte>(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 8)] ^ static_cast<byte>(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = static_cast<byte>(SBox[static_cast<byte>(Y2)] ^ static_cast<byte>(m_expKey[keyCtr]));
}

void RHX::Encrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
}

void RHX::Encrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt512(Input, InOffset, Output, OutOffset);
	Encrypt512(Input, InOffset + 64, Output, OutOffset + 64);
}

void RHX::Encrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt1024(Input, InOffset, Output, OutOffset);
	Encrypt1024(Input, InOffset + 128, Output, OutOffset + 128);
}

//~~~Private Functions~~~//

void RHX::LoadState()
{
	if (m_cprExtension == BlockCipherExtensions::None)
	{
		m_legalKeySizes.resize(4);
		m_legalKeySizes[0] = SymmetricKeySize(16, BLOCK_SIZE, 0);
		m_legalKeySizes[1] = SymmetricKeySize(24, BLOCK_SIZE, 0);
		m_legalKeySizes[2] = SymmetricKeySize(32, BLOCK_SIZE, 0);
		m_legalKeySizes[3] = SymmetricKeySize(64, BLOCK_SIZE, 0);
	}
	else
	{
		m_legalKeySizes.resize(3);

		if (m_cprExtension == BlockCipherExtensions::SHAKE256)
		{
			// sha3-256 blocksize
			m_kdfInfoMax = 136;
		}
		else if (m_cprExtension == BlockCipherExtensions::SHAKE512)
		{
			// sha3-512 blocksize
			m_kdfInfoMax = 72;
		}
		else if (m_cprExtension == BlockCipherExtensions::HKDF512)
		{
			// sha2-512 blocksize - padding + hkdf counter
			m_kdfInfoMax = 128 - (17 + 1);
		}
		else
		{
			// sha2-256 blocksize - padding + hkdf counter
			m_kdfInfoMax = 64 - (9 + 1);
		}

		m_legalKeySizes[0] = SymmetricKeySize(32, BLOCK_SIZE, m_kdfInfoMax);
		m_legalKeySizes[1] = SymmetricKeySize(64, BLOCK_SIZE, m_kdfInfoMax);
		m_legalKeySizes[2] = SymmetricKeySize(128, BLOCK_SIZE, m_kdfInfoMax);
	}
}

CEX_OPTIMIZE_IGNORE
void RHX::Prefetch()
{
	// timing defence: pre-load tables into cache
	if (m_isEncryption)
	{
#if defined(__AVX__)
		PREFETCHT1(SBox[0], 256 * sizeof(byte));
		PREFETCHT1(&T0[0], 256 * sizeof(uint));
		PREFETCHT1(&T1[0], 256 * sizeof(uint));
		PREFETCHT1(&T2[0], 256 * sizeof(uint));
		PREFETCHT1(&T3[0], 256 * sizeof(uint));
#else
		volatile uint dummy = 0;
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= SBox[i];
		}
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= T0[i];
		}
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= T1[i];
		}
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= T2[i];
		}
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= T3[i];
		}
#endif
	}
	else
	{
#if defined(__AVX__)
		PREFETCHT1(&ISBox[0], 256 * sizeof(byte));
		PREFETCHT1(&IT0[0], 256 * sizeof(uint));
		PREFETCHT1(&IT1[0], 256 * sizeof(uint));
		PREFETCHT1(&IT2[0], 256 * sizeof(uint));
		PREFETCHT1(&IT3[0], 256 * sizeof(uint));
#else
		volatile uint dummy = 0;
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= SBox[i];
		}
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= IT0[i];
		}
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= IT1[i];
		}
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= IT2[i];
		}
		for (size_t i = 0; i < 256; ++i)
		{
			dummy ^= IT3[i];
		}
#endif
	}
}
CEX_OPTIMIZE_RESUME

uint RHX::SubByte(uint Rot)
{
	uint value = 0xFF & Rot;
	uint result = SBox[value];
	value = 0xFF & (Rot >> 8);
	result |= (static_cast<uint>(SBox[value]) << 8);
	value = 0xFF & (Rot >> 16);
	result |= (static_cast<uint>(SBox[value]) << 16);
	value = 0xFF & (Rot >> 24);

	return result | (static_cast<uint>(SBox[value]) << 24);
}

NAMESPACE_BLOCKEND
