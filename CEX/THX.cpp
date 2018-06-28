#include "THX.h"
#include "Twofish.h"
#include "IntUtils.h"
#include "KdfFromName.h"

#if defined(CEX_COMPILER_MSC)
#	if defined(__AVX512__)
#		include "UInt512.h"
#	elif defined(__AVX2__)
#		include "UInt256.h"
#	elif defined(__AVX__)
#		include "UInt128.h"
#	endif
#endif

NAMESPACE_BLOCK

const std::string THX::CIPHER_NAME("Twofish");
const std::string THX::CLASS_NAME("THX");
const std::string THX::DEF_DSTINFO("THX version 1 information string");

//~~~Constructor~~~//

THX::THX(BlockCipherExtensions CipherExtension)
	:
	m_cprExtension(CipherExtension),
	m_destroyEngine(true),
	m_distCode(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_distCodeMax(0),
	m_expKey(0),
	m_kdfGenerator(CipherExtension == BlockCipherExtensions::None ? nullptr :
		CipherExtension == BlockCipherExtensions::Custom ? throw CryptoSymmetricCipherException("THX:CTor", "The Kdf can not be null!") :
		Helper::KdfFromName::GetInstance(static_cast<Enumeration::Kdfs>(CipherExtension))),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_sBox(SBOX_SIZE, 0)
{
	LoadState();
}

THX::THX(Kdf::IKdf* Kdf)
	:
	m_cprExtension(BlockCipherExtensions::Custom),
	m_destroyEngine(false),
	m_distCode(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_distCodeMax(0),
	m_expKey(0),
	m_kdfGenerator(Kdf != nullptr ? Kdf :
		throw CryptoSymmetricCipherException("THX:CTor", "The Kdf can not be null!")),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_sBox(SBOX_SIZE, 0)
{
	LoadState();
}

THX::~THX()
{
	if (!m_isDestroyed)
	{
		m_cprExtension = BlockCipherExtensions::None;
		m_distCodeMax = 0;
		m_isEncryption = false;
		m_isInitialized = false;
		m_rndCount = 0;

		Utility::IntUtils::ClearVector(m_expKey);
		Utility::IntUtils::ClearVector(m_distCode);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_sBox);

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

const size_t THX::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCipherExtensions THX::CipherExtension()
{
	return m_cprExtension;
}

std::vector<byte> &THX::DistributionCode()
{
	return m_distCode;
}

const size_t THX::DistributionCodeMax()
{
	return m_distCodeMax;
}

const BlockCiphers THX::Enumeral()
{
	return (m_cprExtension == BlockCipherExtensions::None) ? BlockCiphers::Twofish : BlockCiphers::THX;
}

const bool THX::IsEncryption()
{
	return m_isEncryption;
}

const bool THX::IsInitialized()
{
	return m_isInitialized;
}

const std::vector<SymmetricKeySize> &THX::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string THX::Name()
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

const size_t THX::Rounds()
{
	return m_rndCount;
}

const size_t THX::StateCacheSize()
{
	return STATE_PRECACHED;
}

//~~~Public Functions~~~//

void THX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void THX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void THX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void THX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void THX::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, KeyParams.Key().size()))
	{
		throw CryptoSymmetricCipherException("THX:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	}
	if (m_cprExtension != BlockCipherExtensions::None && KeyParams.Info().size() > m_distCodeMax)
	{
		throw CryptoSymmetricCipherException("THX:Initialize", "Invalid info size! Info parameter must be no longer than DistributionCodeMax size.");
	}

	if (KeyParams.Info().size() > 0)
	{
		m_distCode = KeyParams.Info();
	}

	m_isEncryption = Encryption;
	// expand the key
	ExpandKey(KeyParams.Key());

	// load tables into L1
#if defined(CEX_PREFETCH_THX_TABLES)
	Prefetch();
#endif
	// ready to transform data
	m_isInitialized = true;
}

void THX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
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

void THX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void THX::Transform512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void THX::Transform1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void THX::Transform2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void THX::ExpandKey(const std::vector<byte> &Key)
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
}

void THX::SecureExpand(const std::vector<byte> &Key)
{
	// rounds: k256=40, k512=48, k1024=64
	m_rndCount = Key.size() == 32 ? 20 : Key.size() == 64 ? 24 : 32;

	const size_t EXKSZE = (m_rndCount * 2) + 8;
	const size_t SKMSZE = (Key.size() / 8);

	std::vector<uint> eKm(SKMSZE);
	std::vector<uint> oKm(SKMSZE);
	std::vector<byte> rawKey(EXKSZE * sizeof(uint));
	std::vector<byte> sbKey(Key.size() / 2);
	size_t keyPos;

	// salt is not used
	std::vector<byte> salt(0);
	// initialize the generator
	m_kdfGenerator->Initialize(Key, salt, m_distCode);
	// generate the keying material
	m_kdfGenerator->Generate(rawKey);
	// initialize round-key array
	m_expKey.resize(EXKSZE, 0);

	// copy bytes to round keys
	for (size_t i = 0; i < m_expKey.size(); ++i)
	{
		m_expKey[i] = Utility::IntUtils::LeBytesTo32(rawKey, i * sizeof(uint));
	}

	// sbox encoding steps
	keyPos = 0;
	for (uint i = 0; i < SKMSZE; i++)
	{
		// split
		eKm[i] = Utility::IntUtils::LeBytesTo32(rawKey, keyPos);
		keyPos += 4;
		oKm[i] = Utility::IntUtils::LeBytesTo32(rawKey, keyPos);
		keyPos += 4;
		// encode and add to sbox key
		Utility::IntUtils::Le32ToBytes(MdsEncode(eKm[i], oKm[i]), sbKey, ((SKMSZE * 4) - 4) - (i * 4));
	}

	keyPos = 0;
	std::array<uint, 4> sbMix;

	while (keyPos != SBKEY_BITS)
	{
		Mix16(static_cast<uint>(keyPos), sbKey, sbMix);
		m_sBox[keyPos * 2] = sbMix[0];
		m_sBox[keyPos * 2 + 1] = sbMix[1];
		m_sBox[keyPos * 2 + 0x200] = sbMix[2];
		m_sBox[keyPos * 2 + 0x201] = sbMix[3];
		++keyPos;
	}
}

void THX::StandardExpand(const std::vector<byte> &Key)
{
	// k512 gets 20 rounds
	m_rndCount = (Key.size() == 64) ? 20 : DEF_ROUNDS;

	const size_t EXKSZE = (m_rndCount * 2) + 8;
	const size_t SKMSZE = (Key.size() / 8);

	std::vector<uint> eKm(SKMSZE);
	std::vector<uint> oKm(SKMSZE);
	std::vector<byte> sbKey(Key.size() / 2);
	uint keyPos;
	uint A;
	uint B;
	uint Q;

	keyPos = 0;

	for (size_t i = 0; i < SKMSZE; ++i)
	{
		// round key material
		eKm[i] = Utility::IntUtils::LeBytesTo32(Key, keyPos);
		keyPos += 4;
		oKm[i] = Utility::IntUtils::LeBytesTo32(Key, keyPos);
		keyPos += 4;
		// sbox key material
		Utility::IntUtils::Le32ToBytes(MdsEncode(eKm[i], oKm[i]), sbKey, ((SKMSZE * 4) - 4) - (i * 4));
	}

	// gen s-box members
	keyPos = 0;
	std::array<uint, 4> sbMix;
	m_expKey.resize(EXKSZE);

	while (keyPos != SBKEY_BITS)
	{
		// create the expanded key
		if (keyPos < (m_expKey.size() / 2))
		{
			Q = keyPos * SK_STEP;
			A = Mix4(Q, eKm);
			B = Mix4(Q + SK_BUMP, oKm);
			B = B << 8 | static_cast<uint>(B >> 24);
			A += B;
			m_expKey[keyPos * 2] = A;
			A += B;
			m_expKey[(keyPos * 2) + 1] = static_cast<uint>(A << SK_ROTL) | static_cast<uint>(A >> (32 - SK_ROTL));
		}

		Mix16(keyPos, sbKey, sbMix);
		m_sBox[keyPos * 2] = sbMix[0];
		m_sBox[keyPos * 2 + 1] = sbMix[1];
		m_sBox[keyPos * 2 + 0x200] = sbMix[2];
		m_sBox[keyPos * 2 + 0x201] = sbMix[3];
		++keyPos;
	}
}

//~~~Rounds Processing~~~//

void THX::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t RNDCNT = 8;
	uint X2 = Utility::IntUtils::LeBytesTo32(Input, InOffset) ^ m_expKey[4];
	uint X3 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 4) ^ m_expKey[5];
	uint X0 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 8) ^ m_expKey[6];
	uint X1 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 12) ^ m_expKey[7];
	uint T0, T1;
	size_t keyCtr = m_expKey.size();

	do
	{
		T0 = Fe0(X2, m_sBox);
		T1 = Fe3(X3, m_sBox);
		X1 ^= T0 + 2 * T1 + m_expKey[keyCtr - 1];
		X0 = (X0 << 1) | (X0 >> 31);
		X0 ^= (T0 + T1 + m_expKey[keyCtr - 2]);
		X1 = (X1 >> 1) | (X1 << 31);

		T0 = Fe0(X0, m_sBox);
		T1 = Fe3(X1, m_sBox);
		X3 ^= T0 + 2 * T1 + m_expKey[keyCtr - 3];
		X2 = (X2 << 1) | (X2 >> 31);
		X2 ^= (T0 + T1 + m_expKey[keyCtr - 4]);
		X3 = (X3 >> 1) | (X3 << 31);
		keyCtr -= 4;
	} 
	while (keyCtr != RNDCNT);

	keyCtr = 0;
	Utility::IntUtils::Le32ToBytes(X0 ^ m_expKey[keyCtr], Output, OutOffset);
	Utility::IntUtils::Le32ToBytes(X1 ^ m_expKey[keyCtr + 1], Output, OutOffset + 4);
	Utility::IntUtils::Le32ToBytes(X2 ^ m_expKey[keyCtr + 2], Output, OutOffset + 8);
	Utility::IntUtils::Le32ToBytes(X3 ^ m_expKey[keyCtr + 3], Output, OutOffset + 12);
}

void THX::Decrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void THX::Decrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if (!defined(__AVX512__)) && defined(__AVX2__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey, m_sBox);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
	Decrypt128(Input, InOffset + 64, Output, OutOffset + 64);
	Decrypt128(Input, InOffset + 80, Output, OutOffset + 80);
	Decrypt128(Input, InOffset + 96, Output, OutOffset + 96);
	Decrypt128(Input, InOffset + 112, Output, OutOffset + 112);
#endif
}

void THX::Decrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(__AVX512__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#elif (!defined(__AVX512__)) && defined(__AVX2__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey, m_sBox);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_expKey, m_sBox);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
	Decrypt128(Input, InOffset + 64, Output, OutOffset + 64);
	Decrypt128(Input, InOffset + 80, Output, OutOffset + 80);
	Decrypt128(Input, InOffset + 96, Output, OutOffset + 96);
	Decrypt128(Input, InOffset + 112, Output, OutOffset + 112);
	Decrypt128(Input, InOffset + 128, Output, OutOffset + 128);
	Decrypt128(Input, InOffset + 144, Output, OutOffset + 144);
	Decrypt128(Input, InOffset + 160, Output, OutOffset + 160);
	Decrypt128(Input, InOffset + 176, Output, OutOffset + 176);
	Decrypt128(Input, InOffset + 192, Output, OutOffset + 192);
	Decrypt128(Input, InOffset + 208, Output, OutOffset + 208);
	Decrypt128(Input, InOffset + 224, Output, OutOffset + 224);
	Decrypt128(Input, InOffset + 240, Output, OutOffset + 240);
#endif
}

void THX::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t RNDCNT = m_expKey.size() - 1;
	uint X0 = Utility::IntUtils::LeBytesTo32(Input, InOffset) ^ m_expKey[0];
	uint X1 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 4) ^ m_expKey[1];
	uint X2 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 8) ^ m_expKey[2];
	uint X3 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 12) ^ m_expKey[3];
	uint T0, T1;
	size_t keyCtr = 7;

	do
	{
		T0 = Fe0(X0, m_sBox);
		T1 = Fe3(X1, m_sBox);
		X2 ^= T0 + T1 + m_expKey[keyCtr + 1];
		X2 = (X2 >> 1) | (X2 << 31);
		X3 = (X3 << 1) | (X3 >> 31);
		X3 ^= (T0 + 2 * T1 + m_expKey[keyCtr + 2]);

		T0 = Fe0(X2, m_sBox);
		T1 = Fe3(X3, m_sBox);
		X0 ^= T0 + T1 + m_expKey[keyCtr + 3];
		X0 = (X0 >> 1) | (X0 << 31);
		X1 = (X1 << 1) | (X1 >> 31);
		X1 ^= (T0 + 2 * T1 + m_expKey[keyCtr + 4]);
		keyCtr += 4;
	} 
	while (keyCtr != RNDCNT);

	keyCtr = 4;
	X2 ^= m_expKey[keyCtr];
	X3 ^= m_expKey[keyCtr + 1];
	X0 ^= m_expKey[keyCtr + 2];
	X1 ^= m_expKey[keyCtr + 3];

	Utility::IntUtils::Le32ToBytes(X2, Output, OutOffset);
	Utility::IntUtils::Le32ToBytes(X3, Output, OutOffset + 4);
	Utility::IntUtils::Le32ToBytes(X0, Output, OutOffset + 8);
	Utility::IntUtils::Le32ToBytes(X1, Output, OutOffset + 12);
}

void THX::Encrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void THX::Encrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if (!defined(__AVX512__)) && defined(__AVX2__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey, m_sBox);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
	Encrypt128(Input, InOffset + 64, Output, OutOffset + 64);
	Encrypt128(Input, InOffset + 80, Output, OutOffset + 80);
	Encrypt128(Input, InOffset + 96, Output, OutOffset + 96);
	Encrypt128(Input, InOffset + 112, Output, OutOffset + 112);
#endif
}

void THX::Encrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(__AVX512__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#elif (!defined(__AVX512__)) && defined(__AVX2__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey, m_sBox);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_expKey, m_sBox);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
	Encrypt128(Input, InOffset + 64, Output, OutOffset + 64);
	Encrypt128(Input, InOffset + 80, Output, OutOffset + 80);
	Encrypt128(Input, InOffset + 96, Output, OutOffset + 96);
	Encrypt128(Input, InOffset + 112, Output, OutOffset + 112);
	Encrypt128(Input, InOffset + 128, Output, OutOffset + 128);
	Encrypt128(Input, InOffset + 144, Output, OutOffset + 144);
	Encrypt128(Input, InOffset + 160, Output, OutOffset + 160);
	Encrypt128(Input, InOffset + 176, Output, OutOffset + 176);
	Encrypt128(Input, InOffset + 192, Output, OutOffset + 192);
	Encrypt128(Input, InOffset + 208, Output, OutOffset + 208);
	Encrypt128(Input, InOffset + 224, Output, OutOffset + 224);
	Encrypt128(Input, InOffset + 240, Output, OutOffset + 240);
#endif
}

//~~~Helpers~~~//

void THX::LoadState()
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
			m_distCodeMax = 136;
		}
		else if (m_cprExtension == BlockCipherExtensions::SHAKE512)
		{
			// sha3-512 blocksize
			m_distCodeMax = 72;
		}
		else if (m_cprExtension == BlockCipherExtensions::HKDF512)
		{
			// sha2-512 blocksize - padding + hkdf counter
			m_distCodeMax = 128 - (17 + 1);
		}
		else
		{
			// sha2-256 blocksize - padding + hkdf counter
			m_distCodeMax = 64 - (9 + 1);
		}

		m_legalKeySizes[0] = SymmetricKeySize(32, BLOCK_SIZE, m_distCodeMax);
		m_legalKeySizes[1] = SymmetricKeySize(64, BLOCK_SIZE, m_distCodeMax);
		m_legalKeySizes[2] = SymmetricKeySize(128, BLOCK_SIZE, m_distCodeMax);
	}
}

uint THX::MdsEncode(uint K0, uint K1)
{
	uint B;
	uint G2;
	uint G3;
	uint sum;

	B = ((K1 >> 24) & 0xFF);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	sum = ((K1 << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	B = ((sum >> 24) & 0xFF);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	sum = ((sum << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	B = ((sum >> 24) & 0xFF);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	sum = ((sum << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	B = ((sum >> 24) & 0xFF);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	sum = ((sum << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);
	sum ^= K0;

	B = ((sum >> 24) & 0xFF);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	sum = ((sum << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	B = ((sum >> 24) & 0xFF);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	sum = ((sum << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	B = ((sum >> 24) & 0xFF);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	sum = ((sum << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	B = ((sum >> 24) & 0xFF);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	sum = ((sum << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	return sum;
}

uint THX::Mix4(const uint X, const std::vector<uint> &SubKey)
{
	uint Y0;
	uint Y1;
	uint Y2;
	uint Y3;

	Y0 = static_cast<byte>(X);
	Y1 = static_cast<byte>(X >> 8);
	Y2 = static_cast<byte>(X >> 16);
	Y3 = static_cast<byte>(X >> 24);

	if (SubKey.size() > 8)
	{
		Y0 = Q1[Y0] ^ static_cast<byte>(SubKey[15]);
		Y1 = Q0[Y1] ^ static_cast<byte>(SubKey[15] >> 8);
		Y2 = Q0[Y2] ^ static_cast<byte>(SubKey[15] >> 16);
		Y3 = Q1[Y3] ^ static_cast<byte>(SubKey[15] >> 24);
		Y0 = Q1[Y0] ^ static_cast<byte>(SubKey[14]);
		Y1 = Q1[Y1] ^ static_cast<byte>(SubKey[14] >> 8);
		Y2 = Q0[Y2] ^ static_cast<byte>(SubKey[14] >> 16);
		Y3 = Q0[Y3] ^ static_cast<byte>(SubKey[14] >> 24);
		Y0 = Q0[Y0] ^ static_cast<byte>(SubKey[13]);
		Y1 = Q1[Y1] ^ static_cast<byte>(SubKey[13] >> 8);
		Y2 = Q1[Y2] ^ static_cast<byte>(SubKey[13] >> 16);
		Y3 = Q0[Y3] ^ static_cast<byte>(SubKey[13] >> 24);
		Y0 = Q0[Y0] ^ static_cast<byte>(SubKey[12]);
		Y1 = Q0[Y1] ^ static_cast<byte>(SubKey[12] >> 8);
		Y2 = Q1[Y2] ^ static_cast<byte>(SubKey[12] >> 16);
		Y3 = Q1[Y3] ^ static_cast<byte>(SubKey[12] >> 24);
		Y0 = Q1[Y0] ^ static_cast<byte>(SubKey[11]);
		Y1 = Q0[Y1] ^ static_cast<byte>(SubKey[11] >> 8);
		Y2 = Q0[Y2] ^ static_cast<byte>(SubKey[11] >> 16);
		Y3 = Q1[Y3] ^ static_cast<byte>(SubKey[11] >> 24);
		Y0 = Q1[Y0] ^ static_cast<byte>(SubKey[10]);
		Y1 = Q1[Y1] ^ static_cast<byte>(SubKey[10] >> 8);
		Y2 = Q0[Y2] ^ static_cast<byte>(SubKey[10] >> 16);
		Y3 = Q0[Y3] ^ static_cast<byte>(SubKey[10] >> 24);
		Y0 = Q0[Y0] ^ static_cast<byte>(SubKey[9]);
		Y1 = Q1[Y1] ^ static_cast<byte>(SubKey[9] >> 8);
		Y2 = Q1[Y2] ^ static_cast<byte>(SubKey[9] >> 16);
		Y3 = Q0[Y3] ^ static_cast<byte>(SubKey[9] >> 24);
		Y0 = Q0[Y0] ^ static_cast<byte>(SubKey[8]);
		Y1 = Q0[Y1] ^ static_cast<byte>(SubKey[8] >> 8);
		Y2 = Q1[Y2] ^ static_cast<byte>(SubKey[8] >> 16);
		Y3 = Q1[Y3] ^ static_cast<byte>(SubKey[8] >> 24);
	}
	if (SubKey.size() > 4)
	{
		Y0 = Q1[Y0] ^ static_cast<byte>(SubKey[7]);
		Y1 = Q0[Y1] ^ static_cast<byte>(SubKey[7] >> 8);
		Y2 = Q0[Y2] ^ static_cast<byte>(SubKey[7] >> 16);
		Y3 = Q1[Y3] ^ static_cast<byte>(SubKey[7] >> 24);
		Y0 = Q1[Y0] ^ static_cast<byte>(SubKey[6]);
		Y1 = Q1[Y1] ^ static_cast<byte>(SubKey[6] >> 8);
		Y2 = Q0[Y2] ^ static_cast<byte>(SubKey[6] >> 16);
		Y3 = Q0[Y3] ^ static_cast<byte>(SubKey[6] >> 24);
		Y0 = Q0[Y0] ^ static_cast<byte>(SubKey[5]);
		Y1 = Q1[Y1] ^ static_cast<byte>(SubKey[5] >> 8);
		Y2 = Q1[Y2] ^ static_cast<byte>(SubKey[5] >> 16);
		Y3 = Q0[Y3] ^ static_cast<byte>(SubKey[5] >> 24);
		Y0 = Q0[Y0] ^ static_cast<byte>(SubKey[4]);
		Y1 = Q0[Y1] ^ static_cast<byte>(SubKey[4] >> 8);
		Y2 = Q1[Y2] ^ static_cast<byte>(SubKey[4] >> 16);
		Y3 = Q1[Y3] ^ static_cast<byte>(SubKey[4] >> 24);
	}
	if (SubKey.size() > 3)
	{
		Y0 = Q1[Y0] ^ static_cast<byte>(SubKey[3]);
		Y1 = Q0[Y1] ^ static_cast<byte>(SubKey[3] >> 8);
		Y2 = Q0[Y2] ^ static_cast<byte>(SubKey[3] >> 16);
		Y3 = Q1[Y3] ^ static_cast<byte>(SubKey[3] >> 24);
	}
	if (SubKey.size() > 2)
	{
		Y0 = Q1[Y0] ^ static_cast<byte>(SubKey[2]);
		Y1 = Q1[Y1] ^ static_cast<byte>(SubKey[2] >> 8);
		Y2 = Q0[Y2] ^ static_cast<byte>(SubKey[2] >> 16);
		Y3 = Q0[Y3] ^ static_cast<byte>(SubKey[2] >> 24);
	}

	// return the MDS matrix multiply
	return (
		M0[Q0[Q0[Y0] ^ 
		static_cast<byte>(SubKey[1])] ^ 
		static_cast<byte>(SubKey[0])] ^
		M1[Q0[Q1[Y1] ^ 
		static_cast<byte>(SubKey[1] >> 8)] ^ 
		static_cast<byte>(SubKey[0] >> 8)] ^
		M2[Q1[Q0[Y2] ^ 
		static_cast<byte>(SubKey[1] >> 16)] ^ 
		static_cast<byte>(SubKey[0] >> 16)] ^
		M3[Q1[Q1[Y3] ^ 
		static_cast<byte>(SubKey[1] >> 24)] ^ 
		static_cast<byte>(SubKey[0] >> 24)]
		);
}

void THX::Mix16(const uint X, const std::vector<byte> &SubKey, std::array<uint, 4> &Output)
{
	uint Y0; 
	uint Y1;
	uint Y2;
	uint Y3;

	Y0 = X;
	Y1 = X;
	Y2 = X;
	Y3 = X;

	if (SubKey.size() > 32)
	{
		Y0 = Q1[Y0] ^ SubKey[60];
		Y1 = Q0[Y1] ^ SubKey[61];
		Y2 = Q0[Y2] ^ SubKey[62];
		Y3 = Q1[Y3] ^ SubKey[63];
		Y0 = Q1[Y0] ^ SubKey[56];
		Y1 = Q1[Y1] ^ SubKey[57];
		Y2 = Q0[Y2] ^ SubKey[58];
		Y3 = Q0[Y3] ^ SubKey[59];
		Y0 = Q0[Y0] ^ SubKey[52];
		Y1 = Q1[Y1] ^ SubKey[53];
		Y2 = Q1[Y2] ^ SubKey[54];
		Y3 = Q0[Y3] ^ SubKey[55];
		Y0 = Q0[Y0] ^ SubKey[48];
		Y1 = Q0[Y1] ^ SubKey[49];
		Y2 = Q1[Y2] ^ SubKey[50];
		Y3 = Q1[Y3] ^ SubKey[51];
		Y0 = Q1[Y0] ^ SubKey[44];
		Y1 = Q0[Y1] ^ SubKey[45];
		Y2 = Q0[Y2] ^ SubKey[46];
		Y3 = Q1[Y3] ^ SubKey[47];
		Y0 = Q1[Y0] ^ SubKey[40];
		Y1 = Q1[Y1] ^ SubKey[41];
		Y2 = Q0[Y2] ^ SubKey[42];
		Y3 = Q0[Y3] ^ SubKey[43];
		Y0 = Q0[Y0] ^ SubKey[36];
		Y1 = Q1[Y1] ^ SubKey[37];
		Y2 = Q1[Y2] ^ SubKey[38];
		Y3 = Q0[Y3] ^ SubKey[39];
		Y0 = Q0[Y0] ^ SubKey[32];
		Y1 = Q0[Y1] ^ SubKey[33];
		Y2 = Q1[Y2] ^ SubKey[34];
		Y3 = Q1[Y3] ^ SubKey[35];
		Y0 = Q1[Y0] ^ SubKey[28];
		Y1 = Q0[Y1] ^ SubKey[29];
		Y2 = Q0[Y2] ^ SubKey[30];
		Y3 = Q1[Y3] ^ SubKey[31];
		Y0 = Q1[Y0] ^ SubKey[24];
		Y1 = Q1[Y1] ^ SubKey[25];
		Y2 = Q0[Y2] ^ SubKey[26];
		Y3 = Q0[Y3] ^ SubKey[27];
		Y0 = Q0[Y0] ^ SubKey[20];
		Y1 = Q1[Y1] ^ SubKey[21];
		Y2 = Q1[Y2] ^ SubKey[22];
		Y3 = Q0[Y3] ^ SubKey[23];
		Y0 = Q0[Y0] ^ SubKey[16];
		Y1 = Q0[Y1] ^ SubKey[17];
		Y2 = Q1[Y2] ^ SubKey[18];
		Y3 = Q1[Y3] ^ SubKey[19];
	}
	if (SubKey.size() > 16)
	{
		Y0 = Q1[Y0] ^ SubKey[28];
		Y1 = Q0[Y1] ^ SubKey[29];
		Y2 = Q0[Y2] ^ SubKey[30];
		Y3 = Q1[Y3] ^ SubKey[31];
		Y0 = Q1[Y0] ^ SubKey[24];
		Y1 = Q1[Y1] ^ SubKey[25];
		Y2 = Q0[Y2] ^ SubKey[26];
		Y3 = Q0[Y3] ^ SubKey[27];
		Y0 = Q0[Y0] ^ SubKey[20];
		Y1 = Q1[Y1] ^ SubKey[21];
		Y2 = Q1[Y2] ^ SubKey[22];
		Y3 = Q0[Y3] ^ SubKey[23];
		Y0 = Q0[Y0] ^ SubKey[16];
		Y1 = Q0[Y1] ^ SubKey[17];
		Y2 = Q1[Y2] ^ SubKey[18];
		Y3 = Q1[Y3] ^ SubKey[19];
	}
	if (SubKey.size() > 12)
	{
		Y0 = Q1[Y0] ^ SubKey[12];
		Y1 = Q0[Y1] ^ SubKey[13];
		Y2 = Q0[Y2] ^ SubKey[14];
		Y3 = Q1[Y3] ^ SubKey[15];
	}
	if (SubKey.size() > 8)
	{
		Y0 = Q1[Y0] ^ SubKey[8];
		Y1 = Q1[Y1] ^ SubKey[9];
		Y2 = Q0[Y2] ^ SubKey[10];
		Y3 = Q0[Y3] ^ SubKey[11];
	}

	Output = {
		M0[Q0[Q0[Y0] ^ SubKey[4]] ^ SubKey[0]],
		M1[Q0[Q1[Y1] ^ SubKey[5]] ^ SubKey[1]],
		M2[Q1[Q0[Y2] ^ SubKey[6]] ^ SubKey[2]],
		M3[Q1[Q1[Y3] ^ SubKey[7]] ^ SubKey[3]]
	};
}

CEX_OPTIMIZE_IGNORE
void THX::Prefetch()
{
	// timing defence: pre-load tables into cache
#if defined(__AVX__)
	PREFETCHT1(&m_sBox[0], m_sBox.size() * sizeof(uint));
	PREFETCHT1(&M0[0], 256 * sizeof(uint));
	PREFETCHT1(&M1[0], 256 * sizeof(uint));
	PREFETCHT1(&M2[0], 256 * sizeof(uint));
	PREFETCHT1(&M3[0], 256 * sizeof(uint));
	PREFETCHT1(&Q0[0], 256 * sizeof(uint));
	PREFETCHT1(&Q1[0], 256 * sizeof(uint));
#else
	volatile uint dummy = 0;
	for (size_t i = 0; i < m_sBox.size(); ++i)
	{
		dummy ^= m_sBox[i];
	}
	for (size_t i = 0; i < 256; ++i)
	{
		dummy ^= M0[i];
	}
	for (size_t i = 0; i < 256; ++i)
	{
		dummy ^= M1[i];
	}
	for (size_t i = 0; i < 256; ++i)
	{
		dummy ^= M2[i];
	}
	for (size_t i = 0; i < 256; ++i)
	{
		dummy ^= M3[i];
	}
	for (size_t i = 0; i < 256; ++i)
	{
		dummy ^= Q0[i];
	}
	for (size_t i = 0; i < 256; ++i)
	{
		dummy ^= Q1[i];
	}
#endif
}

CEX_OPTIMIZE_RESUME

NAMESPACE_BLOCKEND
