#include "SHX.h"
#include "Serpent.h"
#include "IntUtils.h"
#include "KdfFromName.h"

#if defined(__AVX512__)
#	include "UInt512.h"
#elif defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_BLOCK

const std::string SHX::CIPHER_NAME("Serpent");
const std::string SHX::CLASS_NAME("SHX");
const std::string SHX::DEF_DSTINFO("SHX version 1 information string");

//~~~Constructor~~~//

SHX::SHX(BlockCipherExtensions CipherExtension)
	:
	m_cprExtension(CipherExtension),
	m_destroyEngine(true),
	m_distCode(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_distCodeMax(0),
	m_expKey(0),
	m_kdfGenerator(CipherExtension == BlockCipherExtensions::None ? nullptr :
		CipherExtension == BlockCipherExtensions::Custom ? throw CryptoSymmetricCipherException("SHX:CTor", "The Kdf can not be null!") :
		Helper::KdfFromName::GetInstance(CipherExtension)),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0)
{
	LoadState();
}

SHX::SHX(Kdf::IKdf* Kdf)
	:
	m_cprExtension(BlockCipherExtensions::Custom),
	m_destroyEngine(false),
	m_distCode(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_distCodeMax(0),
	m_expKey(0),
	m_kdfGenerator(Kdf != nullptr ? Kdf :
		throw CryptoSymmetricCipherException("SHX:CTor", "The Kdf can not be null!")),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0)
{
	LoadState();
}

SHX::~SHX()
{
	if (!m_isDestroyed)
	{
		m_distCodeMax = 0;
		m_cprExtension = BlockCipherExtensions::None;
		m_isEncryption = false;
		m_isInitialized = false;
		m_rndCount = 0;

		Utility::IntUtils::ClearVector(m_expKey);
		Utility::IntUtils::ClearVector(m_distCode);
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

const size_t SHX::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCipherExtensions SHX::CipherExtension()
{
	return m_cprExtension;
}

std::vector<byte> &SHX::DistributionCode()
{
	return m_distCode;
}

const size_t SHX::DistributionCodeMax()
{
	return m_distCodeMax;
}

const BlockCiphers SHX::Enumeral()
{
	return (m_cprExtension == BlockCipherExtensions::None) ? BlockCiphers::Serpent : BlockCiphers::SHX;
}

const bool SHX::IsEncryption()
{
	return m_isEncryption;
}

const bool SHX::IsInitialized()
{
	return m_isInitialized;
}

const std::vector<SymmetricKeySize> &SHX::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string SHX::Name()
{
	std::string txtName = "";

	if (m_cprExtension == BlockCipherExtensions::SHAKE256)
	{
		txtName = CIPHER_NAME + std::string("+SHAKE-256");
	}
	else if (m_cprExtension == BlockCipherExtensions::SHAKE512)
	{
		txtName = CLASS_NAME + std::string("+SHAKE-512");
	}
	else if (m_cprExtension == BlockCipherExtensions::HKDF256)
	{
		txtName = CLASS_NAME + std::string("+HKDF-SHA256");
	}
	else if (m_cprExtension == BlockCipherExtensions::HKDF512)
	{
		txtName = CLASS_NAME + std::string("+HKDF-SHA512");
	}
	else
	{
		txtName = CIPHER_NAME;
	}

	return txtName;
}

const size_t SHX::Rounds()
{
	return m_rndCount;
}

const size_t SHX::StateCacheSize()
{
	return STATE_PRECACHED;
}

//~~~Public Functions~~~//

void SHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void SHX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void SHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void SHX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void SHX::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, KeyParams.Key().size()))
	{
		throw CryptoSymmetricCipherException("SHX:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	}
	if (m_cprExtension != BlockCipherExtensions::None && KeyParams.Info().size() > m_distCodeMax)
	{
		throw CryptoSymmetricCipherException("SHX:Initialize", "Invalid info size! Info parameter must be no longer than DistributionCodeMax size.");
	}

	if (KeyParams.Info().size() > 0)
	{
		m_distCode = KeyParams.Info();
	}

	m_isEncryption = Encryption;
	// expand the key
	ExpandKey(KeyParams.Key());
	// ready to transform data
	m_isInitialized = true;
}

void SHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
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

void SHX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void SHX::Transform512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void SHX::Transform1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void SHX::Transform2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
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

void SHX::ExpandKey(const std::vector<byte> &Key)
{
	if (m_cprExtension != BlockCipherExtensions::None)
	{
		// kdf key expansion
		SecureExpand(Key);
	}
	else
	{
		// standard serpent key expansion + k512
		StandardExpand(Key);
	}
}

void SHX::SecureExpand(const std::vector<byte> &Key)
{
	// rounds: k256=40, k512=48, k1024=64
	m_rndCount = Key.size() == 32 ? 40 : Key.size() == 64 ? 48 : 64;
	// round-key array size
	size_t keySize = 4 * (m_rndCount + 1);
	std::vector<byte> rawKey(keySize * sizeof(uint), 0);
	// salt is not used
	std::vector<byte> salt(0);
	// initialize the generator
	m_kdfGenerator->Initialize(Key, salt, m_distCode);
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

void SHX::StandardExpand(const std::vector<byte> &Key)
{
	uint cnt = 0;
	uint index = 0;
	size_t padSize = Key.size() < 32 ? 16 : Key.size() / 2;
	std::vector<uint> Wp(padSize, 0);
	size_t offset = 0;
	// CHANGE: 512 key gets (fixed) 8 extra rounds
	m_rndCount = (Key.size() == 64) ? 40 : 32;
	size_t keySize = 4 * (m_rndCount + 1);

	// step 1: reverse copy key to temp array
	for (offset = Key.size(); offset > 0; offset -= 4)
	{
		Wp[index] = Utility::IntUtils::BeBytesTo32(Key, offset - 4);
		++index;
	}

	// pad small key
	if (index < 8)
	{
		Wp[index] = 1;
	}

	// initialize the key
	std::vector<uint> Wk(keySize, 0);

	if (padSize == 16)
	{
		// 32 byte key
		// step 2: rotate k into w(k) ints
		for (size_t i = 8; i < 16; i++)
		{
			Wp[i] = Utility::IntUtils::RotL32(static_cast<uint>(Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);
		}

		// copy to expanded key
		Utility::MemUtils::Copy(Wp, 8, Wk, 0, 8 * sizeof(uint));

		// step 3: calculate remainder of rounds with rotating polynomial
		for (size_t i = 8; i < keySize; i++)
		{
			Wk[i] = Utility::IntUtils::RotL32(static_cast<uint>(Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
		}
	}
	else
	{
		// *extended*: 64 byte key
		// step 3: rotate k into w(k) ints, with extended polynominal
		// Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
		for (size_t i = 16; i < 32; i++)
		{
			Wp[i] = Utility::IntUtils::RotL32(static_cast<uint>(Wp[i - 16] ^ Wp[i - 13] ^ Wp[i - 11] ^ Wp[i - 10] ^ Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 16)), 11);
		}

		// copy to expanded key
		Utility::MemUtils::Copy(Wp, 16, Wk, 0, 16 * sizeof(uint));

		// step 3: calculate remainder of rounds with rotating polynomial
		for (size_t i = 16; i < keySize; i++)
		{
			Wk[i] = Utility::IntUtils::RotL32(static_cast<uint>(Wk[i - 16] ^ Wk[i - 13] ^ Wk[i - 11] ^ Wk[i - 10] ^ Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
		}
	}

	// step 4: create the working keys by processing with the Sbox and IP
	while (cnt < keySize - 4)
	{
		Sb3(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb2(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb1(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb0(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb7(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb6(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb5(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb4(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
	}

	// last round
	Sb3(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]);

	m_expKey = Wk;
}

//~~~Rounds Processing~~~//

void SHX::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t RNDCNT = 4;
	size_t keyCtr = m_expKey.size();

	// input round
	uint R3 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 12);
	uint R2 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 8);
	uint R1 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 4);
	uint R0 = Utility::IntUtils::LeBytesTo32(Input, InOffset);

	R3 ^= m_expKey[keyCtr - 1];
	R2 ^= m_expKey[keyCtr - 2];
	R1 ^= m_expKey[keyCtr - 3];
	R0 ^= m_expKey[keyCtr - 4];
	keyCtr -= 4;

	// process 8 round blocks
	do
	{
		Ib7(R0, R1, R2, R3);
		R3 ^= m_expKey[keyCtr - 1];
		R2 ^= m_expKey[keyCtr - 2];
		R1 ^= m_expKey[keyCtr - 3];
		R0 ^= m_expKey[keyCtr - 4];
		InverseTransform(R0, R1, R2, R3);

		Ib6(R0, R1, R2, R3);
		R3 ^= m_expKey[keyCtr - 5];
		R2 ^= m_expKey[keyCtr - 6];
		R1 ^= m_expKey[keyCtr - 7];
		R0 ^= m_expKey[keyCtr - 8];
		InverseTransform(R0, R1, R2, R3);

		Ib5(R0, R1, R2, R3);
		R3 ^= m_expKey[keyCtr - 9];
		R2 ^= m_expKey[keyCtr - 10];
		R1 ^= m_expKey[keyCtr - 11];
		R0 ^= m_expKey[keyCtr - 12];
		InverseTransform(R0, R1, R2, R3);

		Ib4(R0, R1, R2, R3);
		R3 ^= m_expKey[keyCtr - 13];
		R2 ^= m_expKey[keyCtr - 14];
		R1 ^= m_expKey[keyCtr - 15];
		R0 ^= m_expKey[keyCtr - 16];
		InverseTransform(R0, R1, R2, R3);

		Ib3(R0, R1, R2, R3);
		R3 ^= m_expKey[keyCtr - 17];
		R2 ^= m_expKey[keyCtr - 18];
		R1 ^= m_expKey[keyCtr - 19];
		R0 ^= m_expKey[keyCtr - 20];
		InverseTransform(R0, R1, R2, R3);

		Ib2(R0, R1, R2, R3);
		R3 ^= m_expKey[keyCtr - 21];
		R2 ^= m_expKey[keyCtr - 22];
		R1 ^= m_expKey[keyCtr - 23];
		R0 ^= m_expKey[keyCtr - 24];
		InverseTransform(R0, R1, R2, R3);

		Ib1(R0, R1, R2, R3);
		R3 ^= m_expKey[keyCtr - 25];
		R2 ^= m_expKey[keyCtr - 26];
		R1 ^= m_expKey[keyCtr - 27];
		R0 ^= m_expKey[keyCtr - 28];
		InverseTransform(R0, R1, R2, R3);

		Ib0(R0, R1, R2, R3);
		keyCtr -= 28;

		// skip on last block
		if (keyCtr != RNDCNT)
		{
			R3 ^= m_expKey[keyCtr - 1];
			R2 ^= m_expKey[keyCtr - 2];
			R1 ^= m_expKey[keyCtr - 3];
			R0 ^= m_expKey[keyCtr - 4];
			InverseTransform(R0, R1, R2, R3);
			keyCtr -= 4;
		}
	} 
	while (keyCtr != RNDCNT);

	// last round
	Utility::IntUtils::Le32ToBytes(R3 ^ m_expKey[keyCtr - 1], Output, OutOffset + 12);
	Utility::IntUtils::Le32ToBytes(R2 ^ m_expKey[keyCtr - 2], Output, OutOffset + 8);
	Utility::IntUtils::Le32ToBytes(R1 ^ m_expKey[keyCtr - 3], Output, OutOffset + 4);
	Utility::IntUtils::Le32ToBytes(R0 ^ m_expKey[keyCtr - 4], Output, OutOffset);
}

void SHX::Decrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	SHXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void SHX::Decrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if (!defined(__AVX512__)) && defined(__AVX2__)
	SHXDecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	SHXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
	SHXDecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey);
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

void SHX::Decrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(__AVX512__)
	SHXDecryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_expKey);
#elif (!defined(__AVX512__)) && defined(__AVX2__)
	SHXDecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey);
	SHXDecryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	SHXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
	SHXDecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey);
	SHXDecryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey);
	SHXDecryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_expKey);
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

void SHX::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t RNDCNT = m_expKey.size() - 4;
	size_t keyCtr = 0;

	// input round
	uint R0 = Utility::IntUtils::LeBytesTo32(Input, InOffset);
	uint R1 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 4);
	uint R2 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 8);
	uint R3 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 12);

	// process 8 round blocks
	do
	{
		R0 ^= m_expKey[keyCtr];
		R1 ^= m_expKey[keyCtr + 1];
		R2 ^= m_expKey[keyCtr + 2];
		R3 ^= m_expKey[keyCtr + 3];
		Sb0(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[keyCtr + 4];
		R1 ^= m_expKey[keyCtr + 5];
		R2 ^= m_expKey[keyCtr + 6];
		R3 ^= m_expKey[keyCtr + 7];
		Sb1(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[keyCtr + 8];
		R1 ^= m_expKey[keyCtr + 9];
		R2 ^= m_expKey[keyCtr + 10];
		R3 ^= m_expKey[keyCtr + 11];
		Sb2(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[keyCtr + 12];
		R1 ^= m_expKey[keyCtr + 13];
		R2 ^= m_expKey[keyCtr + 14];
		R3 ^= m_expKey[keyCtr + 15];
		Sb3(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[keyCtr + 16];
		R1 ^= m_expKey[keyCtr + 17];
		R2 ^= m_expKey[keyCtr + 18];
		R3 ^= m_expKey[keyCtr + 19];
		Sb4(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[keyCtr + 20];
		R1 ^= m_expKey[keyCtr + 21];
		R2 ^= m_expKey[keyCtr + 22];
		R3 ^= m_expKey[keyCtr + 23];
		Sb5(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[keyCtr + 24];
		R1 ^= m_expKey[keyCtr + 25];
		R2 ^= m_expKey[keyCtr + 26];
		R3 ^= m_expKey[keyCtr + 27];
		Sb6(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[keyCtr + 28];
		R1 ^= m_expKey[keyCtr + 29];
		R2 ^= m_expKey[keyCtr + 30];
		R3 ^= m_expKey[keyCtr + 31];
		Sb7(R0, R1, R2, R3);
		keyCtr += 32;

		// skip on last block
		if (keyCtr != RNDCNT)
		{
			LinearTransform(R0, R1, R2, R3);
		}
	} 
	while (keyCtr != RNDCNT);

	// last round
	Utility::IntUtils::Le32ToBytes(m_expKey[keyCtr] ^ R0, Output, OutOffset);
	Utility::IntUtils::Le32ToBytes(m_expKey[keyCtr + 1] ^ R1, Output, OutOffset + 4);
	Utility::IntUtils::Le32ToBytes(m_expKey[keyCtr + 2] ^ R2, Output, OutOffset + 8);
	Utility::IntUtils::Le32ToBytes(m_expKey[keyCtr + 3] ^ R3, Output, OutOffset + 12);
}

void SHX::Encrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	SHXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void SHX::Encrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if (!defined(__AVX512__)) && defined(__AVX2__)
	SHXEncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	SHXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
	SHXEncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey);
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

void SHX::Encrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(__AVX512__)
	SHXEncryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_expKey);
#elif (!defined(__AVX512__)) && defined(__AVX2__)
	SHXEncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey);
	SHXEncryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	SHXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
	SHXEncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey);
	SHXEncryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey);
	SHXEncryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_expKey);
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

//~~~Helper Functions~~~//

void SHX::LoadState()
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
			// HKDF(HMAC(SHA2-512) mac size - 1 byte counter
			m_distCodeMax = 64;
		}
		else
		{
			// hmac(sha2-256) mac size
			m_distCodeMax = 32;
		}

		m_legalKeySizes[0] = SymmetricKeySize(32, BLOCK_SIZE, m_distCodeMax);
		m_legalKeySizes[1] = SymmetricKeySize(64, BLOCK_SIZE, m_distCodeMax);
		m_legalKeySizes[2] = SymmetricKeySize(128, BLOCK_SIZE, m_distCodeMax);
	}
}

NAMESPACE_BLOCKEND
