#include "RHX.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "KdfFromName.h"
#include "Rijndael.h"

NAMESPACE_BLOCK

using Tools::MemoryTools;
using Tools::IntegerTools;
using Enumeration::Kdfs;
using namespace Cipher::Block::RijndaelBase;

class RHX::RhxState
{
public:

#if defined(CEX_HAS_AVX)
	std::vector<__m128i> RoundKeys;
#elif defined(CEX_HAS_AVX512)
	std::vector<__m512i> RoundKeysW;
#else
	SecureVector<uint32_t> RoundKeys = { 0 };
#endif

	SecureVector<uint8_t> Custom = { 0 };
	std::vector<SymmetricKeySize> LegalKeySizes{
		SymmetricKeySize(IK128_SIZE, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(IK192_SIZE, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(IK256_SIZE, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(IK512_SIZE, BLOCK_SIZE, INFO_SIZE) };
	size_t Rounds = 0;
	BlockCipherExtensions Extension;
	bool Destroyed;
	bool Encryption = false;
	bool Initialized = false;

	RhxState(BlockCipherExtensions CipherExtension, bool IsDestroyed)
		:
		Extension(CipherExtension),
		Destroyed(IsDestroyed)
	{
	}

	~RhxState()
	{
		LegalKeySizes.clear();
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(RoundKeys[0]));
		Rounds = 0;
		Extension = BlockCipherExtensions::None;
		Destroyed = false;
		Encryption = false;
		Initialized = false;
	}

	void Reset()
	{
		MemoryTools::Clear(Custom, 0, Custom.size());
#if defined(CEX_HAS_AVX512)
		MemoryTools::Clear(RoundKeysW, 0, RoundKeysW.size() * sizeof(__m512i));
#endif
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(RoundKeys[0]));
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

RHX::RHX(BlockCipherExtensions CipherExtension)
	:
	m_rhxState(new RhxState(CipherExtension, true)),
	m_kdfGenerator(CipherExtension == BlockCipherExtensions::None ?
		nullptr :
		Helper::KdfFromName::GetInstance(CipherExtension))
{
}

RHX::RHX(IKdf* Kdf)
	:
	m_rhxState(new RhxState(Kdf != nullptr ? static_cast<BlockCipherExtensions>(Kdf->Enumeral()) : 
		BlockCipherExtensions::None, 
		false)),
	m_kdfGenerator(Kdf)
{
}

RHX::~RHX()
{
	if (m_rhxState->Destroyed)
	{
		if (m_kdfGenerator != nullptr)
		{
			m_kdfGenerator.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const size_t RHX::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers RHX::Enumeral()
{
	BlockCiphers tmpn;
	Kdfs ext;

	ext = (m_kdfGenerator != nullptr) ? m_kdfGenerator->Enumeral() : Kdfs::None;

	switch (ext)
	{
		case Kdfs::HKDF256:
		{
			tmpn = BlockCiphers::RHXH256;
			break;
		}
		case Kdfs::HKDF512:
		{
			tmpn = BlockCiphers::RHXH512;
			break;
		}
		case Kdfs::SHAKE256:
		{
			tmpn = BlockCiphers::RHXS256;
			break;
		}
		case Kdfs::SHAKE512:
		{
			tmpn = BlockCiphers::RHXS512;
			break;
		}
		default:
		{
			tmpn = BlockCiphers::AES;
			break;
		}
	}

	return tmpn;
}

const bool RHX::IsEncryption()
{
	return m_rhxState->Encryption;
}

const bool RHX::IsInitialized()
{
	return m_rhxState->Initialized;
}

const std::vector<SymmetricKeySize> &RHX::LegalKeySizes()
{
	return m_rhxState->LegalKeySizes;
}

const std::string RHX::Name()
{
	std::string tmpn;

	tmpn = Enumeration::BlockCipherConvert::ToName(Enumeral());

	return tmpn;
}

const size_t RHX::Rounds()
{
	return m_rhxState->Rounds;
}

const size_t RHX::StateCacheSize()
{
	return STATE_PRECACHED;
}

//~~~Public Functions~~~//

void RHX::DecryptBlock(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void RHX::DecryptBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void RHX::EncryptBlock(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void RHX::EncryptBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void RHX::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}

	if (IsInitialized() == true)
	{
		m_rhxState->Reset();
	}

	m_rhxState->Encryption = Encryption;

	if (m_kdfGenerator != nullptr)
	{
		// info string is ciphers name + 2 bytes for key size + user defined info ex. rhx256=RHXH25601
		// construct the customization string, starting with the ciphers formal string name
		std::string tmpn = Name();
		m_rhxState->Custom.resize(tmpn.size() + sizeof(uint16_t) + Parameters.KeySizes().InfoSize());
		// add the ciphers formal class name to the customization string
		MemoryTools::CopyFromObject(tmpn.data(), m_rhxState->Custom, 0, tmpn.size());
		// add the key size in bits
		uint16_t ksec = static_cast<uint16_t>(Parameters.KeySizes().KeySize()) * 8;
		IntegerTools::Le16ToBytes(ksec, m_rhxState->Custom, tmpn.size());
		// append the optional user-supplied info code
		MemoryTools::Copy(Parameters.Info(), 0, m_rhxState->Custom, tmpn.size() + sizeof(uint16_t), Parameters.KeySizes().InfoSize());

		// call the extended kdf key expansion function, and populate the round key array in state
		SecureExpand(Parameters.SecureKey(), m_rhxState, m_kdfGenerator);
	}
	else
	{
		// standard rijndael key expansion
		StandardExpand(Parameters.SecureKey(), m_rhxState);
	}

#if defined(CEX_HAS_AVX)
	if (!Encryption)
	{
		size_t i;
		size_t j;

		std::swap(m_rhxState->RoundKeys[0], m_rhxState->RoundKeys[m_rhxState->RoundKeys.size() - 1]);

		for (i = 1, j = m_rhxState->RoundKeys.size() - 2; i < j; ++i, --j)
		{
			__m128i temp = _mm_aesimc_si128(m_rhxState->RoundKeys[i]);
			m_rhxState->RoundKeys[i] = _mm_aesimc_si128(m_rhxState->RoundKeys[j]);
			m_rhxState->RoundKeys[j] = temp;
		}

		m_rhxState->RoundKeys[i] = _mm_aesimc_si128(m_rhxState->RoundKeys[i]);
	}
#	if defined(CEX_HAS_AVX512)

	m_rhxState->RoundKeysW.resize(m_rhxState->RoundKeys.size());

	for (i = 0; i < m_rhxState->RoundKeys.size(); ++i)
	{
		m_rhxState->RoundKeysW[i] = Load128To512(m_rhxState->RoundKeys[i]);
	}
#	endif
#endif


	// ready to transform data
	m_rhxState->Initialized = true;
}

void RHX::Transform(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	if (m_rhxState->Encryption)
	{
		Encrypt128(Input, 0, Output, 0);
	}
	else
	{
		Decrypt128(Input, 0, Output, 0);
	}
}

void RHX::Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	if (m_rhxState->Encryption)
	{
		Encrypt128(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt128(Input, InOffset, Output, OutOffset);
	}
}

void RHX::Transform256(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	if (m_rhxState->Encryption)
	{
		Encrypt256(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt256(Input, InOffset, Output, OutOffset);
	}
}

void RHX::Transform512(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	if (m_rhxState->Encryption)
	{
		Encrypt512(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt512(Input, InOffset, Output, OutOffset);
	}
}

void RHX::Transform1024(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	if (m_rhxState->Encryption)
	{
		Encrypt1024(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt1024(Input, InOffset, Output, OutOffset);
	}
}

void RHX::Transform2048(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	if (m_rhxState->Encryption)
	{
		Encrypt2048(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt2048(Input, InOffset, Output, OutOffset);
	}
}

//~~~Key Schedule~~~//

void RHX::SecureExpand(const SecureVector<uint8_t> &Key, std::unique_ptr<RhxState> &State, std::unique_ptr<IKdf> &Generator)
{
#if defined(CEX_HAS_AVX)
	size_t i;
	size_t j;
	size_t klen;
	uint32_t tmpbk;

	// rounds: k256=22, k512=30, k1024=38
	State->Rounds = Key.size() != 128 ? (Key.size() / 4) + 14 : 38;
	// round-key array size
	klen = ((BLOCK_SIZE / sizeof(uint32_t)) * (State->Rounds + 1)) / 4;
	SecureVector<uint8_t> tmpr(klen * sizeof(__m128i));
	// salt is not used
	SecureVector<uint8_t> salt(0);
	// initialize the generator
	SymmetricKey kp(Key, salt, State->Custom);
	Generator->Initialize(kp);
	// generate the keying material
	Generator->Generate(tmpr);
	// initialize round-key array
	State->RoundKeys.resize(klen);

	// big endian format to align with test vectors
	for (i = 0; i < tmpr.size(); i += 4)
	{
		tmpbk = IntegerTools::BeBytesTo32(tmpr, i);
		IntegerTools::Le32ToBytes(tmpbk, tmpr, i);
	}

	// copy bytes to working key
	for (i = 0, j = 0; i < klen; ++i, j += 16)
	{
		State->RoundKeys[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&tmpr[j]));
	}

	MemoryTools::Clear(tmpr, 0, tmpr.size());

#else

	size_t klen;

	// rounds: k256=22, k512=30, k1024=38
	State->Rounds = Key.size() != 128 ? (Key.size() / 4) + 14 : 38;
	// round-key array size
	klen = ((BLOCK_SIZE / sizeof(uint32_t)) * (State->Rounds + 1));
	SecureVector<uint8_t> tmpr(klen * sizeof(uint32_t));
	// salt is not used
	SecureVector<uint8_t> salt(0);
	// initialize the generator
	SymmetricKey kp(Key, salt, State->Custom);
	Generator->Initialize(kp);
	// generate the keying material
	Generator->Generate(tmpr);
	// initialize round-key array
	State->RoundKeys.resize(klen);

	// copy bytes to round keys
#if defined(CEX_IS_LITTLE_ENDIAN)
	MemoryTools::Copy(tmpr, 0, State->RoundKeys, 0, tmpr.size());
#else
	for (size_t i = 0; i < State->RoundKeys.size(); ++i)
	{
		State->RoundKeys[i] = IntegerTools::LeBytesTo32(tmpr, i * sizeof(uint32_t));
	}
#endif

	MemoryTools::Clear(tmpr, 0, tmpr.size());
#endif
}

void RHX::StandardExpand(const SecureVector<uint8_t> &Key, std::unique_ptr<RhxState> &State)
{
#if defined(CEX_HAS_AVX)

	const size_t BWORDS = BLOCK_SIZE / sizeof(uint32_t);
	const size_t KWORDS = Key.size() / sizeof(uint32_t);

	// rounds count calculation
	State->Rounds = KWORDS + 6;
	// create the expanded round-keys
	State->RoundKeys.resize((BWORDS * (State->Rounds + 1)) / sizeof(uint32_t));

	if (KWORDS == 8)
	{
		State->RoundKeys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Key[0]));
		State->RoundKeys[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Key[16]));
		State->RoundKeys[2] = _mm_aeskeygenassist_si128(State->RoundKeys[1], 0x01);
		ExpandRotBlock(State->RoundKeys, 2, 2);
		ExpandSubBlock(State->RoundKeys, 3, 2);
		State->RoundKeys[4] = _mm_aeskeygenassist_si128(State->RoundKeys[3], 0x02);
		ExpandRotBlock(State->RoundKeys, 4, 2);
		ExpandSubBlock(State->RoundKeys, 5, 2);
		State->RoundKeys[6] = _mm_aeskeygenassist_si128(State->RoundKeys[5], 0x04);
		ExpandRotBlock(State->RoundKeys, 6, 2);
		ExpandSubBlock(State->RoundKeys, 7, 2);
		State->RoundKeys[8] = _mm_aeskeygenassist_si128(State->RoundKeys[7], 0x08);
		ExpandRotBlock(State->RoundKeys, 8, 2);
		ExpandSubBlock(State->RoundKeys, 9, 2);
		State->RoundKeys[10] = _mm_aeskeygenassist_si128(State->RoundKeys[9], 0x10);
		ExpandRotBlock(State->RoundKeys, 10, 2);
		ExpandSubBlock(State->RoundKeys, 11, 2);
		State->RoundKeys[12] = _mm_aeskeygenassist_si128(State->RoundKeys[11], 0x20);
		ExpandRotBlock(State->RoundKeys, 12, 2);
		ExpandSubBlock(State->RoundKeys, 13, 2);
		State->RoundKeys[14] = _mm_aeskeygenassist_si128(State->RoundKeys[13], 0x40);
		ExpandRotBlock(State->RoundKeys, 14, 2);
	}
	else if (KWORDS == 6)
	{
		__m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Key[0]));
		__m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Key[8]));

		K1 = _mm_srli_si128(K1, 8);
		State->RoundKeys[0] = K0;
		State->RoundKeys[1] = K1;
		ExpandRotBlock(State->RoundKeys, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x01), 24);
		ExpandRotBlock(State->RoundKeys, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x02), 48);
		ExpandRotBlock(State->RoundKeys, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x04), 72);
		ExpandRotBlock(State->RoundKeys, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x08), 96);
		ExpandRotBlock(State->RoundKeys, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x10), 120);
		ExpandRotBlock(State->RoundKeys, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x20), 144);
		ExpandRotBlock(State->RoundKeys, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x40), 168);
		ExpandRotBlock(State->RoundKeys, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x80), 192);
	}
	else
	{
		State->RoundKeys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data()));
		State->RoundKeys[1] = _mm_aeskeygenassist_si128(State->RoundKeys[0], 0x01);
		ExpandRotBlock(State->RoundKeys, 1, 1);
		State->RoundKeys[2] = _mm_aeskeygenassist_si128(State->RoundKeys[1], 0x02);
		ExpandRotBlock(State->RoundKeys, 2, 1);
		State->RoundKeys[3] = _mm_aeskeygenassist_si128(State->RoundKeys[2], 0x04);
		ExpandRotBlock(State->RoundKeys, 3, 1);
		State->RoundKeys[4] = _mm_aeskeygenassist_si128(State->RoundKeys[3], 0x08);
		ExpandRotBlock(State->RoundKeys, 4, 1);
		State->RoundKeys[5] = _mm_aeskeygenassist_si128(State->RoundKeys[4], 0x10);
		ExpandRotBlock(State->RoundKeys, 5, 1);
		State->RoundKeys[6] = _mm_aeskeygenassist_si128(State->RoundKeys[5], 0x20);
		ExpandRotBlock(State->RoundKeys, 6, 1);
		State->RoundKeys[7] = _mm_aeskeygenassist_si128(State->RoundKeys[6], 0x40);
		ExpandRotBlock(State->RoundKeys, 7, 1);
		State->RoundKeys[8] = _mm_aeskeygenassist_si128(State->RoundKeys[7], 0x80);
		ExpandRotBlock(State->RoundKeys, 8, 1);
		State->RoundKeys[9] = _mm_aeskeygenassist_si128(State->RoundKeys[8], 0x1B);
		ExpandRotBlock(State->RoundKeys, 9, 1);
		State->RoundKeys[10] = _mm_aeskeygenassist_si128(State->RoundKeys[9], 0x36);
		ExpandRotBlock(State->RoundKeys, 10, 1);
	}

#else

	// block and key in 32bit words
	const size_t BWORDS = BLOCK_SIZE / sizeof(uint32_t);
	const size_t KWORDS = Key.size() / sizeof(uint32_t);

	// rounds count calculation
	State->Rounds = KWORDS + 6;
	// setup expanded key
	State->RoundKeys.resize(BWORDS * (State->Rounds + 1), 0x0UL);

	// pre-load the s-box into L1 cache
#if defined(CEX_PREFETCH_RIJNDAEL_TABLES)
	PrefetchSbox();
#endif

	if (KWORDS == 8)
	{
		State->RoundKeys[0] = IntegerTools::BeBytesTo32(Key, 0);
		State->RoundKeys[1] = IntegerTools::BeBytesTo32(Key, 4);
		State->RoundKeys[2] = IntegerTools::BeBytesTo32(Key, 8);
		State->RoundKeys[3] = IntegerTools::BeBytesTo32(Key, 12);
		State->RoundKeys[4] = IntegerTools::BeBytesTo32(Key, 16);
		State->RoundKeys[5] = IntegerTools::BeBytesTo32(Key, 20);
		State->RoundKeys[6] = IntegerTools::BeBytesTo32(Key, 24);
		State->RoundKeys[7] = IntegerTools::BeBytesTo32(Key, 28);

		// k256 R: 8,16,24,32,40,48,56 - S: 12,20,28,36,44,52
		ExpandRotBlock(State->RoundKeys, 8, 8, 1);
		ExpandSubBlock(State->RoundKeys, 12, 8);
		ExpandRotBlock(State->RoundKeys, 16, 8, 2);
		ExpandSubBlock(State->RoundKeys, 20, 8);
		ExpandRotBlock(State->RoundKeys, 24, 8, 3);
		ExpandSubBlock(State->RoundKeys, 28, 8);
		ExpandRotBlock(State->RoundKeys, 32, 8, 4);
		ExpandSubBlock(State->RoundKeys, 36, 8);
		ExpandRotBlock(State->RoundKeys, 40, 8, 5);
		ExpandSubBlock(State->RoundKeys, 44, 8);
		ExpandRotBlock(State->RoundKeys, 48, 8, 6);
		ExpandSubBlock(State->RoundKeys, 52, 8);
		ExpandRotBlock(State->RoundKeys, 56, 8, 7);
	}
	else if (KWORDS == 6)
	{
		State->RoundKeys[0] = IntegerTools::BeBytesTo32(Key, 0);
		State->RoundKeys[1] = IntegerTools::BeBytesTo32(Key, 4);
		State->RoundKeys[2] = IntegerTools::BeBytesTo32(Key, 8);
		State->RoundKeys[3] = IntegerTools::BeBytesTo32(Key, 12);
		State->RoundKeys[4] = IntegerTools::BeBytesTo32(Key, 16);
		State->RoundKeys[5] = IntegerTools::BeBytesTo32(Key, 20);

		// k192 R: 6,12,18,24,30,36,42,48
		ExpandRotBlock(State->RoundKeys, 6, 6, 1);
		State->RoundKeys[10] = State->RoundKeys[4] ^ State->RoundKeys[9];
		State->RoundKeys[11] = State->RoundKeys[5] ^ State->RoundKeys[10];
		ExpandRotBlock(State->RoundKeys, 12, 6, 2);
		State->RoundKeys[16] = State->RoundKeys[10] ^ State->RoundKeys[15];
		State->RoundKeys[17] = State->RoundKeys[11] ^ State->RoundKeys[16];
		ExpandRotBlock(State->RoundKeys, 18, 6, 3);
		State->RoundKeys[22] = State->RoundKeys[16] ^ State->RoundKeys[21];
		State->RoundKeys[23] = State->RoundKeys[17] ^ State->RoundKeys[22];
		ExpandRotBlock(State->RoundKeys, 24, 6, 4);
		State->RoundKeys[28] = State->RoundKeys[22] ^ State->RoundKeys[27];
		State->RoundKeys[29] = State->RoundKeys[23] ^ State->RoundKeys[28];
		ExpandRotBlock(State->RoundKeys, 30, 6, 5);
		State->RoundKeys[34] = State->RoundKeys[28] ^ State->RoundKeys[33];
		State->RoundKeys[35] = State->RoundKeys[29] ^ State->RoundKeys[34];
		ExpandRotBlock(State->RoundKeys, 36, 6, 6);
		State->RoundKeys[40] = State->RoundKeys[34] ^ State->RoundKeys[39];
		State->RoundKeys[41] = State->RoundKeys[35] ^ State->RoundKeys[40];
		ExpandRotBlock(State->RoundKeys, 42, 6, 7);
		State->RoundKeys[46] = State->RoundKeys[40] ^ State->RoundKeys[45];
		State->RoundKeys[47] = State->RoundKeys[41] ^ State->RoundKeys[46];
		ExpandRotBlock(State->RoundKeys, 48, 6, 8);
	}
	else
	{
		State->RoundKeys[0] = IntegerTools::BeBytesTo32(Key, 0);
		State->RoundKeys[1] = IntegerTools::BeBytesTo32(Key, 4);
		State->RoundKeys[2] = IntegerTools::BeBytesTo32(Key, 8);
		State->RoundKeys[3] = IntegerTools::BeBytesTo32(Key, 12);

		// k128 R: 4,8,12,16,20,24,28,32,36,40
		ExpandRotBlock(State->RoundKeys, 4, 4, 1);
		ExpandRotBlock(State->RoundKeys, 8, 4, 2);
		ExpandRotBlock(State->RoundKeys, 12, 4, 3);
		ExpandRotBlock(State->RoundKeys, 16, 4, 4);
		ExpandRotBlock(State->RoundKeys, 20, 4, 5);
		ExpandRotBlock(State->RoundKeys, 24, 4, 6);
		ExpandRotBlock(State->RoundKeys, 28, 4, 7);
		ExpandRotBlock(State->RoundKeys, 32, 4, 8);
		ExpandRotBlock(State->RoundKeys, 36, 4, 9);
		ExpandRotBlock(State->RoundKeys, 40, 4, 10);
	}
#endif
}

#if defined(CEX_HAS_AVX)

void RHX::ExpandRotBlock(std::vector<__m128i> &Key, __m128i* K1, __m128i* K2, __m128i KR, size_t Offset)
{
	// 192 bit key expansion method, -requires additional processing
	__m128i key1 = *K1;

	KR = _mm_shuffle_epi32(KR, _MM_SHUFFLE(1, 1, 1, 1));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, KR);
	*K1 = key1;

	std::memcpy(reinterpret_cast<uint8_t*>(Key.data()) + Offset, &key1, sizeof(__m128i));

	if (!(Offset == 192 && Key.size() == 13))
	{
		__m128i key2 = *K2;
		key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
		key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(key1, _MM_SHUFFLE(3, 3, 3, 3)));
		*K2 = key2;

		Offset += 16;
		std::vector<uint8_t> tmpB(4);
		IntegerTools::Le32ToBytes(_mm_cvtsi128_si32(key2), tmpB, 0);
		std::memcpy(reinterpret_cast<uint8_t*>(Key.data()) + Offset, &tmpB[0], sizeof(uint32_t));

		Offset += 4;
		IntegerTools::Le32ToBytes(_mm_cvtsi128_si32(_mm_srli_si128(key2, sizeof(uint32_t))), tmpB, 0);
		std::memcpy(reinterpret_cast<uint8_t*>(Key.data()) + Offset, &tmpB[0], sizeof(uint32_t));
	}
}

void RHX::ExpandRotBlock(std::vector<__m128i> &Key, size_t Index, size_t Offset)
{
	// 128, 256, 512 bit key method
	__m128i pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(Key[Index], 0xFF);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

void RHX::ExpandSubBlock(std::vector<__m128i> &Key, size_t Index, size_t Offset)
{
	// used with 256 and 512 bit keys
	__m128i pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(Key[Index - 1], 0x0), 0xAA);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

void RHX::Decrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_rhxState->RoundKeys.size() - 2;
	size_t kctr = 0;
	__m128i x;

	x = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
	x = _mm_xor_si128(x, m_rhxState->RoundKeys[kctr]);

	while (kctr != RNDCNT)
	{
		++kctr;
		x = _mm_aesdec_si128(x, m_rhxState->RoundKeys[kctr]);
	}

	++kctr;
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_aesdeclast_si128(x, m_rhxState->RoundKeys[kctr]));
}

void RHX::Encrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_rhxState->RoundKeys.size() - 2;
	size_t kctr = 0;
	__m128i x;

	x = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
	x = _mm_xor_si128(x, m_rhxState->RoundKeys[kctr]);

	while (kctr != RNDCNT)
	{
		++kctr;
		x = _mm_aesenc_si128(x, m_rhxState->RoundKeys[kctr]);
	}

	++kctr;
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_aesenclast_si128(x, m_rhxState->RoundKeys[kctr]));
}

#else

void RHX::ExpandRotBlock(SecureVector<uint32_t> &RoundKeys, size_t KeyIndex, size_t KeyOffset, size_t RconIndex)
{
	size_t kctr;

	kctr = KeyIndex - KeyOffset;
	RoundKeys[KeyIndex] = RoundKeys[kctr] ^ 
		SubWord(static_cast<uint32_t>(RoundKeys[KeyIndex - 1] << 8) | static_cast<uint32_t>(RoundKeys[KeyIndex - 1] >> 24) & 0xFF, SBox) ^ 
		Rcon[RconIndex];
	++KeyIndex;
	++kctr;
	RoundKeys[KeyIndex] = RoundKeys[kctr] ^ RoundKeys[KeyIndex - 1];
	++KeyIndex;
	++kctr;
	RoundKeys[KeyIndex] = RoundKeys[kctr] ^ RoundKeys[KeyIndex - 1];
	++KeyIndex;
	++kctr;
	RoundKeys[KeyIndex] = RoundKeys[kctr] ^ RoundKeys[KeyIndex - 1];
}

void RHX::ExpandSubBlock(SecureVector<uint32_t> &RoundKeys, size_t KeyIndex, size_t KeyOffset)
{
	size_t kctr;

	kctr = KeyIndex - KeyOffset;
	RoundKeys[KeyIndex] = SubWord(RoundKeys[KeyIndex - 1], SBox) ^ RoundKeys[kctr];
	++KeyIndex;
	++kctr;
	RoundKeys[KeyIndex] = RoundKeys[kctr] ^ RoundKeys[KeyIndex - 1];
	++KeyIndex;
	++kctr;
	RoundKeys[KeyIndex] = RoundKeys[kctr] ^ RoundKeys[KeyIndex - 1];
	++KeyIndex;
	++kctr;
	RoundKeys[KeyIndex] = RoundKeys[kctr] ^ RoundKeys[KeyIndex - 1];
}

void RHX::Decrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	SecureVector<uint8_t> state(BLOCK_SIZE, 0x00);
	size_t i;

	MemoryTools::Copy(Input, InOffset, state, 0, BLOCK_SIZE);
	KeyAddition(state, m_rhxState->RoundKeys, m_rhxState->Rounds << 2);

	// pre-load the s-box into L1 cache
#if defined(CEX_PREFETCH_RIJNDAEL_TABLES)
	PrefetchISbox();
#endif

	for (i = m_rhxState->Rounds - 1; i > 0; --i)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		KeyAddition(state, m_rhxState->RoundKeys, (i << 2UL));
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);
	KeyAddition(state, m_rhxState->RoundKeys, 0);

	MemoryTools::Copy(state, 0, Output, OutOffset, BLOCK_SIZE);
}

void RHX::Encrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	SecureVector<uint8_t> state(BLOCK_SIZE, 0x00);
	size_t i;

	MemoryTools::Copy(Input, InOffset, state, 0, BLOCK_SIZE);
	KeyAddition(state, m_rhxState->RoundKeys, 0);

	// pre-load the s-box into L1 cache
#if defined(CEX_PREFETCH_RIJNDAEL_TABLES)
	PrefetchSbox();
#endif

	for (i = 1; i < m_rhxState->Rounds; ++i)
	{
		Substitution(state);
		ShiftRows128(state);
		MixColumns(state);
		KeyAddition(state, m_rhxState->RoundKeys, (i << 2));
	}

	Substitution(state);
	ShiftRows128(state);
	KeyAddition(state, m_rhxState->RoundKeys, (m_rhxState->Rounds << 2));
	MemoryTools::Copy(state, 0, Output, OutOffset, BLOCK_SIZE);
}

CEX_OPTIMIZE_IGNORE
void RHX::PrefetchISbox()
{
	// timing defence: pre-load inverse sbox into l1 cache
	MemoryTools::PrefetchL1(ISBox, 0, ISBox.size());
}
CEX_OPTIMIZE_RESUME

CEX_OPTIMIZE_IGNORE
void RHX::PrefetchSbox()
{
	// timing defence: pre-load sbox into l1 cache
	MemoryTools::PrefetchL1(SBox, 0, SBox.size());
}
CEX_OPTIMIZE_RESUME
#endif

//~~~Rounds Processing~~~//

void RHX::Decrypt256(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
}

void RHX::Decrypt512(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Decrypt256(Input, InOffset, Output, OutOffset);
	Decrypt256(Input, InOffset + 32, Output, OutOffset + 32);
}

void RHX::Decrypt1024(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Decrypt512(Input, InOffset, Output, OutOffset);
	Decrypt512(Input, InOffset + 64, Output, OutOffset + 64);
}

void RHX::Decrypt2048(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Decrypt1024(Input, InOffset, Output, OutOffset);
	Decrypt1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void RHX::Encrypt256(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
}

void RHX::Encrypt512(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Encrypt256(Input, InOffset, Output, OutOffset);
	Encrypt256(Input, InOffset + 32, Output, OutOffset + 32);
}

void RHX::Encrypt1024(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Encrypt512(Input, InOffset, Output, OutOffset);
	Encrypt512(Input, InOffset + 64, Output, OutOffset + 64);
}

void RHX::Encrypt2048(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Encrypt1024(Input, InOffset, Output, OutOffset);
	Encrypt1024(Input, InOffset + 128, Output, OutOffset + 128);
}

//~~~Private Functions~~~//

std::vector<SymmetricKeySize> RHX::CalculateKeySizes(BlockCipherExtensions Extension)
{
	std::vector<SymmetricKeySize> keys(3);

	// Note: the hkdf variants info-size calculation: block-size - (name-size + hash-size + 1-uint8_t hkdf counter + sha2 padding) fills one sha2 final block,
	// this avoids permuting a partially empty block, for security and performance reasons.
	// In the shake variants, info is the shake name string, which is sized as the shake-rate - the classes string-name-size and 2 bytes for the key-size-bits.

	switch (Extension)
	{
		case BlockCipherExtensions::None:
		{
			keys[0] = SymmetricKeySize(16, BLOCK_SIZE, 0);
			keys[1] = SymmetricKeySize(24, BLOCK_SIZE, 0);
			keys[2] = SymmetricKeySize(32, BLOCK_SIZE, 0);
			break;
		}
		case BlockCipherExtensions::HKDF256:
		{
			keys[0] = SymmetricKeySize(32, BLOCK_SIZE, 13);
			keys[1] = SymmetricKeySize(64, BLOCK_SIZE, 13);
			keys[2] = SymmetricKeySize(128, BLOCK_SIZE, 13);
			break;
		}
		case BlockCipherExtensions::HKDF512:
		{
			keys[0] = SymmetricKeySize(32, BLOCK_SIZE, 37);
			keys[1] = SymmetricKeySize(64, BLOCK_SIZE, 37);
			keys[2] = SymmetricKeySize(128, BLOCK_SIZE, 37);
			break;
		}
		case BlockCipherExtensions::SHAKE256:
		{
			keys[0] = SymmetricKeySize(32, BLOCK_SIZE, 127);
			keys[1] = SymmetricKeySize(64, BLOCK_SIZE, 127);
			keys[2] = SymmetricKeySize(128, BLOCK_SIZE, 127);
			break;
		}
		case BlockCipherExtensions::SHAKE128:
		{
			keys[0] = SymmetricKeySize(32, BLOCK_SIZE, 159);
			keys[1] = SymmetricKeySize(64, BLOCK_SIZE, 159);
			keys[2] = SymmetricKeySize(128, BLOCK_SIZE, 159);
			break;
		}
		case BlockCipherExtensions::SHAKE512:
		{
			keys[0] = SymmetricKeySize(32, BLOCK_SIZE, 63);
			keys[1] = SymmetricKeySize(64, BLOCK_SIZE, 63);
			keys[2] = SymmetricKeySize(128, BLOCK_SIZE, 63);
			break;
		}
	}

	return keys;
}

#if defined(CEX_HAS_AVX512)
__m512i RHX::Load128To512(__m128i &V)
{
	__m512i x;

	x = _mm512_setzero_si512();
	x = _mm512_inserti32x4(x, V, 0);
	x = _mm512_inserti32x4(x, V, 1);
	x = _mm512_inserti32x4(x, V, 2);
	x = _mm512_inserti32x4(x, V, 3);

	return x;
}
#endif

NAMESPACE_BLOCKEND
