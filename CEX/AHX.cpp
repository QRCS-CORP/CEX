#include "AHX.h"
#include "KdfFromName.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "UInt128.h"
#include <wmmintrin.h>

NAMESPACE_BLOCK

using Enumeration::BlockCipherConvert;
using Tools::MemoryTools;
using Tools::IntegerTools;
using Enumeration::Kdfs;

class AHX::AhxState
{
public:

	SecureVector<byte> Custom;
	std::vector<__m128i> RoundKeys;
	size_t Rounds;
	BlockCipherExtensions Extension;
	bool Destroyed;
	bool Encryption;
	bool Initialized;

	AhxState(BlockCipherExtensions CipherExtension, bool IsDestroyed)
		:
		Custom(0),
		RoundKeys(0),
		Rounds(0),
		Extension(CipherExtension),
		Destroyed(IsDestroyed),
		Encryption(false),
		Initialized(false)
	{
	}

	~AhxState()
	{
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint));
		Rounds = 0;
		Extension = BlockCipherExtensions::None;
		Destroyed = false;
		Encryption = false;
		Initialized = false;
	}

	void Reset()
	{
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint));
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

AHX::AHX(BlockCipherExtensions CipherExtension)
	:
	m_ahxState(new AhxState(CipherExtension, true)),
	m_kdfGenerator(CipherExtension == BlockCipherExtensions::None ?
		nullptr :
		Helper::KdfFromName::GetInstance(CipherExtension)),
	m_legalKeySizes(CalculateKeySizes(CipherExtension))
{
#if !defined(CEX_AVX_INTRINSICS)
	throw CryptoSymmetricException(BlockCipherConvert::ToName(BlockCiphers::AES), std::string("Constructor"), std::string("AVX is not supported on this system!"), ErrorCodes::NotSupported);
#endif
}

AHX::AHX(IKdf* Kdf)
	:
	m_ahxState(new AhxState(Kdf != nullptr ? static_cast<BlockCipherExtensions>(Kdf->Enumeral()) :
		BlockCipherExtensions::None,
		false)),
	m_kdfGenerator(Kdf),
	m_legalKeySizes(CalculateKeySizes(Kdf != nullptr ? static_cast<BlockCipherExtensions>(Kdf->Enumeral()) :
		BlockCipherExtensions::None))
{

}

AHX::~AHX()
{
	if (m_ahxState->Destroyed)
	{
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

	IntegerTools::Clear(m_legalKeySizes);
}

//~~~Accessors~~~//

const size_t AHX::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers AHX::Enumeral()
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
		case Kdfs::SHAKE1024:
		{
			tmpn = BlockCiphers::RHXS1024;
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

const bool AHX::IsEncryption()
{
	return m_ahxState->Encryption;
}

const bool AHX::IsInitialized()
{
	return m_ahxState->Initialized;
}

const std::vector<SymmetricKeySize> &AHX::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string AHX::Name()
{
	std::string tmpn;

	tmpn = Enumeration::BlockCipherConvert::ToName(Enumeral());

	return tmpn;
}

const size_t AHX::Rounds()
{
	return m_ahxState->Rounds;
}

const size_t AHX::StateCacheSize()
{
	return STATE_PRECACHED;
}

//~~~Public Functions~~~//

void AHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void AHX::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void AHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void AHX::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void AHX::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, Parameters.KeySizes().KeySize()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}

	if (m_kdfGenerator != nullptr)
	{
		std::string tmpn = Name();
		m_ahxState->Custom.resize(tmpn.size() + sizeof(ushort) + Parameters.KeySizes().InfoSize());
		// add the ciphers formal class name to the customization string
		MemoryTools::CopyFromObject(tmpn.data(), m_ahxState->Custom, 0, tmpn.size());
		// add the key size in bits
		ushort ksec = static_cast<ushort>(Parameters.KeySizes().KeySize()) * 8;
		IntegerTools::Le16ToBytes(ksec, m_ahxState->Custom, tmpn.size());
		// append the optional info code
		MemoryTools::Copy(Parameters.Info(), 0, m_ahxState->Custom, tmpn.size() + sizeof(ushort), Parameters.KeySizes().InfoSize());

		// kdf key expansion
		SecureExpand(Parameters.SecureKey(), m_ahxState, m_kdfGenerator);
	}
	else
	{
		// standard rijndael key expansion
		StandardExpand(Parameters.SecureKey(), m_ahxState);
	}

	// inverse cipher
	if (!Encryption)
	{
		size_t i;
		size_t j;

		std::swap(m_ahxState->RoundKeys[0], m_ahxState->RoundKeys[m_ahxState->RoundKeys.size() - 1]);

		for (i = 1, j = m_ahxState->RoundKeys.size() - 2; i < j; ++i, --j)
		{
			__m128i temp = _mm_aesimc_si128(m_ahxState->RoundKeys[i]);
			m_ahxState->RoundKeys[i] = _mm_aesimc_si128(m_ahxState->RoundKeys[j]);
			m_ahxState->RoundKeys[j] = temp;
		}

		m_ahxState->RoundKeys[i] = _mm_aesimc_si128(m_ahxState->RoundKeys[i]);
	}

	// ready to transform data
	m_ahxState->Encryption = Encryption;
	m_ahxState->Initialized = true;
}

void AHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_ahxState->Encryption)
	{
		Encrypt128(Input, 0, Output, 0);
	}
	else
	{
		Decrypt128(Input, 0, Output, 0);
	}
}

void AHX::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (m_ahxState->Encryption)
	{
		Encrypt128(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt128(Input, InOffset, Output, OutOffset);
	}
}

void AHX::Transform512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (m_ahxState->Encryption)
	{
		Encrypt512(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt512(Input, InOffset, Output, OutOffset);
	}
}

void AHX::Transform1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (m_ahxState->Encryption)
	{
		Encrypt1024(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt1024(Input, InOffset, Output, OutOffset);
	}
}

void AHX::Transform2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (m_ahxState->Encryption)
	{
		Encrypt2048(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt2048(Input, InOffset, Output, OutOffset);
	}
}

//~~~Key Schedule~~~//

void AHX::SecureExpand(const SecureVector<byte> &Key, std::unique_ptr<AhxState> &State, std::unique_ptr<IKdf> &Generator)
{
	size_t i;
	size_t j;
	size_t klen;
	uint tmpbk;

	// rounds: k256=22, k512=30, k1024=38
	State->Rounds = Key.size() != 128 ? (Key.size() / 4) + 14 : 38;
	// round-key array size
	klen = ((BLOCK_SIZE / sizeof(uint)) * (State->Rounds + 1)) / 4;
	SecureVector<byte> tmpr(klen * sizeof(__m128i));
	// salt is not used
	SecureVector<byte> salt(0);
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
}

void AHX::StandardExpand(const SecureVector<byte> &Key, std::unique_ptr<AhxState> &State)
{
	// block and key in 32bit words
	const size_t BWORDS = BLOCK_SIZE / sizeof(uint);
	const size_t KWORDS = Key.size() / sizeof(uint);

	// rounds count calculation
	State->Rounds = KWORDS + 6;
	// create the expanded round-keys
	State->RoundKeys.resize((BWORDS * (State->Rounds + 1)) / sizeof(uint));

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
}

void AHX::ExpandRotBlock(std::vector<__m128i> &Key, __m128i* K1, __m128i* K2, __m128i KR, size_t Offset)
{
	// 192 bit key expansion method, -requires additional processing
	__m128i key1 = *K1;

	KR = _mm_shuffle_epi32(KR, _MM_SHUFFLE(1, 1, 1, 1));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, KR);
	*K1 = key1;

	std::memcpy(reinterpret_cast<byte*>(Key.data()) + Offset, &key1, sizeof(__m128i));

	if (!(Offset == 192 && Key.size() == 13))
	{
		__m128i key2 = *K2;
		key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
		key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(key1, _MM_SHUFFLE(3, 3, 3, 3)));
		*K2 = key2;

		Offset += 16;
		std::vector<byte> tmpB(4);
		IntegerTools::Le32ToBytes(_mm_cvtsi128_si32(key2), tmpB, 0);
		std::memcpy(reinterpret_cast<byte*>(Key.data()) + Offset, &tmpB[0], sizeof(uint));

		Offset += 4;
		IntegerTools::Le32ToBytes(_mm_cvtsi128_si32(_mm_srli_si128(key2, sizeof(uint))), tmpB, 0);
		std::memcpy(reinterpret_cast<byte*>(Key.data()) + Offset, &tmpB[0], sizeof(uint));
	}
}

void AHX::ExpandRotBlock(std::vector<__m128i> &Key, size_t Index, size_t Offset)
{
	// 128, 256, 512 bit key method
	__m128i pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(Key[Index], 0xFF);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

void AHX::ExpandSubBlock(std::vector<__m128i> &Key, size_t Index, size_t Offset)
{
	// used with 256 and 512 bit keys
	__m128i pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(Key[Index - 1], 0x0), 0xAA);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

//~~~Rounds Processing~~~//

void AHX::Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_ahxState->RoundKeys.size() - 2;
	size_t kctr = 0;

	__m128i X = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
	X = _mm_xor_si128(X, m_ahxState->RoundKeys[kctr]);

	while (kctr != RNDCNT)
	{
		++kctr;
		X = _mm_aesdec_si128(X, m_ahxState->RoundKeys[kctr]);
	}

	++kctr;
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_aesdeclast_si128(X, m_ahxState->RoundKeys[kctr]));
}

void AHX::Decrypt512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_ahxState->RoundKeys.size() - 2;
	size_t kctr = 0;

	Numeric::UInt128 X0(Input, InOffset);
	Numeric::UInt128 X1(Input, InOffset + 16);
	Numeric::UInt128 X2(Input, InOffset + 32);
	Numeric::UInt128 X3(Input, InOffset + 48);

	X0.xmm = _mm_xor_si128(X0.xmm, m_ahxState->RoundKeys[kctr]);
	X1.xmm = _mm_xor_si128(X1.xmm, m_ahxState->RoundKeys[kctr]);
	X2.xmm = _mm_xor_si128(X2.xmm, m_ahxState->RoundKeys[kctr]);
	X3.xmm = _mm_xor_si128(X3.xmm, m_ahxState->RoundKeys[kctr]);

	while (kctr != RNDCNT)
	{
		++kctr;
		X0.xmm = _mm_aesdec_si128(X0.xmm, m_ahxState->RoundKeys[kctr]);
		X1.xmm = _mm_aesdec_si128(X1.xmm, m_ahxState->RoundKeys[kctr]);
		X2.xmm = _mm_aesdec_si128(X2.xmm, m_ahxState->RoundKeys[kctr]);
		X3.xmm = _mm_aesdec_si128(X3.xmm, m_ahxState->RoundKeys[kctr]);
	}

	++kctr;
	X0.xmm = _mm_aesdeclast_si128(X0.xmm, m_ahxState->RoundKeys[kctr]);
	X1.xmm = _mm_aesdeclast_si128(X1.xmm, m_ahxState->RoundKeys[kctr]);
	X2.xmm = _mm_aesdeclast_si128(X2.xmm, m_ahxState->RoundKeys[kctr]);
	X3.xmm = _mm_aesdeclast_si128(X3.xmm, m_ahxState->RoundKeys[kctr]);

	X0.Store(Output, OutOffset);
	X1.Store(Output, OutOffset + 16);
	X2.Store(Output, OutOffset + 32);
	X3.Store(Output, OutOffset + 48);
}

void AHX::Decrypt1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	// no aes-ni 256 api.. yet
	Decrypt512(Input, InOffset, Output, OutOffset);
	Decrypt512(Input, InOffset + 64, Output, OutOffset + 64);
}

void AHX::Decrypt2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Decrypt1024(Input, InOffset, Output, OutOffset);
	Decrypt1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void AHX::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_ahxState->RoundKeys.size() - 2;
	size_t kctr = 0;

	__m128i X = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
	X = _mm_xor_si128(X, m_ahxState->RoundKeys[kctr]);

	while (kctr != RNDCNT)
	{
		++kctr;
		X = _mm_aesenc_si128(X, m_ahxState->RoundKeys[kctr]);
	}

	++kctr;
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_aesenclast_si128(X, m_ahxState->RoundKeys[kctr]));
}

void AHX::Encrypt512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_ahxState->RoundKeys.size() - 2;
	size_t kctr = 0;

	Numeric::UInt128 X0(Input, InOffset);
	Numeric::UInt128 X1(Input, InOffset + 16);
	Numeric::UInt128 X2(Input, InOffset + 32);
	Numeric::UInt128 X3(Input, InOffset + 48);

	X0.xmm = _mm_xor_si128(X0.xmm, m_ahxState->RoundKeys[kctr]);
	X1.xmm = _mm_xor_si128(X1.xmm, m_ahxState->RoundKeys[kctr]);
	X2.xmm = _mm_xor_si128(X2.xmm, m_ahxState->RoundKeys[kctr]);
	X3.xmm = _mm_xor_si128(X3.xmm, m_ahxState->RoundKeys[kctr]);

	while (kctr != RNDCNT)
	{
		++kctr;
		X0.xmm = _mm_aesenc_si128(X0.xmm, m_ahxState->RoundKeys[kctr]);
		X1.xmm = _mm_aesenc_si128(X1.xmm, m_ahxState->RoundKeys[kctr]);
		X2.xmm = _mm_aesenc_si128(X2.xmm, m_ahxState->RoundKeys[kctr]);
		X3.xmm = _mm_aesenc_si128(X3.xmm, m_ahxState->RoundKeys[kctr]);
	}

	++kctr;
	X0.xmm = _mm_aesenclast_si128(X0.xmm, m_ahxState->RoundKeys[kctr]);
	X1.xmm = _mm_aesenclast_si128(X1.xmm, m_ahxState->RoundKeys[kctr]);
	X2.xmm = _mm_aesenclast_si128(X2.xmm, m_ahxState->RoundKeys[kctr]);
	X3.xmm = _mm_aesenclast_si128(X3.xmm, m_ahxState->RoundKeys[kctr]);

	X0.Store(Output, OutOffset);
	X1.Store(Output, OutOffset + 16);
	X2.Store(Output, OutOffset + 32);
	X3.Store(Output, OutOffset + 48);
}

void AHX::Encrypt1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Encrypt512(Input, InOffset, Output, OutOffset);
	Encrypt512(Input, InOffset + 64, Output, OutOffset + 64);
}

void AHX::Encrypt2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Encrypt1024(Input, InOffset, Output, OutOffset);
	Encrypt1024(Input, InOffset + 128, Output, OutOffset + 128);
}

//~~~Helpers~~~//

std::vector<SymmetricKeySize> AHX::CalculateKeySizes(BlockCipherExtensions Extension)
{
	std::vector<SymmetricKeySize> keys(0);

	// Note: the hkdf variants info-size calculation: block-size - (name-size + hash-size + 1-byte hkdf counter + sha2 padding) fills one sha2 final block,
	// this avoids permuting a partially empty block, for security and performance reasons.
	// In the shake variants, info is the shake name string, which is sized as the shake-rate - the classes string-name-size and 2 bytes for the key-size-bits.

	switch (Extension)
	{
	case BlockCipherExtensions::None:
	{
		keys.push_back(SymmetricKeySize(16, BLOCK_SIZE, 0));
		keys.push_back(SymmetricKeySize(24, BLOCK_SIZE, 0));
		keys.push_back(SymmetricKeySize(32, BLOCK_SIZE, 0));
		break;
	}
	case BlockCipherExtensions::HKDF256:
	{
		keys.push_back(SymmetricKeySize(32, BLOCK_SIZE, 13));
		keys.push_back(SymmetricKeySize(64, BLOCK_SIZE, 13));
		keys.push_back(SymmetricKeySize(128, BLOCK_SIZE, 13));
		break;
	}
	case BlockCipherExtensions::HKDF512:
	{
		keys.push_back(SymmetricKeySize(32, BLOCK_SIZE, 37));
		keys.push_back(SymmetricKeySize(64, BLOCK_SIZE, 37));
		keys.push_back(SymmetricKeySize(128, BLOCK_SIZE, 37));
		break;
	}
	case BlockCipherExtensions::SHAKE256:
	{
		keys.push_back(SymmetricKeySize(32, BLOCK_SIZE, 127));
		keys.push_back(SymmetricKeySize(64, BLOCK_SIZE, 127));
		keys.push_back(SymmetricKeySize(128, BLOCK_SIZE, 127));
		break;
	}
	case BlockCipherExtensions::SHAKE128:
	{
		keys.push_back(SymmetricKeySize(32, BLOCK_SIZE, 159));
		keys.push_back(SymmetricKeySize(64, BLOCK_SIZE, 159));
		keys.push_back(SymmetricKeySize(128, BLOCK_SIZE, 159));
		break;
	}
	case BlockCipherExtensions::SHAKE512:
	{
		keys.push_back(SymmetricKeySize(32, BLOCK_SIZE, 63));
		keys.push_back(SymmetricKeySize(64, BLOCK_SIZE, 63));
		keys.push_back(SymmetricKeySize(128, BLOCK_SIZE, 63));
		break;
	}
	case BlockCipherExtensions::SHAKE1024:
	{
		keys.push_back(SymmetricKeySize(32, BLOCK_SIZE, 62));
		keys.push_back(SymmetricKeySize(64, BLOCK_SIZE, 62));
		keys.push_back(SymmetricKeySize(128, BLOCK_SIZE, 62));
		break;
	}
	}

	return keys;
}

NAMESPACE_BLOCKEND

