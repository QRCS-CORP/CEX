#include "SHX.h"
#include "Serpent.h"
#include "IntegerTools.h"
#include "KdfFromName.h"

#if defined(__AVX512__)
#	include "UInt512.h"
#elif defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_BLOCK

using namespace Cipher::Block::SerpentBase;
using Utility::IntegerTools;
using Enumeration::Kdfs;
using Utility::MemoryTools;

class SHX::ShxState
{
public:

	SecureVector<byte> Custom;
	SecureVector<uint> RoundKeys;
	size_t Rounds;
	BlockCipherExtensions Extension;
	bool Destroyed;
	bool Encryption;
	bool Initialized;

	ShxState(BlockCipherExtensions CipherExtension, bool IsDestroyed)
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

	~ShxState()
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

SHX::SHX(BlockCipherExtensions CipherExtension)
	:
	m_shxState(new ShxState(CipherExtension, true)),
	m_kdfGenerator(CipherExtension == BlockCipherExtensions::None ? nullptr :
		Helper::KdfFromName::GetInstance(CipherExtension)),
	m_legalKeySizes(CalculateKeySizes(CipherExtension))
{
}

SHX::SHX(IKdf* Kdf)
	:
	m_shxState(new ShxState(Kdf != nullptr ? static_cast<BlockCipherExtensions>(Kdf->Enumeral()) :
		BlockCipherExtensions::None,
		false)),
	m_kdfGenerator(Kdf),
	m_legalKeySizes(CalculateKeySizes(Kdf != nullptr ? static_cast<BlockCipherExtensions>(Kdf->Enumeral()) : 
		BlockCipherExtensions::None))
{
}

SHX::~SHX()
{
	if (m_shxState->Destroyed)
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

const size_t SHX::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers SHX::Enumeral()
{
	BlockCiphers tmpn;
	Kdfs ext;

	ext = (m_kdfGenerator != nullptr) ? m_kdfGenerator->Enumeral() : Kdfs::None;

	switch (ext)
	{
		case Kdfs::HKDF256:
		{
			tmpn = BlockCiphers::SHXH256;
			break;
		}
		case Kdfs::HKDF512:
		{
			tmpn = BlockCiphers::SHXH512;
			break;
		}
		case Kdfs::SHAKE256:
		{
			tmpn = BlockCiphers::SHXS256;
			break;
		}
		case Kdfs::SHAKE512:
		{
			tmpn = BlockCiphers::SHXS512;
			break;
		}
		case Kdfs::SHAKE1024:
		{
			tmpn = BlockCiphers::SHXS1024;
			break;
		}
		default:
		{
			tmpn = BlockCiphers::Serpent;
		}
	}

	return tmpn;
}

const bool SHX::IsEncryption()
{
	return m_shxState->Encryption;
}

const bool SHX::IsInitialized()
{
	return m_shxState->Initialized;
}

const std::vector<SymmetricKeySize> &SHX::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string SHX::Name()
{
	std::string tmpn;

	tmpn = Enumeration::BlockCipherConvert::ToName(Enumeral());

	return tmpn;
}

const size_t SHX::Rounds()
{
	return m_shxState->Rounds;
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

void SHX::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void SHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void SHX::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void SHX::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, Parameters.KeySizes().KeySize()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}

	m_shxState->Encryption = Encryption;

	// expand the key
	if (m_kdfGenerator != nullptr)
	{
		std::string tmpn = Name();
		m_shxState->Custom.resize(tmpn.size() + sizeof(ushort) + Parameters.KeySizes().InfoSize());
		// add the ciphers formal class name to the customization string
		MemoryTools::CopyFromObject(tmpn.data(), m_shxState->Custom, 0, tmpn.size());
		// add the key size in bits
		ushort ksec = static_cast<ushort>(Parameters.KeySizes().KeySize()) * 8;
		IntegerTools::Le16ToBytes(ksec, m_shxState->Custom, tmpn.size());
		// append the optional info code
		MemoryTools::Copy(Parameters.Info(), 0, m_shxState->Custom, tmpn.size() + sizeof(ushort), Parameters.KeySizes().InfoSize());

		// kdf key expansion
		SecureExpand(Parameters.SecureKey(), m_shxState, m_kdfGenerator);
	}
	else
	{
		// standard serpent key expansion + k512
		StandardExpand(Parameters.SecureKey(), m_shxState);
	}

	// ready to transform data
	m_shxState->Initialized = true;
}

void SHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_shxState->Encryption)
	{
		Encrypt128(Input, 0, Output, 0);
	}
	else
	{
		Decrypt128(Input, 0, Output, 0);
	}
}

void SHX::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (m_shxState->Encryption)
	{
		Encrypt128(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt128(Input, InOffset, Output, OutOffset);
	}
}

void SHX::Transform512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (m_shxState->Encryption)
	{
		Encrypt512(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt512(Input, InOffset, Output, OutOffset);
	}
}

void SHX::Transform1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (m_shxState->Encryption)
	{
		Encrypt1024(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt1024(Input, InOffset, Output, OutOffset);
	}
}

void SHX::Transform2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (m_shxState->Encryption)
	{
		Encrypt2048(Input, InOffset, Output, OutOffset);
	}
	else
	{
		Decrypt2048(Input, InOffset, Output, OutOffset);
	}
}

//~~~Key Schedule~~~//

void SHX::SecureExpand(const SecureVector<byte> &Key, std::unique_ptr<ShxState> &State, std::unique_ptr<IKdf> &Generator)
{
	size_t klen;

	// rounds: k256=40, k512=48, k1024=64
	State->Rounds = Key.size() == 32 ? 40 : Key.size() == 64 ? 48 : 64;
	// round-key array size
	klen = 4 * (State->Rounds + 1);
	SecureVector<byte> tmpr(klen * sizeof(uint));
	// salt is not used
	SecureVector<byte> salt(0);
	// initialize the generator
	SymmetricKey kp(Key, salt, State->Custom);
	Generator->Initialize(kp);
	// generate the keying material
	Generator->Generate(tmpr);
	// initialize round-key array
	State->RoundKeys.resize(klen, 0);

	// copy bytes to working key
#if defined(CEX_IS_LITTLE_ENDIAN)
	MemoryTools::Copy(tmpr, 0, State->RoundKeys, 0, tmpr.size());
#else
	for (size_t i = 0; i < State->RoundKeys.size(); ++i)
	{
		State->RoundKeys[i] = IntegerTools::LeBytesTo32(tmpr, i * sizeof(uint));
	}
#endif

	MemoryTools::Clear(tmpr, 0, tmpr.size());
}

void SHX::StandardExpand(const SecureVector<byte> &Key, std::unique_ptr<ShxState> &State)
{
	const size_t WPKLEN = Key.size() < 32 ? 16 : Key.size() / 2;
	std::vector<uint> tmpw(WPKLEN);
	size_t kctr;
	size_t kidx;
	size_t klen;
	size_t woft;

	State->Rounds = (Key.size() == 64) ? 40 : 32;
	klen = sizeof(uint) * (State->Rounds + 1);
	kidx = 0;
	woft = 0;

	// step 1: reverse copy key to temp array
	for (woft = Key.size(); woft > 0; woft -= sizeof(uint))
	{
		tmpw[kidx] = IntegerTools::BeBytesTo32(Key, woft - sizeof(uint));
		++kidx;
	}

	// pad small key
	if (kidx < 8)
	{
		tmpw[kidx] = 1;
	}

	// initialize the key
	State->RoundKeys.resize(klen);

	if (WPKLEN == 16)
	{
		// 32 byte key
		// step 2: rotate k into w(k) ints
		for (size_t i = 8; i < 16; i++)
		{
			tmpw[i] = IntegerTools::RotL32(static_cast<uint>(tmpw[i - 8] ^ tmpw[i - 5] ^ tmpw[i - 3] ^ tmpw[i - 1] ^ PHI ^ (i - 8)), 11);
		}

		// copy to expanded key
		MemoryTools::Copy(tmpw, 8, State->RoundKeys, 0, 8 * sizeof(uint));

		// step 3: calculate remainder of rounds with rotating polynomial
		for (size_t i = 8; i < klen; i++)
		{
			State->RoundKeys[i] = IntegerTools::RotL32(static_cast<uint>(State->RoundKeys[i - 8] ^ State->RoundKeys[i - 5] ^ State->RoundKeys[i - 3] ^ State->RoundKeys[i - 1] ^ PHI ^ i), 11);
		}
	}
	else
	{
		// *extended*: 64 byte key
		// step 3: rotate k into w(k) ints, with extended polynominal
		// tmpw := (tmpw-16 ^ tmpw-13 ^ tmpw-11 ^ tmpw-10 ^ tmpw-8 ^ tmpw-5 ^ tmpw-3 ^ tmpw-1 ^ PHI ^ i) <<< 11
		for (size_t i = 16; i < 32; i++)
		{
			tmpw[i] = IntegerTools::RotL32(static_cast<uint>(tmpw[i - 16] ^ tmpw[i - 13] ^ tmpw[i - 11] ^ tmpw[i - 10] ^ tmpw[i - 8] ^ tmpw[i - 5] ^ tmpw[i - 3] ^ tmpw[i - 1] ^ PHI ^ (i - 16)), 11);
		}

		// copy to expanded key
		MemoryTools::Copy(tmpw, 16, State->RoundKeys, 0, 16 * sizeof(uint));

		// step 3: calculate remainder of rounds with rotating polynomial
		for (size_t i = 16; i < klen; i++)
		{
			State->RoundKeys[i] = IntegerTools::RotL32(static_cast<uint>(State->RoundKeys[i - 16] ^ State->RoundKeys[i - 13] ^ State->RoundKeys[i - 11] ^ State->RoundKeys[i - 10] ^ State->RoundKeys[i - 8] ^ State->RoundKeys[i - 5] ^ State->RoundKeys[i - 3] ^ State->RoundKeys[i - 1] ^ PHI ^ i), 11);
		}
	}

	MemoryTools::Clear(tmpw, 0, tmpw.size());
	kctr = 0;

	// step 4: create the working keys by processing with the Sbox and IP
	while (kctr < klen - 4)
	{
		Sb3(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]); 
		kctr += 4;
		Sb2(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]); 
		kctr += 4;
		Sb1(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]); 
		kctr += 4;
		Sb0(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]); 
		kctr += 4;
		Sb7(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]); 
		kctr += 4;
		Sb6(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]); 
		kctr += 4;
		Sb5(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]); 
		kctr += 4;
		Sb4(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]); 
		kctr += 4;
	}

	// last round
	Sb3(State->RoundKeys[kctr], State->RoundKeys[kctr + 1], State->RoundKeys[kctr + 2], State->RoundKeys[kctr + 3]);
}

//~~~Rounds Processing~~~//

void SHX::Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t RNDCNT = 4;
	size_t kctr;
	uint R3;
	uint R2;
	uint R1;
	uint R0;

	// input round
	kctr = m_shxState->RoundKeys.size();
	R3 = IntegerTools::LeBytesTo32(Input, InOffset + 12);
	R2 = IntegerTools::LeBytesTo32(Input, InOffset + 8);
	R1 = IntegerTools::LeBytesTo32(Input, InOffset + 4);
	R0 = IntegerTools::LeBytesTo32(Input, InOffset);
	R3 ^= m_shxState->RoundKeys[kctr - 1];
	R2 ^= m_shxState->RoundKeys[kctr - 2];
	R1 ^= m_shxState->RoundKeys[kctr - 3];
	R0 ^= m_shxState->RoundKeys[kctr - 4];
	kctr -= 4;

	// process 8 round blocks
	do
	{
		Ib7(R0, R1, R2, R3);
		R3 ^= m_shxState->RoundKeys[kctr - 1];
		R2 ^= m_shxState->RoundKeys[kctr - 2];
		R1 ^= m_shxState->RoundKeys[kctr - 3];
		R0 ^= m_shxState->RoundKeys[kctr - 4];
		InverseTransform(R0, R1, R2, R3);

		Ib6(R0, R1, R2, R3);
		R3 ^= m_shxState->RoundKeys[kctr - 5];
		R2 ^= m_shxState->RoundKeys[kctr - 6];
		R1 ^= m_shxState->RoundKeys[kctr - 7];
		R0 ^= m_shxState->RoundKeys[kctr - 8];
		InverseTransform(R0, R1, R2, R3);

		Ib5(R0, R1, R2, R3);
		R3 ^= m_shxState->RoundKeys[kctr - 9];
		R2 ^= m_shxState->RoundKeys[kctr - 10];
		R1 ^= m_shxState->RoundKeys[kctr - 11];
		R0 ^= m_shxState->RoundKeys[kctr - 12];
		InverseTransform(R0, R1, R2, R3);

		Ib4(R0, R1, R2, R3);
		R3 ^= m_shxState->RoundKeys[kctr - 13];
		R2 ^= m_shxState->RoundKeys[kctr - 14];
		R1 ^= m_shxState->RoundKeys[kctr - 15];
		R0 ^= m_shxState->RoundKeys[kctr - 16];
		InverseTransform(R0, R1, R2, R3);

		Ib3(R0, R1, R2, R3);
		R3 ^= m_shxState->RoundKeys[kctr - 17];
		R2 ^= m_shxState->RoundKeys[kctr - 18];
		R1 ^= m_shxState->RoundKeys[kctr - 19];
		R0 ^= m_shxState->RoundKeys[kctr - 20];
		InverseTransform(R0, R1, R2, R3);

		Ib2(R0, R1, R2, R3);
		R3 ^= m_shxState->RoundKeys[kctr - 21];
		R2 ^= m_shxState->RoundKeys[kctr - 22];
		R1 ^= m_shxState->RoundKeys[kctr - 23];
		R0 ^= m_shxState->RoundKeys[kctr - 24];
		InverseTransform(R0, R1, R2, R3);

		Ib1(R0, R1, R2, R3);
		R3 ^= m_shxState->RoundKeys[kctr - 25];
		R2 ^= m_shxState->RoundKeys[kctr - 26];
		R1 ^= m_shxState->RoundKeys[kctr - 27];
		R0 ^= m_shxState->RoundKeys[kctr - 28];
		InverseTransform(R0, R1, R2, R3);

		Ib0(R0, R1, R2, R3);
		kctr -= 28;

		// skip on last block
		if (kctr != RNDCNT)
		{
			R3 ^= m_shxState->RoundKeys[kctr - 1];
			R2 ^= m_shxState->RoundKeys[kctr - 2];
			R1 ^= m_shxState->RoundKeys[kctr - 3];
			R0 ^= m_shxState->RoundKeys[kctr - 4];
			InverseTransform(R0, R1, R2, R3);
			kctr -= 4;
		}
	} 
	while (kctr != RNDCNT);

	// last round
	IntegerTools::Le32ToBytes(R3 ^ m_shxState->RoundKeys[kctr - 1], Output, OutOffset + 12);
	IntegerTools::Le32ToBytes(R2 ^ m_shxState->RoundKeys[kctr - 2], Output, OutOffset + 8);
	IntegerTools::Le32ToBytes(R1 ^ m_shxState->RoundKeys[kctr - 3], Output, OutOffset + 4);
	IntegerTools::Le32ToBytes(R0 ^ m_shxState->RoundKeys[kctr - 4], Output, OutOffset);
}

void SHX::Decrypt512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	DecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void SHX::Decrypt1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if (!defined(__AVX512__)) && defined(__AVX2__)
	DecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	DecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
	DecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_shxState->RoundKeys);
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

void SHX::Decrypt2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(__AVX512__)
	DecryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
#elif (!defined(__AVX512__)) && defined(__AVX2__)
	DecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
	DecryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_shxState->RoundKeys);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	DecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
	DecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_shxState->RoundKeys);
	DecryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_shxState->RoundKeys);
	DecryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_shxState->RoundKeys);
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

void SHX::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_shxState->RoundKeys.size() - 4;
	size_t kctr;
	uint R0;
	uint R1;
	uint R2;
	uint R3;

	// input round
	kctr = 0;
	R0 = IntegerTools::LeBytesTo32(Input, InOffset);
	R1 = IntegerTools::LeBytesTo32(Input, InOffset + 4);
	R2 = IntegerTools::LeBytesTo32(Input, InOffset + 8);
	R3 = IntegerTools::LeBytesTo32(Input, InOffset + 12);

	// process 8 round blocks
	do
	{
		R0 ^= m_shxState->RoundKeys[kctr];
		R1 ^= m_shxState->RoundKeys[kctr + 1];
		R2 ^= m_shxState->RoundKeys[kctr + 2];
		R3 ^= m_shxState->RoundKeys[kctr + 3];
		Sb0(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_shxState->RoundKeys[kctr + 4];
		R1 ^= m_shxState->RoundKeys[kctr + 5];
		R2 ^= m_shxState->RoundKeys[kctr + 6];
		R3 ^= m_shxState->RoundKeys[kctr + 7];
		Sb1(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_shxState->RoundKeys[kctr + 8];
		R1 ^= m_shxState->RoundKeys[kctr + 9];
		R2 ^= m_shxState->RoundKeys[kctr + 10];
		R3 ^= m_shxState->RoundKeys[kctr + 11];
		Sb2(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_shxState->RoundKeys[kctr + 12];
		R1 ^= m_shxState->RoundKeys[kctr + 13];
		R2 ^= m_shxState->RoundKeys[kctr + 14];
		R3 ^= m_shxState->RoundKeys[kctr + 15];
		Sb3(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_shxState->RoundKeys[kctr + 16];
		R1 ^= m_shxState->RoundKeys[kctr + 17];
		R2 ^= m_shxState->RoundKeys[kctr + 18];
		R3 ^= m_shxState->RoundKeys[kctr + 19];
		Sb4(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_shxState->RoundKeys[kctr + 20];
		R1 ^= m_shxState->RoundKeys[kctr + 21];
		R2 ^= m_shxState->RoundKeys[kctr + 22];
		R3 ^= m_shxState->RoundKeys[kctr + 23];
		Sb5(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_shxState->RoundKeys[kctr + 24];
		R1 ^= m_shxState->RoundKeys[kctr + 25];
		R2 ^= m_shxState->RoundKeys[kctr + 26];
		R3 ^= m_shxState->RoundKeys[kctr + 27];
		Sb6(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_shxState->RoundKeys[kctr + 28];
		R1 ^= m_shxState->RoundKeys[kctr + 29];
		R2 ^= m_shxState->RoundKeys[kctr + 30];
		R3 ^= m_shxState->RoundKeys[kctr + 31];
		Sb7(R0, R1, R2, R3);
		kctr += 32;

		// skip on last block
		if (kctr != RNDCNT)
		{
			LinearTransform(R0, R1, R2, R3);
		}
	} 
	while (kctr != RNDCNT);

	// last round
	IntegerTools::Le32ToBytes(m_shxState->RoundKeys[kctr] ^ R0, Output, OutOffset);
	IntegerTools::Le32ToBytes(m_shxState->RoundKeys[kctr + 1] ^ R1, Output, OutOffset + 4);
	IntegerTools::Le32ToBytes(m_shxState->RoundKeys[kctr + 2] ^ R2, Output, OutOffset + 8);
	IntegerTools::Le32ToBytes(m_shxState->RoundKeys[kctr + 3] ^ R3, Output, OutOffset + 12);
}

void SHX::Encrypt512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	EncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void SHX::Encrypt1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if (!defined(__AVX512__)) && defined(__AVX2__)
	EncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	EncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
	EncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_shxState->RoundKeys);
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

void SHX::Encrypt2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(__AVX512__)
	EncryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
#elif (!defined(__AVX512__)) && defined(__AVX2__)
	EncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
	EncryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_shxState->RoundKeys);
#elif (!defined(__AVX512__)) && (!defined(__AVX2__)) && defined(__AVX__)
	EncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_shxState->RoundKeys);
	EncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_shxState->RoundKeys);
	EncryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_shxState->RoundKeys);
	EncryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_shxState->RoundKeys);
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

std::vector<SymmetricKeySize> SHX::CalculateKeySizes(BlockCipherExtensions Extension)
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
