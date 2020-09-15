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

	SecureVector<byte> Custom;
	SecureVector<uint> RoundKeys;
	size_t Rounds;
	BlockCipherExtensions Extension;
	bool Destroyed;
	bool Encryption;
	bool Initialized;

	RhxState(BlockCipherExtensions CipherExtension, bool IsDestroyed)
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

	~RhxState()
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

RHX::RHX(BlockCipherExtensions CipherExtension)
	:
	m_rhxState(new RhxState(CipherExtension, true)),
	m_kdfGenerator(CipherExtension == BlockCipherExtensions::None ?
		nullptr :
		Helper::KdfFromName::GetInstance(CipherExtension)),
	m_legalKeySizes(CalculateKeySizes(CipherExtension))
{
}

RHX::RHX(IKdf* Kdf)
	:
	m_rhxState(new RhxState(Kdf != nullptr ? static_cast<BlockCipherExtensions>(Kdf->Enumeral()) : 
		BlockCipherExtensions::None, 
		false)),
	m_kdfGenerator(Kdf),
	m_legalKeySizes(CalculateKeySizes(Kdf != nullptr ? static_cast<BlockCipherExtensions>(Kdf->Enumeral()) : 
		BlockCipherExtensions::None))
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

	IntegerTools::Clear(m_legalKeySizes);
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
	return m_legalKeySizes;
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

void RHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void RHX::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void RHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void RHX::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void RHX::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, Parameters.KeySizes().KeySize()))
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
		m_rhxState->Custom.resize(tmpn.size() + sizeof(ushort) + Parameters.KeySizes().InfoSize());
		// add the ciphers formal class name to the customization string
		MemoryTools::CopyFromObject(tmpn.data(), m_rhxState->Custom, 0, tmpn.size());
		// add the key size in bits
		ushort ksec = static_cast<ushort>(Parameters.KeySizes().KeySize()) * 8;
		IntegerTools::Le16ToBytes(ksec, m_rhxState->Custom, tmpn.size());
		// append the optional user-supplied info code
		MemoryTools::Copy(Parameters.Info(), 0, m_rhxState->Custom, tmpn.size() + sizeof(ushort), Parameters.KeySizes().InfoSize());

		// call the extended kdf key expansion function, and populate the round key array in state
		SecureExpand(Parameters.SecureKey(), m_rhxState, m_kdfGenerator);
	}
	else
	{
		// standard rijndael key expansion
		StandardExpand(Parameters.SecureKey(), m_rhxState);
	}

	// ready to transform data
	m_rhxState->Initialized = true;
}

void RHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
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

void RHX::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
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

void RHX::Transform512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
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

void RHX::Transform1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
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

void RHX::Transform2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
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

void RHX::SecureExpand(const SecureVector<byte> &Key, std::unique_ptr<RhxState> &State, std::unique_ptr<IKdf> &Generator)
{
	size_t klen;

	// rounds: k256=22, k512=30, k1024=38
	State->Rounds = Key.size() != 128 ? (Key.size() / 4) + 14 : 38;
	// round-key array size
	klen = ((BLOCK_SIZE / sizeof(uint)) * (State->Rounds + 1));
	SecureVector<byte> tmpr(klen * sizeof(uint));
	// salt is not used
	SecureVector<byte> salt(0);
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
		State->RoundKeys[i] = IntegerTools::LeBytesTo32(tmpr, i * sizeof(uint));
	}
#endif

	MemoryTools::Clear(tmpr, 0, tmpr.size());
}

void RHX::StandardExpand(const SecureVector<byte> &Key, std::unique_ptr<RhxState> &State)
{
	// block and key in 32bit words
	const size_t BWORDS = BLOCK_SIZE / sizeof(uint);
	const size_t KWORDS = Key.size() / sizeof(uint);

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
}

void RHX::ExpandRotBlock(SecureVector<uint> &RoundKeys, size_t KeyIndex, size_t KeyOffset, size_t RconIndex)
{
	size_t kctr;

	kctr = KeyIndex - KeyOffset;
	RoundKeys[KeyIndex] = RoundKeys[kctr] ^ 
		SubWord(static_cast<uint>(RoundKeys[KeyIndex - 1] << 8) | static_cast<uint>(RoundKeys[KeyIndex - 1] >> 24) & 0xFF, SBox) ^ 
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

void RHX::ExpandSubBlock(SecureVector<uint> &RoundKeys, size_t KeyIndex, size_t KeyOffset)
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

//~~~Rounds Processing~~~//

void RHX::Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	SecureVector<byte> state(BLOCK_SIZE, 0x00);
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

void RHX::Decrypt512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
}

void RHX::Decrypt1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Decrypt512(Input, InOffset, Output, OutOffset);
	Decrypt512(Input, InOffset + 64, Output, OutOffset + 64);
}

void RHX::Decrypt2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Decrypt1024(Input, InOffset, Output, OutOffset);
	Decrypt1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void RHX::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	SecureVector<byte> state(BLOCK_SIZE, 0x00);
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

void RHX::Encrypt512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
}

void RHX::Encrypt1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Encrypt512(Input, InOffset, Output, OutOffset);
	Encrypt512(Input, InOffset + 64, Output, OutOffset + 64);
}

void RHX::Encrypt2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Encrypt1024(Input, InOffset, Output, OutOffset);
	Encrypt1024(Input, InOffset + 128, Output, OutOffset + 128);
}

//~~~Private Functions~~~//

std::vector<SymmetricKeySize> RHX::CalculateKeySizes(BlockCipherExtensions Extension)
{
	std::vector<SymmetricKeySize> keys(3);

	// Note: the hkdf variants info-size calculation: block-size - (name-size + hash-size + 1-byte hkdf counter + sha2 padding) fills one sha2 final block,
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
		case BlockCipherExtensions::SHAKE1024:
		{
			keys[0] = SymmetricKeySize(32, BLOCK_SIZE, 62);
			keys[1] = SymmetricKeySize(64, BLOCK_SIZE, 62);
			keys[2] = SymmetricKeySize(128, BLOCK_SIZE, 62);
			break;
		}
	}

	return keys;
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

NAMESPACE_BLOCKEND
