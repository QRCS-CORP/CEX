#include "TSX1024.h"
#include "IntegerTools.h"
#include "KMAC.h"
#include "MemoryTools.h"
#include "ParallelTools.h"
#include "SHAKE.h"
#include "Threefish.h"

#if defined(CEX_HAS_AVX2)
#	include "ULong256.h"
#endif

NAMESPACE_STREAM

using Tools::IntegerTools;
using Mac::KMAC;
using Tools::MemoryTools;
using Tools::ParallelTools;

const std::string TSX1024::CLASS_NAME("TSX1024");
const std::vector<uint8_t> TSX1024::OMEGA_INFO = { 0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73, 0x68, 0x31, 0x30, 0x32, 0x34, 0x31, 0x32, 0x30 };

class TSX1024::TSX1024State
{
public:

	std::array<uint64_t, 16> Key = { 0 };
	std::array<uint64_t, 2> Nonce = { 0 };
	std::array<uint64_t, 2> Tweak = { 0 };
	SecureVector<uint8_t> Custom;
	std::vector<SymmetricKeySize> LegalKeySizes{
		SymmetricKeySize(IK1024_SIZE, NONCE_SIZE * sizeof(uint64_t), INFO_SIZE) };
	SecureVector<uint8_t> MacKey;
	SecureVector<uint8_t> MacTag;
	uint64_t Counter = 0;
	bool IsAuthenticated = false;
	bool IsEncryption = false;
	bool IsInitialized = false;

	TSX1024State(bool Authenticated)
		:
		Custom(0),
		MacKey(0),
		MacTag(0),
		IsAuthenticated(Authenticated)
	{
	}

	~TSX1024State()
	{
		LegalKeySizes.clear();
		MemoryTools::Clear(Key, 0, Key.size() * sizeof(uint64_t));
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(uint64_t));
		MemoryTools::Clear(Tweak, 0, Tweak.size() * sizeof(uint64_t));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		IsAuthenticated = false;
		IsEncryption = false;
		IsInitialized = false;
	}

	void Reset()
	{
		MemoryTools::Clear(Key, 0, Key.size() * sizeof(uint64_t));
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(uint64_t));
		MemoryTools::Clear(Tweak, 0, Tweak.size() * sizeof(uint64_t));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		IsEncryption = false;
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

TSX1024::TSX1024(bool Authenticate)
	:
	m_tsx1024State(new TSX1024State(Authenticate)),
	m_macAuthenticator(nullptr),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

TSX1024::~TSX1024()
{
	if (m_tsx1024State != nullptr)
	{
		m_tsx1024State.reset(nullptr);
	}
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers TSX1024::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() ? 
		StreamAuthenticators::KMAC512 : 
		StreamAuthenticators::None;
	tmpn = Enumeration::StreamCipherConvert::FromDescription(StreamCiphers::TSX256, auth);

	return tmpn;
}

const bool TSX1024::IsAuthenticator()
{
	return m_tsx1024State->IsAuthenticated;
}

const bool TSX1024::IsEncryption()
{
	return m_tsx1024State->IsEncryption;
}

const bool TSX1024::IsInitialized()
{
	return m_tsx1024State->IsInitialized;
}

const bool TSX1024::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &TSX1024::LegalKeySizes()
{
	return m_tsx1024State->LegalKeySizes;
}

const std::string TSX1024::Name()
{
	std::string name;

	name = CLASS_NAME;

	if (IsAuthenticator())
	{
		name += std::string("-") + Enumeration::StreamAuthenticatorConvert::ToName(StreamAuthenticators::KMAC512);
	}

	return name;
}

const std::vector<uint8_t> TSX1024::Nonce()
{
	std::vector<uint8_t> tmpn(2 * sizeof(uint64_t));

	IntegerTools::Le64ToBytes(m_tsx1024State->Nonce[0], tmpn, 0);
	IntegerTools::Le64ToBytes(m_tsx1024State->Nonce[1], tmpn, sizeof(uint64_t));

	return tmpn;
}

const size_t TSX1024::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &TSX1024::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<uint8_t> TSX1024::Tag()
{
	return SecureUnlock(m_tsx1024State->MacTag);
}

const void TSX1024::Tag(SecureVector<uint8_t> &Output)
{
	SecureCopy(m_tsx1024State->MacTag, 0, Output, 0, m_tsx1024State->MacTag.size());
}

const size_t TSX1024::TagSize()
{
	return IsAuthenticator() ? TAG_SIZE : 0;
}

//~~~Public Functions~~~//

void TSX1024::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().KeySize() != KEY_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().IVSize() != (NONCE_SIZE * sizeof(uint64_t)))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Nonce must be 16 bytes!"), ErrorCodes::InvalidNonce);
	}
	if (Parameters.KeySizes().InfoSize() > 0 && Parameters.KeySizes().InfoSize() > INFO_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Info must be no more than 16 bytes!"), ErrorCodes::InvalidInfo);
	}

	if (m_parallelProfile.IsParallel())
	{
		if (m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	// reset the counter and mac
	if (IsInitialized() == true)
	{
		Reset();
	}

	// copy nonce
	m_tsx1024State->Nonce[0] = IntegerTools::LeBytesTo64(Parameters.IV(), 0);
	m_tsx1024State->Nonce[1] = IntegerTools::LeBytesTo64(Parameters.IV(), 8);

	if (Parameters.KeySizes().InfoSize() != 0)
	{
		// custom code
		m_tsx1024State->Tweak[0] = IntegerTools::LeBytesTo64(Parameters.Info(), 0);
		m_tsx1024State->Tweak[1] = IntegerTools::LeBytesTo64(Parameters.Info(), 8);
	}
	else
	{
		// default tweak
		m_tsx1024State->Tweak[0] = IntegerTools::LeBytesTo64(OMEGA_INFO, 0);
		m_tsx1024State->Tweak[1] = IntegerTools::LeBytesTo64(OMEGA_INFO, 8);
	}

	if (IsAuthenticator() == false)
	{
		m_tsx1024State->Key[0] = IntegerTools::LeBytesTo64(Parameters.Key(), 0);
		m_tsx1024State->Key[1] = IntegerTools::LeBytesTo64(Parameters.Key(), 8);
		m_tsx1024State->Key[2] = IntegerTools::LeBytesTo64(Parameters.Key(), 16);
		m_tsx1024State->Key[3] = IntegerTools::LeBytesTo64(Parameters.Key(), 24);
		m_tsx1024State->Key[4] = IntegerTools::LeBytesTo64(Parameters.Key(), 32);
		m_tsx1024State->Key[5] = IntegerTools::LeBytesTo64(Parameters.Key(), 40);
		m_tsx1024State->Key[6] = IntegerTools::LeBytesTo64(Parameters.Key(), 48);
		m_tsx1024State->Key[7] = IntegerTools::LeBytesTo64(Parameters.Key(), 56);
		m_tsx1024State->Key[8] = IntegerTools::LeBytesTo64(Parameters.Key(), 64);
		m_tsx1024State->Key[9] = IntegerTools::LeBytesTo64(Parameters.Key(), 72);
		m_tsx1024State->Key[10] = IntegerTools::LeBytesTo64(Parameters.Key(), 80);
		m_tsx1024State->Key[11] = IntegerTools::LeBytesTo64(Parameters.Key(), 88);
		m_tsx1024State->Key[12] = IntegerTools::LeBytesTo64(Parameters.Key(), 96);
		m_tsx1024State->Key[13] = IntegerTools::LeBytesTo64(Parameters.Key(), 104);
		m_tsx1024State->Key[14] = IntegerTools::LeBytesTo64(Parameters.Key(), 112);
		m_tsx1024State->Key[15] = IntegerTools::LeBytesTo64(Parameters.Key(), 120);
	}
	else
	{
		m_macAuthenticator.reset(new KMAC(Enumeration::KmacModes::KMAC512));

		// set the initial counter value
		m_tsx1024State->Counter = 1;

		// create the cSHAKE customization string
		m_tsx1024State->Custom.resize(sizeof(uint64_t) + Name().size());
		// add mac counter and algorithm name to customization string
		IntegerTools::Le64ToBytes(m_tsx1024State->Counter, m_tsx1024State->Custom, 0);
		MemoryTools::CopyFromObject(Name().data(), m_tsx1024State->Custom, sizeof(uint64_t), Name().size());

		// initialize cSHAKE
		Kdf::SHAKE gen(ShakeModes::SHAKE512);
		gen.Initialize(Parameters.SecureKey(), m_tsx1024State->Custom);

		// generate the new cipher key
		SecureVector<uint8_t> ck(KEY_SIZE);
		gen.Generate(ck);

		// copy key to state
		m_tsx1024State->Key[0] = IntegerTools::LeBytesTo64(ck, 0);
		m_tsx1024State->Key[1] = IntegerTools::LeBytesTo64(ck, 8);
		m_tsx1024State->Key[2] = IntegerTools::LeBytesTo64(ck, 16);
		m_tsx1024State->Key[3] = IntegerTools::LeBytesTo64(ck, 24);
		m_tsx1024State->Key[4] = IntegerTools::LeBytesTo64(ck, 32);
		m_tsx1024State->Key[5] = IntegerTools::LeBytesTo64(ck, 40);
		m_tsx1024State->Key[6] = IntegerTools::LeBytesTo64(ck, 48);
		m_tsx1024State->Key[7] = IntegerTools::LeBytesTo64(ck, 56);
		m_tsx1024State->Key[8] = IntegerTools::LeBytesTo64(ck, 64);
		m_tsx1024State->Key[9] = IntegerTools::LeBytesTo64(ck, 72);
		m_tsx1024State->Key[10] = IntegerTools::LeBytesTo64(ck, 80);
		m_tsx1024State->Key[11] = IntegerTools::LeBytesTo64(ck, 88);
		m_tsx1024State->Key[12] = IntegerTools::LeBytesTo64(ck, 96);
		m_tsx1024State->Key[13] = IntegerTools::LeBytesTo64(ck, 104);
		m_tsx1024State->Key[14] = IntegerTools::LeBytesTo64(ck, 112);
		m_tsx1024State->Key[15] = IntegerTools::LeBytesTo64(ck, 120);

		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[0];
		SecureVector<uint8_t> mack(ks.KeySize());
		gen.Generate(mack);
		// initailize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_tsx1024State->MacKey.resize(mack.size());
		SecureMove(mack, 0, m_tsx1024State->MacKey, 0, mack.size());
		m_tsx1024State->MacTag.resize(TagSize());
	}

	m_tsx1024State->IsEncryption = Encryption;
	m_tsx1024State->IsInitialized = true;
}

void TSX1024::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void TSX1024::SetAssociatedData(const std::vector<uint8_t> &Input, size_t Offset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}
	if (Length == 0)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The additional data array can not be zero sized!"), ErrorCodes::InvalidSize);
	}

	if (IsAuthenticator() == true)
	{
		std::vector<uint8_t> code(sizeof(uint32_t));
		// version 1.1a add AD and encoding to hash
		m_macAuthenticator->Update(Input, Offset, Length);
		IntegerTools::Le32ToBytes(static_cast<uint32_t>(Length), code, 0);
		m_macAuthenticator->Update(code, 0, code.size());
	}
}

void TSX1024::Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (IsEncryption() == true)
	{
		if (IsAuthenticator() == true)
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not int64_t enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<uint8_t>>(m_tsx1024State->Nonce[0]), 0, sizeof(uint64_t));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<uint8_t>>(m_tsx1024State->Nonce[1]), 0, sizeof(uint64_t));
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_tsx1024State->Counter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_tsx1024State, m_macAuthenticator);
			MemoryTools::Copy(m_tsx1024State->MacTag, 0, Output, OutOffset + Length, m_tsx1024State->MacTag.size());
		}
		else
		{
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		if (IsAuthenticator() == true)
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<uint8_t>>(m_tsx1024State->Nonce[0]), 0, sizeof(uint64_t));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<uint8_t>>(m_tsx1024State->Nonce[1]), 0, sizeof(uint64_t));
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_tsx1024State->Counter += Length;
			// finalize the mac and verify
			Finalize(m_tsx1024State, m_macAuthenticator);

			if (IntegerTools::Compare(Input, InOffset + Length, m_tsx1024State->MacTag, 0, m_tsx1024State->MacTag.size()) == false)
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void TSX1024::Finalize(std::unique_ptr<TSX1024State> &State, std::unique_ptr<IMac> &Authenticator)
{
	// customization string is mac counter + algorithm name
	IntegerTools::Le64ToBytes(State->Counter, State->Custom, 0);

	// update the authenticator
	Authenticator->Update(SecureUnlock(State->Custom), 0, State->Custom.size());

	// generate the mac code
	Authenticator->Finalize(State->MacTag, 0);
}

void TSX1024::Generate(std::unique_ptr<TSX1024State> &State, std::array<uint64_t, 2> &Counter, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(CEX_HAS_AVX512)

	const size_t AVX512BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<uint64_t, 16> ctr16;
		std::array<uint64_t, 128> tmp128;

		// process 8 blocks
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, ctr16, 0, 8);
			MemoryTools::Copy(Counter, 1, ctr16, 8, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr16, 1, 8);
			MemoryTools::Copy(Counter, 1, ctr16, 9, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr16, 2, 8);
			MemoryTools::Copy(Counter, 1, ctr16, 10, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr16, 3, 8);
			MemoryTools::Copy(Counter, 1, ctr16, 11, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr16, 4, 8);
			MemoryTools::Copy(Counter, 1, ctr16, 12, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr16, 5, 8);
			MemoryTools::Copy(Counter, 1, ctr16, 13, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr16, 6, 8);
			MemoryTools::Copy(Counter, 1, ctr16, 14, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr16, 7, 8);
			MemoryTools::Copy(Counter, 1, ctr16, 15, 8);
			IntegerTools::LeIncrementW(Counter);
			Threefish::PemuteP8x1024H(State->Key, ctr16, State->Tweak, tmp128, ROUND_COUNT);
			MemoryTools::Copy(tmp128, 0, Output, OutOffset + ctr, AVX512BLK);
			ctr += AVX512BLK;
		}
	}

#elif defined(CEX_HAS_AVX2)

	const size_t AVX2BLK = 4 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<uint64_t, 8> ctr8;
		std::array<uint64_t, 64> tmp64;

		// process 4 blocks
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, ctr8, 0, 8);
			MemoryTools::Copy(Counter, 1, ctr8, 4, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr8, 1, 8);
			MemoryTools::Copy(Counter, 1, ctr8, 5, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr8, 2, 8);
			MemoryTools::Copy(Counter, 1, ctr8, 6, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctr8, 3, 8);
			MemoryTools::Copy(Counter, 1, ctr8, 7, 8);
			IntegerTools::LeIncrementW(Counter);
			Threefish::PemuteP4x1024H(State->Key, ctr8, State->Tweak, tmp64, ROUND_COUNT);
			MemoryTools::Copy(tmp64, 0, Output, OutOffset + ctr, AVX2BLK);
			ctr += AVX2BLK;
		}
	}

#endif

	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	std::array<uint64_t, 16> tmp;

	while (ctr != ALNLEN)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP1024C(State->Key, Counter, State->Tweak, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR120P1024U(State->Key, Counter, State->Tweak, tmp);
#endif
		MemoryTools::Copy(tmp, 0, Output, OutOffset + ctr, BLOCK_SIZE);
		IntegerTools::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP1024C(State->Key, Counter, State->Tweak, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR120P1024U(State->Key, Counter, State->Tweak, tmp);
#endif
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(tmp, 0, Output, OutOffset + ctr, FNLLEN);
		IntegerTools::LeIncrementW(Counter);
	}
}

void TSX1024::Process(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	const size_t PRCLEN = Length;

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(m_tsx1024State, m_tsx1024State->Nonce, Output, OutOffset, PRCLEN);
		// output is input ^ random
		const size_t ALNLEN = PRCLEN - (PRCLEN % BLOCK_SIZE);

		if (ALNLEN != 0)
		{
			MemoryTools::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
		}

		// process the remaining bytes
		if (ALNLEN != PRCLEN)
		{
			for (size_t i = ALNLEN; i < PRCLEN; ++i)
			{
				Output[i + OutOffset] ^= Input[i + InOffset];
			}
		}
	}
	else
	{
		// parallel CTR processing
		const size_t CNKLEN = (PRCLEN / BLOCK_SIZE / m_parallelProfile.ParallelMaxDegree()) * BLOCK_SIZE;
		const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
		const size_t CTROFT = (CNKLEN / BLOCK_SIZE);
		std::vector<uint64_t> tmpCtr(NONCE_SIZE);

		ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTROFT](size_t i)
		{
			// thread level counter
			std::array<uint64_t, NONCE_SIZE> thdCtr;
			// offset counter by chunk size
			IntegerTools::LeIncreaseW(m_tsx1024State->Nonce, thdCtr, (CTROFT * i));
			const size_t STMPOS = i * CNKLEN;
			// create random at offset position
			this->Generate(m_tsx1024State, thdCtr, Output, OutOffset + STMPOS, CNKLEN);
			// xor with input at offset
			MemoryTools::XOR(Input, InOffset + STMPOS, Output, OutOffset + STMPOS, CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(uint64_t));
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpCtr, 0, m_tsx1024State->Nonce, 0, NONCE_SIZE * sizeof(uint64_t));

		// last block processing
		if (ALNLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN - ALNLEN;
			InOffset += ALNLEN;
			OutOffset += ALNLEN;

			Generate(m_tsx1024State, m_tsx1024State->Nonce, Output, OutOffset, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[OutOffset + i] ^= Input[InOffset + i];
			}
		}
	}
}

void TSX1024::Reset()
{
	m_tsx1024State->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}
}

NAMESPACE_STREAMEND
