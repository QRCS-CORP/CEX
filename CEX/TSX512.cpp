#include "TSX512.h"
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

const std::string TSX512::CLASS_NAME("TSX512");
const std::vector<byte> TSX512::OMEGA_INFO = { 0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73, 0x68, 0x50, 0x35, 0x31, 0x32, 0x52, 0x39, 0x36 };

class TSX512::TSX512State
{
public:

	std::array<ulong, 8> Key = { 0ULL };
	std::array<ulong, 2> Nonce = { 0ULL };
	std::array<ulong, 2> Tweak = { 0ULL };
	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	ulong Counter;
	bool IsAuthenticated;
	bool IsEncryption;
	bool IsInitialized;

	TSX512State(bool Authenticated)
		:
		Custom(0),
		MacKey(0),
		MacTag(0),
		Counter(0),
		IsAuthenticated(Authenticated),
		IsEncryption(false),
		IsInitialized(false)
	{
	}

	~TSX512State()
	{
		Reset();
		IsAuthenticated = false;
	}

	void Reset()
	{
		MemoryTools::Clear(Key, 0, Key.size() * sizeof(ulong));
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(ulong));
		MemoryTools::Clear(Tweak, 0, Tweak.size() * sizeof(ulong));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		IsEncryption = false;
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

TSX512::TSX512(bool Authenticate)
	:
	m_tsx512State(new TSX512State(Authenticate)),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, NONCE_SIZE * sizeof(ulong), INFO_SIZE) },
	m_macAuthenticator(nullptr),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

TSX512::~TSX512()
{
	if (m_tsx512State != nullptr)
	{
		m_tsx512State.reset(nullptr);
	}
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}

	IntegerTools::Clear(m_legalKeySizes);
}

//~~~Accessors~~~//

const StreamCiphers TSX512::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() ? 
		StreamAuthenticators::KMAC512 : 
		StreamAuthenticators::None;
	tmpn = Enumeration::StreamCipherConvert::FromDescription(StreamCiphers::TSX256, auth);

	return tmpn;
}

const bool TSX512::IsAuthenticator()
{
	return m_tsx512State->IsAuthenticated;
}

const bool TSX512::IsEncryption()
{
	return m_tsx512State->IsEncryption;
}

const bool TSX512::IsInitialized()
{
	return m_tsx512State->IsInitialized;
}

const bool TSX512::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &TSX512::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string TSX512::Name()
{
	std::string name;

	name = CLASS_NAME;

	if (IsAuthenticator())
	{
		name += std::string("-") + Enumeration::StreamAuthenticatorConvert::ToName(StreamAuthenticators::KMAC512);
	}

	return name;
}

const std::vector<byte> TSX512::Nonce()
{
	std::vector<byte> tmpn(2 * sizeof(ulong));

	IntegerTools::Le64ToBytes(m_tsx512State->Nonce[0], tmpn, 0);
	IntegerTools::Le64ToBytes(m_tsx512State->Nonce[1], tmpn, sizeof(ulong));

	return tmpn;
}

const size_t TSX512::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &TSX512::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> TSX512::Tag()
{
	return SecureUnlock(m_tsx512State->MacTag);
}

const void TSX512::Tag(SecureVector<byte> &Output)
{
	SecureCopy(m_tsx512State->MacTag, 0, Output, 0, m_tsx512State->MacTag.size());
}

const size_t TSX512::TagSize()
{
	return IsAuthenticator() ? TAG_SIZE : 0;
}

//~~~Public Functions~~~//

void TSX512::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().KeySize() != KEY_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().IVSize() != (NONCE_SIZE * sizeof(ulong)))
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
	m_tsx512State->Nonce[0] = IntegerTools::LeBytesTo64(Parameters.IV(), 0);
	m_tsx512State->Nonce[1] = IntegerTools::LeBytesTo64(Parameters.IV(), 8);

	if (Parameters.KeySizes().InfoSize() != 0)
	{
		// custom code
		m_tsx512State->Tweak[0] = IntegerTools::LeBytesTo64(Parameters.Info(), 0);
		m_tsx512State->Tweak[1] = IntegerTools::LeBytesTo64(Parameters.Info(), 8);
	}
	else
	{
		// default tweak
		m_tsx512State->Tweak[0] = IntegerTools::LeBytesTo64(OMEGA_INFO, 0);
		m_tsx512State->Tweak[1] = IntegerTools::LeBytesTo64(OMEGA_INFO, 8);
	}

	if (IsAuthenticator() == false)
	{
		m_tsx512State->Key[0] = IntegerTools::LeBytesTo64(Parameters.Key(), 0);
		m_tsx512State->Key[1] = IntegerTools::LeBytesTo64(Parameters.Key(), 8);
		m_tsx512State->Key[2] = IntegerTools::LeBytesTo64(Parameters.Key(), 16);
		m_tsx512State->Key[3] = IntegerTools::LeBytesTo64(Parameters.Key(), 24);
		m_tsx512State->Key[4] = IntegerTools::LeBytesTo64(Parameters.Key(), 32);
		m_tsx512State->Key[5] = IntegerTools::LeBytesTo64(Parameters.Key(), 40);
		m_tsx512State->Key[6] = IntegerTools::LeBytesTo64(Parameters.Key(), 48);
		m_tsx512State->Key[7] = IntegerTools::LeBytesTo64(Parameters.Key(), 56);
	}
	else
	{
		m_macAuthenticator.reset(new KMAC(Enumeration::KmacModes::KMAC512));

		// set the initial counter value
		m_tsx512State->Counter = 1;

		// create the cSHAKE customization string
		m_tsx512State->Custom.resize(sizeof(ulong) + Name().size());
		// add mac counter and algorithm name to customization string
		IntegerTools::Le64ToBytes(m_tsx512State->Counter, m_tsx512State->Custom, 0);
		MemoryTools::CopyFromObject(Name().data(), m_tsx512State->Custom, sizeof(ulong), Name().size());

		// initialize cSHAKE
		Kdf::SHAKE gen(ShakeModes::SHAKE512);
		gen.Initialize(Parameters.SecureKey(), m_tsx512State->Custom);

		// generate the new cipher key
		SecureVector<byte> ck(KEY_SIZE);
		gen.Generate(ck);

		// copy key to state
		m_tsx512State->Key[0] = IntegerTools::LeBytesTo64(ck, 0);
		m_tsx512State->Key[1] = IntegerTools::LeBytesTo64(ck, 8);
		m_tsx512State->Key[2] = IntegerTools::LeBytesTo64(ck, 16);
		m_tsx512State->Key[3] = IntegerTools::LeBytesTo64(ck, 24);
		m_tsx512State->Key[4] = IntegerTools::LeBytesTo64(ck, 32);
		m_tsx512State->Key[5] = IntegerTools::LeBytesTo64(ck, 40);
		m_tsx512State->Key[6] = IntegerTools::LeBytesTo64(ck, 48);
		m_tsx512State->Key[7] = IntegerTools::LeBytesTo64(ck, 56);

		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
		SecureVector<byte> mack(ks.KeySize());
		gen.Generate(mack);
		// initailize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_tsx512State->MacKey.resize(mack.size());
		SecureMove(mack, 0, m_tsx512State->MacKey, 0, mack.size());
		m_tsx512State->MacTag.resize(TagSize());
	}

	m_tsx512State->IsEncryption = Encryption;
	m_tsx512State->IsInitialized = true;
}

void TSX512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void TSX512::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}

	// update the authenticator
	m_macAuthenticator->Update(Input, Offset, Length);
}

void TSX512::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (IsEncryption() == true)
	{
		if (IsAuthenticator() == true)
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not long enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_tsx512State->Nonce[0]), 0, sizeof(ulong));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_tsx512State->Nonce[1]), 0, sizeof(ulong));
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_tsx512State->Counter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_tsx512State, m_macAuthenticator);
			MemoryTools::Copy(m_tsx512State->MacTag, 0, Output, OutOffset + Length, m_tsx512State->MacTag.size());
		}
		else
		{
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		if (IsAuthenticator())
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_tsx512State->Nonce[0]), 0, sizeof(ulong));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_tsx512State->Nonce[1]), 0, sizeof(ulong));
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_tsx512State->Counter += Length;
			// finalize the mac and verify
			Finalize(m_tsx512State, m_macAuthenticator);

			if (!IntegerTools::Compare(Input, InOffset + Length, m_tsx512State->MacTag, 0, m_tsx512State->MacTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void TSX512::Finalize(std::unique_ptr<TSX512State> &State, std::unique_ptr<IMac> &Authenticator)
{
	// customization string is mac counter + algorithm name
	IntegerTools::Le64ToBytes(State->Counter, State->Custom, 0);

	// update the authenticator
	Authenticator->Update(SecureUnlock(State->Custom), 0, State->Custom.size());

	// generate the mac code
	Authenticator->Finalize(State->MacTag, 0);
}

void TSX512::Generate(std::unique_ptr<TSX512State> &State, std::array<ulong, 2> &Counter, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(CEX_HAS_AVX512)

	const size_t AVX512BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<ulong, 16> ctr16;
		std::array<ulong, 64> tmp64;

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
			Threefish::PemuteP8x512H(State->Key, ctr16, State->Tweak, tmp64, ROUND_COUNT);
			MemoryTools::Copy(tmp64, 0, Output, OutOffset + ctr, AVX2BLK);
			ctr += AVX512BLK;
		}
	}

#elif defined(CEX_HAS_AVX2)

	const size_t AVX2BLK = 4 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<ulong, 8> ctr8;
		std::array<ulong, 32> tmp32;

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
			Threefish::PemuteP4x512H(State->Key, ctr8, State->Tweak, tmp32, ROUND_COUNT);
			MemoryTools::Copy(tmp32, 0, Output, OutOffset + ctr, AVX2BLK);
			ctr += AVX2BLK;
		}
	}

#endif

	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	std::array<ulong, 8> tmp;

	while (ctr != ALNLEN)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP512C(State->Key, Counter, State->Tweak, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR96P512U(State->Key, Counter, State->Tweak, tmp);
#endif
		MemoryTools::Copy(tmp, 0, Output, OutOffset + ctr, BLOCK_SIZE);
		IntegerTools::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP512C(State->Key, Counter, State->Tweak, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR96P512U(State->Key, Counter, State->Tweak, tmp);
#endif
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(tmp, 0, Output, OutOffset + ctr, FNLLEN);
		IntegerTools::LeIncrementW(Counter);
	}
}

void TSX512::Process(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t PRCLEN = Length;

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(m_tsx512State, m_tsx512State->Nonce, Output, OutOffset, PRCLEN);
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
		const size_t RNDLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
		const size_t CTROFT = (CNKLEN / BLOCK_SIZE);
		std::vector<ulong> tmpCtr(NONCE_SIZE);

		ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTROFT](size_t i)
		{
			// thread level counter
			std::array<ulong, NONCE_SIZE> thdCtr;
			// offset counter by chunk size
			IntegerTools::LeIncreaseW(m_tsx512State->Nonce, thdCtr, (CTROFT * i));
			const size_t STMPOS = i * CNKLEN;
			// create random at offset position
			this->Generate(m_tsx512State, thdCtr, Output, OutOffset + STMPOS, CNKLEN);
			// xor with input at offset
			MemoryTools::XOR(Input, InOffset + STMPOS, Output, OutOffset + STMPOS, CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(ulong));
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpCtr, 0, m_tsx512State->Nonce, 0, NONCE_SIZE * sizeof(ulong));

		// last block processing
		if (RNDLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN % RNDLEN;
			Generate(m_tsx512State, m_tsx512State->Nonce, Output, RNDLEN, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[i + OutOffset + RNDLEN] ^= Input[i + InOffset + RNDLEN];
			}
		}
	}
}

void TSX512::Reset()
{
	m_tsx512State->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}
}

NAMESPACE_STREAMEND
