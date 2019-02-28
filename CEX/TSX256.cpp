#include "TSX256.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "ParallelTools.h"
#include "SHAKE.h"
#include "SymmetricSecureKey.h"
#include "SymmetricKey.h"
#include "Threefish.h"

#if defined(__AVX2__)
#	include "ULong256.h"
#elif defined(__AVX__)
#	include "ULong128.h"
#endif

NAMESPACE_STREAM

using Utility::IntegerTools;
using Utility::MemoryTools;
using Utility::ParallelTools;
using Kdf::SHAKE;

const std::string TSX256::CLASS_NAME("TSX256");
const std::vector<byte> TSX256::OMEGA_INFO = { 0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73, 0x68, 0x50, 0x32, 0x35, 0x36, 0x52, 0x37, 0x32 };

class TSX256::TSX256State
{
public:

	std::array<ulong, 4> Key = { 0ULL };
	std::array<ulong, 2> Nonce = { 0ULL };
	std::array<ulong, 2> Tweak = { 0ULL };
	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	ulong Counter;
	bool Encryption;
	bool Initialized;

	TSX256State()
		:
		Custom(0),
		MacKey(0),
		MacTag(0),
		Counter(0),
		Encryption(false),
		Initialized(false)
	{
	}

	void Reset()
	{
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(ulong));
		MemoryTools::Clear(Key, 0, Key.size() * sizeof(ulong));
		MemoryTools::Clear(Tweak, 0, Tweak.size() * sizeof(ulong));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

TSX256::TSX256(StreamAuthenticators AuthenticatorType)
	:
	m_tsx256State(new TSX256State),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, NONCE_SIZE * sizeof(ulong), INFO_SIZE) },
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

TSX256::~TSX256()
{
	if (m_tsx256State != nullptr)
	{
		m_tsx256State->Reset();
		m_tsx256State.reset(nullptr);
	}
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}

	IntegerTools::Clear(m_legalKeySizes);
}

//~~~Accessors~~~//

const StreamCiphers TSX256::Enumeral()
{
	return StreamCiphers::TSX256;
}

const bool TSX256::IsAuthenticator()
{
	return static_cast<bool>(m_macAuthenticator != nullptr);
}

const bool TSX256::IsEncryption()
{
	return m_tsx256State->Encryption;
}

const bool TSX256::IsInitialized()
{
	return m_tsx256State->Initialized;
}

const bool TSX256::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &TSX256::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string TSX256::Name()
{
	std::string name;

	name = CLASS_NAME;

	if (IsAuthenticator())
	{
		name += std::string("-") + Enumeration::StreamAuthenticatorConvert::ToName(static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()));
	}

	return name;
}

const size_t TSX256::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &TSX256::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> TSX256::Tag()
{
	return Unlock(m_tsx256State->MacTag);
}

const void TSX256::Tag(SecureVector<byte> &Output)
{
	Copy(m_tsx256State->MacTag, 0, Output, 0, m_tsx256State->MacTag.size());
}

const size_t TSX256::TagSize()
{
	return IsAuthenticator() ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void TSX256::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().KeySize() != KEY_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().NonceSize() != (NONCE_SIZE * sizeof(ulong)))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Nonce must be 16 bytes!"), ErrorCodes::InvalidNonce);
	}
	if (Parameters.KeySizes().InfoSize() > 0 && Parameters.KeySizes().InfoSize() != INFO_SIZE)
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
	if (IsInitialized())
	{
		Reset();
	}

	// copy nonce
	m_tsx256State->Nonce[0] = IntegerTools::LeBytesTo64(Parameters.Nonce(), 0);
	m_tsx256State->Nonce[1] = IntegerTools::LeBytesTo64(Parameters.Nonce(), 8);

	if (Parameters.KeySizes().InfoSize() != 0)
	{
		// custom code
		m_tsx256State->Tweak[0] = IntegerTools::LeBytesTo64(Parameters.Info(), 0);
		m_tsx256State->Tweak[1] = IntegerTools::LeBytesTo64(Parameters.Info(), 8);
	}
	else
	{
		// default tweak
		m_tsx256State->Tweak[0] = IntegerTools::LeBytesTo64(OMEGA_INFO, 0);
		m_tsx256State->Tweak[1] = IntegerTools::LeBytesTo64(OMEGA_INFO, 8);
	}

	if (!IsAuthenticator())
	{
		m_tsx256State->Key[0] = IntegerTools::LeBytesTo64(Parameters.Key(), 0);
		m_tsx256State->Key[1] = IntegerTools::LeBytesTo64(Parameters.Key(), 8);
		m_tsx256State->Key[2] = IntegerTools::LeBytesTo64(Parameters.Key(), 16);
		m_tsx256State->Key[3] = IntegerTools::LeBytesTo64(Parameters.Key(), 24);
	}
	else
	{
		// set the initial counter value
		m_tsx256State->Counter = 1;

		// create the cSHAKE customization string
		std::string tmpn = Name();
		m_tsx256State->Custom.resize(sizeof(ulong) + tmpn.size());
		// add mac counter and algorithm name to customization string
		IntegerTools::Le64ToBytes(m_tsx256State->Counter, m_tsx256State->Custom, 0);
		MemoryTools::CopyFromObject(tmpn.data(), m_tsx256State->Custom, sizeof(ulong), tmpn.size());

		// initialize cSHAKE
		SHAKE gen(ShakeModes::SHAKE256);
		gen.Initialize(Parameters.SecureKey(), m_tsx256State->Custom);
		// generate the new cipher key
		SecureVector<byte> ck(KEY_SIZE);
		gen.Generate(ck);

		// copy key to state
		m_tsx256State->Key[0] = IntegerTools::LeBytesTo64(ck, 0);
		m_tsx256State->Key[1] = IntegerTools::LeBytesTo64(ck, 8);
		m_tsx256State->Key[2] = IntegerTools::LeBytesTo64(ck, 16);
		m_tsx256State->Key[3] = IntegerTools::LeBytesTo64(ck, 24);

		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
		SecureVector<byte> mack(ks.KeySize());
		gen.Generate(mack);
		// initailize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_tsx256State->MacKey.resize(mack.size());
		Move(mack, m_tsx256State->MacKey, 0);
		m_tsx256State->MacTag.resize(TagSize());
	}

	m_tsx256State->Encryption = Encryption;
	m_tsx256State->Initialized = true;
}

void TSX256::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void TSX256::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (!IsAuthenticator())
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}

	// update the authenticator
	m_macAuthenticator->Update(Input, Offset, Length);
}

void TSX256::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (IsEncryption())
	{
		if (IsAuthenticator())
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not long enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_tsx256State->Nonce[0]), 0, sizeof(ulong));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_tsx256State->Nonce[1]), 0, sizeof(ulong));
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_tsx256State->Counter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_tsx256State, m_macAuthenticator);
			MemoryTools::Copy(m_tsx256State->MacTag, 0, Output, OutOffset + Length, m_tsx256State->MacTag.size());
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
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_tsx256State->Nonce[0]), 0, sizeof(ulong));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_tsx256State->Nonce[1]), 0, sizeof(ulong));
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_tsx256State->Counter += Length;
			// finalize the mac and verify
			Finalize(m_tsx256State, m_macAuthenticator);

			if (!IntegerTools::Compare(Input, InOffset + Length, m_tsx256State->MacTag, 0, m_tsx256State->MacTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void TSX256::Finalize(std::unique_ptr<TSX256State> &State, std::unique_ptr<IMac> &Authenticator)
{
	// generate the mac code
	Authenticator->Finalize(State->MacTag, 0);

	// customization string is: mac counter + algorithm name
	IntegerTools::Le64ToBytes(State->Counter, State->Custom, 0);

	// extract the new mac key
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(State->MacKey, State->Custom);
	SymmetricKeySize ks = Authenticator->LegalKeySizes()[1];
	SecureVector<byte> mack(ks.KeySize());
	gen.Generate(mack);

	// reset the generator with the new key
	SymmetricKey kpm(mack);
	Authenticator->Initialize(kpm);
	// store the new key and erase the temporary key
	Move(mack, State->MacKey, 0);
}

void TSX256::Generate(std::unique_ptr<TSX256State> &State, std::array<ulong, 2> &Nonce, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(__AVX512__)

	const size_t AVX512BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<ulong, 16> ctr16;
		std::array<ulong, 32> tmp32;

		// process 8 blocks
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Nonce, 0, ctr16, 0, 8);
			MemoryTools::Copy(Nonce, 1, ctr16, 8, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr16, 1, 8);
			MemoryTools::Copy(Nonce, 1, ctr16, 9, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr16, 2, 8);
			MemoryTools::Copy(Nonce, 1, ctr16, 10, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr16, 3, 8);
			MemoryTools::Copy(Nonce, 1, ctr16, 11, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr16, 4, 8);
			MemoryTools::Copy(Nonce, 1, ctr16, 12, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr16, 5, 8);
			MemoryTools::Copy(Nonce, 1, ctr16, 13, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr16, 6, 8);
			MemoryTools::Copy(Nonce, 1, ctr16, 14, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr16, 7, 8);
			MemoryTools::Copy(Nonce, 1, ctr16, 15, 8);
			IntegerTools::LeIncrementW(Nonce);
			Threefish::PemuteP4x512H(State->Key, ctr16, State->Tweak, tmp32, ROUND_COUNT);
			MemoryTools::Copy(tmp32, 0, Output, OutOffset + ctr, AVX2BLK);
			ctr += AVX512BLK;
		}
	}

#elif defined(__AVX2__)

	const size_t AVX2BLK = 4 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<ulong, 8> ctr8;
		std::array<ulong, 16> tmp16;

		// process 4 blocks
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Nonce, 0, ctr8, 0, 8);
			MemoryTools::Copy(Nonce, 1, ctr8, 4, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr8, 1, 8);
			MemoryTools::Copy(Nonce, 1, ctr8, 5, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr8, 2, 8);
			MemoryTools::Copy(Nonce, 1, ctr8, 6, 8);
			IntegerTools::LeIncrementW(Nonce);
			MemoryTools::Copy(Nonce, 0, ctr8, 3, 8);
			MemoryTools::Copy(Nonce, 1, ctr8, 7, 8);
			IntegerTools::LeIncrementW(Nonce);
			Threefish::PemuteP4x256H(State->Key, ctr8, State->Tweak, tmp16, ROUND_COUNT);
			MemoryTools::Copy(tmp16, 0, Output, OutOffset + ctr, AVX2BLK);
			ctr += AVX2BLK;
		}
	}

#endif

	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	std::array<ulong, 4> tmp;

	while (ctr != ALNLEN)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP256C(State->Key, Nonce, State->Tweak, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR72P256U(State->Key, Nonce, State->Tweak, tmp);
#endif
		MemoryTools::Copy(tmp, 0, Output, OutOffset + ctr, BLOCK_SIZE);
		IntegerTools::LeIncrementW(Nonce);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP256C(State->Key, Nonce, State->Tweak, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR72P256U(State->Key, Nonce, State->Tweak, tmp);
#endif
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(tmp, 0, Output, OutOffset + ctr, FNLLEN);
		IntegerTools::LeIncrementW(Nonce);
	}
}

void TSX256::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t PRCLEN = Length;

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(m_tsx256State, m_tsx256State->Nonce, Output, OutOffset, PRCLEN);
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
			IntegerTools::LeIncreaseW(m_tsx256State->Nonce, thdCtr, (CTROFT * i));
			// create random at offset position
			this->Generate(m_tsx256State, thdCtr, Output, OutOffset + (i * CNKLEN), CNKLEN);
			// xor with input at offset
			MemoryTools::XOR(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(ulong));
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpCtr, 0, m_tsx256State->Nonce, 0, NONCE_SIZE * sizeof(ulong));

		// last block processing
		if (RNDLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN % RNDLEN;
			Generate(m_tsx256State, m_tsx256State->Nonce, Output, RNDLEN, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[i + OutOffset + RNDLEN] ^= Input[i + InOffset + RNDLEN];
			}
		}
	}
}

void TSX256::Reset()
{
	m_tsx256State->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}
}

NAMESPACE_STREAMEND
