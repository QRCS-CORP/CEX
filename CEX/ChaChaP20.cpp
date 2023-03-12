#include "ChaChaP20.h"
#include "ChaCha.h"
#include "IntegerTools.h"
#include "KMAC.h"
#include "MemoryTools.h"
#include "ParallelTools.h"
#include "SHAKE.h"

#if defined(CEX_HAS_AVX2)
#	include "UInt256.h"
#elif defined(CEX_HAS_AVX)
#	include "UInt128.h"
#endif

NAMESPACE_STREAM

using Tools::IntegerTools;
using Mac::KMAC;
using Enumeration::KmacModes;
using Tools::MemoryTools;
using Tools::ParallelTools;
using Kdf::SHAKE;

const std::string ChaChaP20::CLASS_NAME("ChaChaP20");
const std::vector<uint8_t> ChaChaP20::SIGMA_INFO = { 0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33, 0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B };

class ChaChaP20::CSX256State
{
public:

	std::array<uint32_t, 2> Nonce = { 0 };
	std::array<uint32_t, 14> State = { 0 };
	SecureVector<uint8_t> Custom;
	SecureVector<uint8_t> MacKey;
	SecureVector<uint8_t> MacTag;
	std::vector<SymmetricKeySize> LegalKeySizes{
			SymmetricKeySize(IK256_SIZE, NONCE_SIZE * sizeof(uint32_t), INFO_SIZE)};
	uint64_t Counter = 0;
	bool IsAuthenticated = false;
	bool IsEncryption = false;
	bool IsInitialized = false;

	CSX256State(bool Authenticate)
		:
		Custom(0),
		MacKey(0),
		MacTag(0),
		IsAuthenticated(Authenticate)
	{
	}

	CSX256State(SecureVector<uint8_t> &State)
		:
		Custom(0),
		MacKey(0),
		MacTag(0)
	{
		DeSerialize(State);
	}

	~CSX256State()
	{
		LegalKeySizes.clear();
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(uint32_t));
		MemoryTools::Clear(State, 0, State.size() * sizeof(uint32_t));
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		IsEncryption = false;
		IsInitialized = false;
		IsAuthenticated = false;
	}

	void DeSerialize(SecureVector<uint8_t> &SecureState)
	{
		size_t soff;
		uint16_t vlen;

		soff = 0;
		vlen = 0;

		vlen = static_cast<uint16_t>(State.size()) * sizeof(uint32_t);
		MemoryTools::Copy(SecureState, soff, State, 0, vlen);
		soff = vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(uint16_t));
		Custom.resize(vlen);
		soff += sizeof(uint16_t);
		MemoryTools::Copy(SecureState, soff, Custom, 0, Custom.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(uint16_t));
		MacKey.resize(vlen);
		soff += sizeof(uint16_t);
		MemoryTools::Copy(SecureState, soff, MacKey, 0, MacKey.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(uint16_t));
		MacTag.resize(vlen);
		soff += sizeof(uint16_t);
		MemoryTools::Copy(SecureState, soff, MacTag, 0, MacTag.size());
		soff += vlen;

		vlen = static_cast<uint16_t>(Nonce.size()) * sizeof(uint32_t);
		MemoryTools::Copy(SecureState, soff, Nonce, 0, vlen);
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &Counter, sizeof(uint64_t));
		soff += sizeof(uint64_t);
		MemoryTools::CopyToObject(SecureState, soff, &IsAuthenticated, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyToObject(SecureState, soff, &IsEncryption, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyToObject(SecureState, soff, &IsInitialized, sizeof(bool));
	}

	void Reset()
	{
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(uint32_t));
		MemoryTools::Clear(State, 0, State.size() * sizeof(uint32_t));
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		IsEncryption = false;
		IsInitialized = false;
	}

	SecureVector<uint8_t> Serialize()
	{
		const size_t STALEN = ((State.size() * sizeof(uint32_t)) + Custom.size() + MacKey.size() + MacTag.size() + (Nonce.size() * sizeof(uint32_t)) + sizeof(uint64_t) + (3 * sizeof(uint16_t)) + (3 * sizeof(bool)));

		size_t soff;
		uint16_t vlen;
		SecureVector<uint8_t> state(STALEN);

		soff = 0;
		vlen = static_cast<uint16_t>(State.size()) * sizeof(uint32_t);
		MemoryTools::Copy(State, 0, state, soff, vlen);
		soff += vlen;

		vlen = static_cast<uint16_t>(Custom.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(uint16_t));
		soff += sizeof(uint16_t);
		MemoryTools::Copy(Custom, 0, state, soff, Custom.size());
		soff += Custom.size();

		vlen = static_cast<uint16_t>(MacKey.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(uint16_t));
		soff += sizeof(uint16_t);
		MemoryTools::Copy(MacKey, 0, state, soff, MacKey.size());
		soff += MacKey.size();

		vlen = static_cast<uint16_t>(MacTag.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(uint16_t));
		soff += sizeof(uint16_t);
		MemoryTools::Copy(MacTag, 0, state, soff, MacTag.size());
		soff += MacTag.size();

		vlen = static_cast<uint16_t>(Nonce.size()) * sizeof(uint32_t);
		MemoryTools::Copy(Nonce, 0, state, soff, vlen);
		soff += vlen;

		MemoryTools::CopyFromObject(&Counter, state, soff, sizeof(uint64_t));
		soff += sizeof(uint64_t);
		MemoryTools::CopyFromObject(&IsAuthenticated, state, soff, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyFromObject(&IsEncryption, state, soff, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyFromObject(&IsInitialized, state, soff, sizeof(bool));

		return state;
	}
};

//~~~Constructor~~~//

ChaChaP20::ChaChaP20(bool Authenticate)
	:
	m_csx256State(new CSX256State(Authenticate)),
	m_macAuthenticator(nullptr),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

ChaChaP20::ChaChaP20(SecureVector<uint8_t> &State)
	:
	m_csx256State(State.size() >= STATE_THRESHOLD ? new CSX256State(State) :
		throw CryptoSymmetricException(std::string("ChaChaP20"), std::string("Constructor"), std::string("The State array is invalid!"), ErrorCodes::InvalidKey)),
	m_macAuthenticator(m_csx256State->IsAuthenticated == false ?
		nullptr :
		new KMAC(KmacModes::KMAC256)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
	if (m_csx256State->IsAuthenticated == true)
	{
		// initialize the mac
		SymmetricKey kpm(m_csx256State->MacKey);
		m_macAuthenticator->Initialize(kpm);
	}
}

ChaChaP20::~ChaChaP20()
{
	if (m_csx256State != nullptr)
	{
		m_csx256State.reset(nullptr);
	}

	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers ChaChaP20::Enumeral() 
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() ? StreamAuthenticators::KMAC256 : StreamAuthenticators::None;
	tmpn = Enumeration::StreamCipherConvert::FromDescription(StreamCiphers::ChaChaP20, auth);

	return tmpn;
}

const bool ChaChaP20::IsAuthenticator()
{
	return m_csx256State->IsAuthenticated;
}

const bool ChaChaP20::IsEncryption()
{
	return m_csx256State->IsEncryption;
}

const bool ChaChaP20::IsInitialized() 
{ 
	return m_csx256State->IsInitialized;
}

const bool ChaChaP20::IsParallel() 
{ 
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &ChaChaP20::LegalKeySizes()
{
	return m_csx256State->LegalKeySizes; 
}

const std::string ChaChaP20::Name()
{ 
	std::string name;

	name = CLASS_NAME;

	if (IsAuthenticator())
	{
		name += std::string("-") + Enumeration::StreamAuthenticatorConvert::ToName(StreamAuthenticators::KMAC256);
	}

	return name;
}

const std::vector<uint8_t> ChaChaP20::Nonce()
{
	std::vector<uint8_t> tmpn(2 * sizeof(uint32_t));

	IntegerTools::Le32ToBytes(m_csx256State->Nonce[0], tmpn, 0);
	IntegerTools::Le32ToBytes(m_csx256State->Nonce[1], tmpn, sizeof(uint32_t));

	return tmpn;
}

const size_t ChaChaP20::ParallelBlockSize() 
{
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &ChaChaP20::ParallelProfile() 
{
	return m_parallelProfile;
}

const std::vector<uint8_t> ChaChaP20::Tag()
{
	if (m_csx256State->MacTag.size() == 0 || IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(std::string("ChaChaP20"), std::string("Tag"), std::string("The cipher is not initialized for authentication or has not run!"), ErrorCodes::NotInitialized);
	}

	return SecureUnlock(m_csx256State->MacTag);
}

const void ChaChaP20::Tag(SecureVector<uint8_t> &Output)
{
	if (m_csx256State->MacTag.size() == 0 || IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(std::string("ChaChaP20"), std::string("Tag"), std::string("The cipher is not initialized for authentication or has not run!"), ErrorCodes::NotInitialized);
	}

	SecureCopy(m_csx256State->MacTag, 0, Output, 0, m_csx256State->MacTag.size());
}

const size_t ChaChaP20::TagSize()
{
	return IsAuthenticator() ? TAG_SIZE : 0;
}

//~~~Public Functions~~~//

void ChaChaP20::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().KeySize() != IK256_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().IVSize() != NONCE_SIZE * sizeof(uint32_t))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Nonce must be 8 bytes!"), ErrorCodes::InvalidNonce);
	}
	if (Parameters.KeySizes().InfoSize() > 0 && Parameters.KeySizes().InfoSize() != INFO_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The distribution code must be no larger than LegalKeySizes info size!"), ErrorCodes::InvalidInfo);
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

	m_csx256State->Custom.resize(INFO_SIZE);

	if (Parameters.KeySizes().InfoSize() != 0)
	{
		// custom code
		MemoryTools::Copy(Parameters.Info(), 0, m_csx256State->Custom, 0, IntegerTools::Min(Parameters.KeySizes().InfoSize(), m_csx256State->Custom.size()));
	}
	else
	{
		// standard
		MemoryTools::Copy(SIGMA_INFO, 0, m_csx256State->Custom, 0, SIGMA_INFO.size());
	}

	if (IsAuthenticator() == false)
	{
		// add key and nonce to state
		Load(Parameters.SecureKey(), Parameters.SecureIV(), m_csx256State->Custom);
	}
	else
	{
		m_macAuthenticator.reset(new KMAC(Enumeration::KmacModes::KMAC256));

		// store algorithm name
		std::string tmpn = Name();
		SecureVector<uint8_t> name(tmpn.size());
		MemoryTools::CopyFromObject(Name().data(), name, 0, name.size());

		// initialize cSHAKE
		SHAKE gen(ShakeModes::SHAKE256);
		// not using customization parameter
		SecureVector<uint8_t> zero(0);
		gen.Initialize(Parameters.SecureKey(), zero, name);

		// generate the new cipher key
		SecureVector<uint8_t> cprk(IK256_SIZE);
		gen.Generate(cprk);

		// load the ciphers state
		Load(cprk, Parameters.SecureIV(), m_csx256State->Custom);

		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[0];
		SecureVector<uint8_t> mack(ks.KeySize());
		gen.Generate(mack);

		// initialize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		m_csx256State->MacTag.resize(TagSize());

		// store mac key for serializaztion
		m_csx256State->MacKey.resize(mack.size());
		SecureMove(mack, m_csx256State->MacKey, 0);
	}

	m_csx256State->IsEncryption = Encryption;
	m_csx256State->IsInitialized = true;
}

void ChaChaP20::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

SecureVector<uint8_t> ChaChaP20::Serialize()
{
	SecureVector<uint8_t> tmps = m_csx256State->Serialize();

	return tmps;
}

void ChaChaP20::SetAssociatedData(const std::vector<uint8_t> &Input, size_t Offset, size_t Length)
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

void ChaChaP20::Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
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
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<uint8_t>>(m_csx256State->Nonce[0]), 0, sizeof(uint32_t));
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<uint8_t>>(m_csx256State->Nonce[1]), 0, sizeof(uint32_t));
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_csx256State->Counter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_csx256State, m_macAuthenticator);
			MemoryTools::Copy(m_csx256State->MacTag, 0, Output, OutOffset + Length, m_csx256State->MacTag.size());
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
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<uint8_t>>(m_csx256State->Nonce[0]), 0, sizeof(uint32_t));
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<uint8_t>>(m_csx256State->Nonce[1]), 0, sizeof(uint32_t));
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_csx256State->Counter += Length;
			// finalize the mac and verify
			Finalize(m_csx256State, m_macAuthenticator);

			if (!IntegerTools::Compare(Input, InOffset + Length, m_csx256State->MacTag, 0, m_csx256State->MacTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void ChaChaP20::Finalize(std::unique_ptr<CSX256State> &State, std::unique_ptr<IMac> &Authenticator)
{
	std::vector<uint8_t> cust(sizeof(uint64_t));

	// cap input with mac bytes counter
	IntegerTools::Le64ToBytes(State->Counter, cust, 0);

	// update the authenticator
	Authenticator->Update(cust, 0, cust.size());

	// generate the mac code
	Authenticator->Finalize(State->MacTag, 0);
}

void ChaChaP20::Generate(std::unique_ptr<CSX256State> &State, std::array<uint32_t, 2> &Counter, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(CEX_HAS_AVX512)

	const size_t AVX512BLK = 16 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<uint32_t, 32> tmpc = { 0 };

		// process 8 blocks (uses avx if available)
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 16, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 1, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 17, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 2, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 18, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 3, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 19, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 4, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 20, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 5, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 21, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 6, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 22, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 7, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 23, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 8, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 24, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 9, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 25, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 10, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 26, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 11, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 27, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 12, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 28, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 13, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 29, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 14, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 30, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 15, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 31, 4);
			IntegerTools::LeIncrementW(Counter);
			ChaCha::PermuteP16x512H(Output, OutOffset + ctr, tmpc, State->State, ROUND_COUNT);
			ctr += AVX512BLK;
		}
	}
#elif defined(CEX_HAS_AVX2)
	const size_t AVX2BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<uint32_t, 16> tmpc = { 0 };

		// process 8 blocks (uses avx if available)
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 8, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 1, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 9, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 2, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 10, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 3, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 11, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 4, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 12, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 5, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 13, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 6, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 14, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 7, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 15, 4);
			IntegerTools::LeIncrementW(Counter);
			ChaCha::PermuteP8x512H(Output, OutOffset + ctr, tmpc, State->State, ROUND_COUNT);
			ctr += AVX2BLK;
		}
	}
#elif defined(CEX_HAS_AVX)
	const size_t AVXBLK = 4 * BLOCK_SIZE;

	if (Length >= AVXBLK)
	{
		const size_t SEGALN = Length - (Length % AVXBLK);
		std::array<uint32_t, 8> tmpc = { 0 };

		// process 4 blocks (uses sse intrinsics if available)
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 4, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 1, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 5, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 2, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 6, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 3, 4);
			MemoryTools::Copy(Counter, 1, tmpc, 7, 4);
			IntegerTools::LeIncrementW(Counter);
			ChaCha::PermuteP4x512H(Output, OutOffset + ctr, tmpc, State->State, ROUND_COUNT);
			ctr += AVXBLK;
		}
	}
#endif

	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);

	while (ctr != ALNLEN)
	{
#if defined(CEX_CIPHER_COMPACT)
		ChaCha::PermuteP512C(Output, OutOffset + ctr, Counter, State->State, ROUND_COUNT);
#else
		ChaCha::PermuteR20P512U(Output, OutOffset + ctr, Counter, State->State);
#endif
		IntegerTools::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<uint8_t> otp(BLOCK_SIZE, 0);
#if defined(CEX_CIPHER_COMPACT)
		ChaCha::PermuteP512C(otp, 0, Counter, State->State, ROUND_COUNT);
#else
		ChaCha::PermuteR20P512U(otp, 0, Counter, State->State);
#endif
		IntegerTools::LeIncrementW(Counter);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
	}
}

void ChaChaP20::Load(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &Nonce, const SecureVector<uint8_t> &Code)
{
	m_csx256State->State[0] = IntegerTools::LeBytesTo32(Code, 0);
	m_csx256State->State[1] = IntegerTools::LeBytesTo32(Code, 4);
	m_csx256State->State[2] = IntegerTools::LeBytesTo32(Code, 8);
	m_csx256State->State[3] = IntegerTools::LeBytesTo32(Code, 12);
	m_csx256State->State[4] = IntegerTools::LeBytesTo32(Key, 0);
	m_csx256State->State[5] = IntegerTools::LeBytesTo32(Key, 4);
	m_csx256State->State[6] = IntegerTools::LeBytesTo32(Key, 8);
	m_csx256State->State[7] = IntegerTools::LeBytesTo32(Key, 12);
	m_csx256State->State[8] = IntegerTools::LeBytesTo32(Key, 16);
	m_csx256State->State[9] = IntegerTools::LeBytesTo32(Key, 20);
	m_csx256State->State[10] = IntegerTools::LeBytesTo32(Key, 24);
	m_csx256State->State[11] = IntegerTools::LeBytesTo32(Key, 28);
	m_csx256State->State[12] = IntegerTools::LeBytesTo32(Nonce, 0);
	m_csx256State->State[13] = IntegerTools::LeBytesTo32(Nonce, 4);
}

void ChaChaP20::Process(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	const size_t PRCLEN = (Length >= Input.size() - InOffset) && Length >= Output.size() - OutOffset ? IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) : Length;

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(m_csx256State, m_csx256State->Nonce, Output, OutOffset, PRCLEN);
		// output is input xor random
		const size_t ALNLEN = PRCLEN - (PRCLEN % BLOCK_SIZE);

		if (ALNLEN != 0)
		{
			MemoryTools::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
		}

		// get the remaining bytes
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
		const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
		std::vector<uint32_t> tmpCtr(NONCE_SIZE);

		ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			std::array<uint32_t, 2> thdCtr = { 0 };
			// offset counter by chunk size / block size
			IntegerTools::LeIncreaseW(m_csx256State->Nonce, thdCtr, CTRLEN * i);
			const size_t STMPOS = i * CNKLEN;
			// create random at offset position
			this->Generate(m_csx256State, thdCtr, Output, OutOffset + STMPOS, CNKLEN);
			// xor with input at offset
			MemoryTools::XOR(Input, InOffset + STMPOS, Output, OutOffset + STMPOS, CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(uint32_t));
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpCtr, 0, m_csx256State->Nonce, 0, NONCE_SIZE * sizeof(uint32_t));

		// last block processing
		if (RNDLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN % RNDLEN;
			Generate(m_csx256State, m_csx256State->Nonce, Output, RNDLEN, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[i + OutOffset + RNDLEN] ^= static_cast<uint8_t>(Input[i + InOffset + RNDLEN]);
			}
		}
	}
}

void ChaChaP20::Reset()
{
	m_csx256State->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}
}

NAMESPACE_STREAMEND
