#include "CSX512.h"
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

class CSX512::CSX512State
{
public:

	std::array<uint64_t, 2> Nonce = { 0 };
	std::array<uint64_t, 14> State = { 0 };
	SecureVector<uint8_t> Custom;
	SecureVector<uint8_t> MacKey;
	SecureVector<uint8_t> MacTag;
	std::vector<SymmetricKeySize> LegalKeySizes{
			SymmetricKeySize(IK512_SIZE, NONCE_SIZE * sizeof(uint64_t), INFO_SIZE)};
	uint64_t Counter = 0;
	bool IsAuthenticated = false;
	bool IsEncryption = false;
	bool IsInitialized = false;

	CSX512State(bool Authenticate)
		:
		Custom(0),
		MacKey(0),
		MacTag(0),
		IsAuthenticated(Authenticate)
	{
	}

	CSX512State(SecureVector<uint8_t> &State)
	{
		DeSerialize(State);
	}

	~CSX512State()
	{
		LegalKeySizes.clear();
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(uint64_t));
		MemoryTools::Clear(State, 0, State.size() * sizeof(uint64_t));
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		IsAuthenticated = false;
		IsEncryption = false;
		IsInitialized = false;
	}

	void DeSerialize(SecureVector<uint8_t> &SecureState)
	{
		size_t soff;
		uint16_t vlen;

		vlen = 0;
		soff = 0;

		vlen = static_cast<uint16_t>(State.size()) * sizeof(uint64_t);
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

		vlen = static_cast<uint16_t>(Nonce.size()) * sizeof(uint64_t);
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
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(uint64_t));
		MemoryTools::Clear(State, 0, State.size() * sizeof(uint64_t));
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		IsEncryption = false;
		IsInitialized = false;
	}

	SecureVector<uint8_t> Serialize()
	{
		const size_t STALEN = ((State.size() * sizeof(uint64_t)) + Custom.size() + MacKey.size() + MacTag.size() + (Nonce.size() * sizeof(uint64_t)) + sizeof(uint64_t) + (3 * sizeof(uint16_t)) + (3 * sizeof(bool)));

		size_t soff;
		uint16_t vlen;
		SecureVector<uint8_t> state(STALEN);

		soff = 0;
		vlen = static_cast<uint16_t>(State.size()) * sizeof(uint64_t);
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

		vlen = static_cast<uint16_t>(Nonce.size()) * sizeof(uint64_t);
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

const std::string CSX512::CLASS_NAME("CSX512");
const std::vector<uint8_t> CSX512::SIGMA_INFO = { 0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x20, 0x4B, 0x4D, 0x41, 0x43, 0x20, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6E, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x76, 0x65, 0x72, 0x2E, 0x20, 
	0x31, 0x63, 0x20, 0x43, 0x45, 0x58, 0x2B, 0x2B, 0x20, 0x6C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79 };

//~~~Constructor~~~//

CSX512::CSX512(bool Authenticate)
	:
	m_csx512State(new CSX512State(Authenticate)),
	m_macAuthenticator(nullptr),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

CSX512::CSX512(SecureVector<uint8_t> &State)
	:
	m_csx512State(State.size() >= STATE_THRESHOLD ? new CSX512State(State) :
		throw CryptoSymmetricException(std::string("CSX512"), std::string("Constructor"), std::string("The State array is invalid!"), ErrorCodes::InvalidKey)),
	m_macAuthenticator(m_csx512State->IsAuthenticated == false ?
		nullptr :
		new KMAC(KmacModes::KMAC512)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
	if (m_csx512State->IsAuthenticated == true)
	{
		// initialize the mac
		SymmetricKey kpm(m_csx512State->MacKey);
		m_macAuthenticator->Initialize(kpm);
	}
}

CSX512::~CSX512()
{
	if (m_csx512State != nullptr)
	{
		m_csx512State.reset(nullptr);
	}
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers CSX512::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() ? StreamAuthenticators::KMAC512 : StreamAuthenticators::None;
	tmpn = Enumeration::StreamCipherConvert::FromDescription(StreamCiphers::CSX512, auth);

	return tmpn;
}

const bool CSX512::IsAuthenticator()
{
	return m_csx512State->IsAuthenticated;
}

const bool CSX512::IsEncryption()
{
	return m_csx512State->IsEncryption;
}

const bool CSX512::IsInitialized()
{
	return m_csx512State->IsInitialized;
}

const bool CSX512::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &CSX512::LegalKeySizes()
{
	return m_csx512State->LegalKeySizes;
}

const std::string CSX512::Name()
{
	std::string name = CLASS_NAME;

	if (IsAuthenticator())
	{
		name += std::string("-") + Enumeration::StreamAuthenticatorConvert::ToName(StreamAuthenticators::KMAC512);
	}

	return name;
}

const std::vector<uint8_t> CSX512::Nonce()
{
	std::vector<uint8_t> tmpn(2 * sizeof(uint64_t));

	IntegerTools::Le64ToBytes(m_csx512State->Nonce[0], tmpn, 0);
	IntegerTools::Le64ToBytes(m_csx512State->Nonce[1], tmpn, sizeof(uint64_t));

	return tmpn;
}

const size_t CSX512::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &CSX512::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<uint8_t> CSX512::Tag()
{
	if (m_csx512State->MacTag.size() == 0 || IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(std::string("CSX512"), std::string("Tag"), std::string("The cipher is not initialized for authentication or has not run!"), ErrorCodes::NotInitialized);
	}

	return SecureUnlock(m_csx512State->MacTag);
}

const void CSX512::Tag(SecureVector<uint8_t> &Output)
{
	if (m_csx512State->MacTag.size() == 0 || IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(std::string("CSX512"), std::string("Tag"), std::string("The cipher is not initialized for authentication or has not run!"), ErrorCodes::NotInitialized);
	}

	SecureCopy(m_csx512State->MacTag, 0, Output, 0, m_csx512State->MacTag.size());
}

const size_t CSX512::TagSize()
{
	return IsAuthenticator() ? TAG_SIZE : 0;
}

//~~~Public Functions~~~//

void CSX512::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().KeySize() != IK512_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().IVSize() != NONCE_SIZE * sizeof(uint64_t))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid nonce size; an 16-uint8_t nonce is required with CSX512!"), ErrorCodes::InvalidNonce);
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

	m_csx512State->Custom.resize(INFO_SIZE);

	if (Parameters.KeySizes().InfoSize() != 0)
	{
		// custom code
		MemoryTools::Copy(Parameters.SecureInfo(), 0, m_csx512State->Custom, 0, IntegerTools::Min(Parameters.KeySizes().InfoSize(), m_csx512State->Custom.size()));
	}
	else
	{ 
		// standard
		MemoryTools::Copy(SIGMA_INFO, 0, m_csx512State->Custom, 0, SIGMA_INFO.size());
	}

	if (IsAuthenticator() == false)
	{
		// add key and nonce to state
		Load(Parameters.SecureKey(), Parameters.SecureIV(), m_csx512State->Custom);
	}
	else
	{
		m_macAuthenticator.reset(new KMAC(Enumeration::KmacModes::KMAC512));

		// store algorithm name
		std::string tmpn = Name();
		SecureVector<uint8_t> name(tmpn.size());
		MemoryTools::CopyFromObject(Name().data(), name, 0, name.size());

		// initialize cSHAKE
		Kdf::SHAKE gen(ShakeModes::SHAKE512);
		// not using customization parameter
		SecureVector<uint8_t> zero(0);
		gen.Initialize(Parameters.SecureKey(), zero, name);

		// generate the new cipher key
		SecureVector<uint8_t> cprk(IK512_SIZE);
		gen.Generate(cprk);

		// load the ciphers state
		Load(cprk, Parameters.SecureIV(), m_csx512State->Custom);

		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[0];
		SecureVector<uint8_t> mack(ks.KeySize());
		gen.Generate(mack);

		// initialize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		m_csx512State->MacTag.resize(TagSize());

		// store mac key for serializaztion
		m_csx512State->MacKey.resize(mack.size());
		SecureMove(mack, m_csx512State->MacKey, 0);
	}

	m_csx512State->IsEncryption = Encryption;
	m_csx512State->IsInitialized = true;
}

void CSX512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

SecureVector<uint8_t> CSX512::Serialize()
{
	SecureVector<uint8_t> tmps = m_csx512State->Serialize();

	return tmps;
}

void CSX512::SetAssociatedData(const std::vector<uint8_t> &Input, size_t Offset, size_t Length)
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

void CSX512::Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (IsEncryption() == true)
	{
		if (IsAuthenticator() == true)
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not int64_t enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce//506097522914230528 1084818905618843912
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<uint8_t>>(m_csx512State->Nonce[0]), 0, sizeof(uint64_t));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<uint8_t>>(m_csx512State->Nonce[1]), 0, sizeof(uint64_t));
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_csx512State->Counter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_csx512State, m_macAuthenticator);
			MemoryTools::Copy(m_csx512State->MacTag, 0, Output, OutOffset + Length, m_csx512State->MacTag.size());
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
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<uint8_t>>(m_csx512State->Nonce[0]), 0, sizeof(uint64_t));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<uint8_t>>(m_csx512State->Nonce[1]), 0, sizeof(uint64_t));
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_csx512State->Counter += Length;
			// finalize the mac and verify
			Finalize(m_csx512State, m_macAuthenticator);

			if (IntegerTools::Compare(Input, InOffset + Length, m_csx512State->MacTag, 0, m_csx512State->MacTag.size()) == false)
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void CSX512::Finalize(std::unique_ptr<CSX512State> &State, std::unique_ptr<IMac> &Authenticator)
{
	std::vector<uint8_t> cust(sizeof(uint64_t));

	// cap input with mac bytes counter
	IntegerTools::Le64ToBytes(State->Counter, cust, 0);

	// update the authenticator
	Authenticator->Update(cust, 0, cust.size());

	// generate the mac code
	Authenticator->Finalize(State->MacTag, 0);
}

void CSX512::Generate(std::unique_ptr<CSX512State> &State, std::vector<uint8_t> &Output, size_t OutOffset, std::array<uint64_t, 2> &Counter, size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(CEX_HAS_AVX512)

	const size_t AVX512BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<uint64_t, 16> tmpc = { 0 };

		// process 8 blocks (uses avx if available)
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 8, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 1, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 9, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 2, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 10, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 3, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 11, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 4, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 12, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 5, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 13, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 6, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 14, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 7, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 15, 8);
			IntegerTools::LeIncrementW(Counter);
			ChaCha::PermuteP8x1024H(Output, OutOffset + ctr, tmpc, State->State, ROUND_COUNT);
			ctr += AVX512BLK;
		}
	}

#elif defined(CEX_HAS_AVX2)

	const size_t AVX2BLK = 4 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<uint64_t, 8> tmpc = { 0 };

		// process 8 blocks (uses avx if available)
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 4, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 1, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 5, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 2, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 6, 8);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, tmpc, 3, 8);
			MemoryTools::Copy(Counter, 1, tmpc, 7, 8);
			IntegerTools::LeIncrementW(Counter);
			ChaCha::PermuteP4x1024H(Output, OutOffset + ctr, tmpc, State->State, ROUND_COUNT);
			ctr += AVX2BLK;
		}
	}

#endif

	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);

	while (ctr != ALNLEN)
	{
		ChaCha::PermuteP1024C(Output, OutOffset + ctr, Counter, State->State, ROUND_COUNT);
		IntegerTools::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<uint8_t> otp(BLOCK_SIZE, 0);
		ChaCha::PermuteP1024C(otp, 0, Counter, State->State, ROUND_COUNT);
		IntegerTools::LeIncrementW(Counter);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
	}
}

void CSX512::Load(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &Nonce, const SecureVector<uint8_t> &Code)
{
#if defined(CEX_IS_LITTLE_ENDIAN)
	MemoryTools::Copy(Key, 0, m_csx512State->State, 0, Key.size());
	MemoryTools::Copy(Code, 0, m_csx512State->State, Key.size() / sizeof(uint64_t), Code.size());
	MemoryTools::Copy(Nonce, 0, m_csx512State->Nonce, 0, Nonce.size());
#else
	m_csx512State->State[0] = IntegerTools::LeBytesTo64(Key, 0);
	m_csx512State->State[1] = IntegerTools::LeBytesTo64(Key, 8);
	m_csx512State->State[2] = IntegerTools::LeBytesTo64(Key, 16);
	m_csx512State->State[3] = IntegerTools::LeBytesTo64(Key, 24);
	m_csx512State->State[4] = IntegerTools::LeBytesTo64(Key, 32);
	m_csx512State->State[5] = IntegerTools::LeBytesTo64(Key, 40);
	m_csx512State->State[6] = IntegerTools::LeBytesTo64(Key, 48);
	m_csx512State->State[7] = IntegerTools::LeBytesTo64(Key, 56);
	m_csx512State->State[8] = IntegerTools::LeBytesTo64(Code, 0);
	m_csx512State->State[9] = IntegerTools::LeBytesTo64(Code, 8);
	m_csx512State->State[10] = IntegerTools::LeBytesTo64(Code, 16);
	m_csx512State->State[11] = IntegerTools::LeBytesTo64(Code, 24);
	m_csx512State->State[12] = IntegerTools::LeBytesTo64(Code, 32);
	m_csx512State->State[13] = IntegerTools::LeBytesTo64(Code, 40);
	m_csx512State->Nonce[0] = IntegerTools::LeBytesTo64(Nonce, 0);
	m_csx512State->Nonce[1] = IntegerTools::LeBytesTo64(Nonce, 8);

#endif
}

void CSX512::Process(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	const size_t PRCLEN = (Length >= Input.size() - InOffset) && Length >= Output.size() - OutOffset ? IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) : Length;

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(m_csx512State, Output, OutOffset, m_csx512State->Nonce, PRCLEN);
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
		// parallel CTR processing //
		const size_t CNKLEN = (PRCLEN / BLOCK_SIZE / m_parallelProfile.ParallelMaxDegree()) * BLOCK_SIZE;
		const size_t RNDLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
		const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
		std::vector<uint64_t> tmpCtr(NONCE_SIZE);

		ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			std::array<uint64_t, 2> thdCtr = { 0 };
			// offset counter by chunk size / block size
			IntegerTools::LeIncreaseW(m_csx512State->Nonce, thdCtr, CTRLEN * i);
			const size_t STMPOS = i * CNKLEN;
			// create random at offset position
			this->Generate(m_csx512State, Output, OutOffset + STMPOS, thdCtr, CNKLEN);
			// xor with input at offset
			MemoryTools::XOR(Input, InOffset + STMPOS, Output, OutOffset + STMPOS, CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(uint64_t));
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpCtr, 0, m_csx512State->Nonce, 0, NONCE_SIZE * sizeof(uint64_t));

		// last block processing
		if (RNDLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN % RNDLEN;
			Generate(m_csx512State, Output, RNDLEN, m_csx512State->Nonce, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[i + OutOffset + RNDLEN] ^= static_cast<uint8_t>(Input[i + InOffset + RNDLEN]);
			}
		}
	}
}

void CSX512::Reset()
{
	m_csx512State->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}
}

NAMESPACE_STREAMEND
