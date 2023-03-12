#include "RCS.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "KMAC.h"
#include "MemoryTools.h"
#include "Rijndael.h"
#include "SHAKE.h"
#include "StreamAuthenticators.h"

NAMESPACE_STREAM

using namespace Cipher::Block::RijndaelBase;
using Tools::IntegerTools;
using Mac::KMAC;
using Enumeration::KmacModes;
using Tools::MemoryTools;
using Tools::ParallelTools;
using Enumeration::ShakeModes;
using Enumeration::StreamAuthenticators;
using Enumeration::StreamCipherConvert;

#if defined(CEX_HAS_AVX)
#	if defined(CEX_HAS_AVX512)
	const __m512i RCS::NI512K0 = _mm512_set_epi64(17361641481138401520, 17361641481138401520, 8102099357864587376, 8102099357864587376,
		17361641481138401520, 17361641481138401520, 8102099357864587376, 8102099357864587376);
	const __m512i RCS::NI512K1 = _mm512_set_epi64(8102099357864587376, 8102099357864587376, 17361641481138401520, 17361641481138401520,
		8102099357864587376, 8102099357864587376, 17361641481138401520, 17361641481138401520);
#	endif
#	if defined(CEX_EXTENDED_AESNI)
	const __m256i RCS::NI256K0 = _mm256_set_epi64x(17361641481138401520, 17361641481138401520, 8102099357864587376, 8102099357864587376);
	const __m256i RCS::NI256K1 = _mm256_set_epi64x(8102099357864587376, 8102099357864587376, 17361641481138401520, 17361641481138401520);
#	else
	const __m128i RCS::NIBMASK = _mm_set_epi32(0x80000000UL, 0x80800000UL, 0x80800000UL, 0x80808000UL);
	const __m128i RCS::NISMASK = _mm_setr_epi8(0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3);
#	endif
#endif

class RCS::RcsState
{
public:

#if defined(CEX_HAS_AVX)
#	if defined(CEX_EXTENDED_AESNI)
	std::vector<__m256i> RoundKeys;
#	else
	std::vector<__m128i> RoundKeys;
#	endif
#else
	SecureVector<uint32_t> RoundKeys;
#endif

	SecureVector<uint8_t> Custom;
	SecureVector<uint8_t> MacKey;
	SecureVector<uint8_t> MacTag;
	SecureVector<uint8_t> Name;
	std::vector<SymmetricKeySize> LegalKeySizes{
			SymmetricKeySize(IK256_SIZE, BLOCK_SIZE, INFO_SIZE),
			SymmetricKeySize(IK512_SIZE, BLOCK_SIZE, INFO_SIZE)};
	std::vector<uint8_t> Nonce;
	uint64_t Counter = 0;
	uint32_t Rounds = 0;
	KmacModes Authenticator = KmacModes::None;
	ShakeModes Mode = ShakeModes::None;
	bool IsAuthenticated = false;
	bool IsEncryption = false;
	bool IsInitialized = false;

	RcsState(bool Authenticate)
		:
		RoundKeys(0),
		Custom(0),
		MacKey(0),
		MacTag(0),
		Name(0),
		Nonce(BLOCK_SIZE, 0x00),
		IsAuthenticated(Authenticate)
	{
	}

	RcsState(SecureVector<uint8_t> &State)
	{
		DeSerialize(State);
	}

	~RcsState()
	{
		LegalKeySizes.clear();
#if defined(CEX_HAS_AVX)
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(__m128i));
#else
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint32_t));
#endif
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		Counter = 0;
		Rounds = 0;
		Authenticator = KmacModes::None;
		Mode = ShakeModes::None;
		IsAuthenticated = false;
		IsEncryption = false;
		IsInitialized = false;
	}

	void DeSerialize(SecureVector<uint8_t> &SecureState)
	{
		size_t soff;
		uint16_t vlen; 

		soff = 0;
		vlen = 0;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(uint16_t));
#if defined(CEX_HAS_AVX)
		RoundKeys.resize(vlen / sizeof(__m128i));
#else
		RoundKeys.resize(vlen / sizeof(uint32_t));
#endif
		soff += sizeof(uint16_t);
		MemoryTools::Copy(SecureState, soff, RoundKeys, 0, vlen);
		soff += vlen;

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

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(uint16_t));
		Name.resize(vlen);
		soff += sizeof(uint16_t);
		MemoryTools::Copy(SecureState, soff, Name, 0, Name.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(uint16_t));
		Nonce.resize(vlen);
		soff += sizeof(uint16_t);
		MemoryTools::Copy(SecureState, soff, Nonce, 0, Nonce.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &Counter, sizeof(uint64_t));
		soff += sizeof(uint64_t);
		MemoryTools::CopyToObject(SecureState, soff, &Rounds, sizeof(uint32_t));
		soff += sizeof(uint32_t);

		MemoryTools::CopyToObject(SecureState, soff, &Authenticator, sizeof(KmacModes));
		soff += sizeof(KmacModes);
		MemoryTools::CopyToObject(SecureState, soff, &Mode, sizeof(ShakeModes));
		soff += sizeof(ShakeModes);

		MemoryTools::CopyToObject(SecureState, soff, &IsAuthenticated, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyToObject(SecureState, soff, &IsEncryption, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyToObject(SecureState, soff, &IsInitialized, sizeof(bool));
	}

	void Reset()
	{
#if defined(CEX_HAS_AVX)
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(__m128i));
#else
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint32_t));
#endif
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		Counter = 0;
		Rounds = 0;
		IsEncryption = false;
		IsInitialized = false;
	}

	SecureVector<uint8_t> Serialize()
	{
#if defined(CEX_HAS_AVX)
		const size_t RKMSZE = sizeof(__m128i);
#else
		const size_t RKMSZE = sizeof(uint32_t);
#endif
		const size_t STALEN = (RoundKeys.size() * RKMSZE) + Custom.size() + MacKey.size() + MacTag.size() + Name.size() + 
			Nonce.size() + sizeof(Counter) + sizeof(Rounds) + sizeof(Authenticator) + sizeof(Mode) + (3 * sizeof(bool)) + (7 * sizeof(uint16_t));

		size_t soff;
		uint16_t vlen;
		SecureVector<uint8_t> state(STALEN);

		soff = 0;
		vlen = static_cast<uint16_t>(RoundKeys.size() * RKMSZE);
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(uint16_t));
		soff += sizeof(uint16_t);
		MemoryTools::Copy(RoundKeys, 0, state, soff, static_cast<size_t>(vlen));
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

		vlen = static_cast<uint16_t>(Name.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(uint16_t));
		soff += sizeof(uint16_t);
		MemoryTools::Copy(Name, 0, state, soff, Name.size());
		soff += Name.size();

		vlen = static_cast<uint16_t>(Nonce.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(uint16_t));
		soff += sizeof(uint16_t);
		MemoryTools::Copy(Nonce, 0, state, soff, Nonce.size());
		soff += Nonce.size();

		MemoryTools::CopyFromObject(&Counter, state, soff, sizeof(uint64_t));
		soff += sizeof(uint64_t);
		MemoryTools::CopyFromObject(&Rounds, state, soff, sizeof(uint32_t));
		soff += sizeof(uint32_t);

		MemoryTools::CopyFromObject(&Authenticator, state, soff, sizeof(KmacModes));
		soff += sizeof(KmacModes);
		MemoryTools::CopyFromObject(&Mode, state, soff, sizeof(ShakeModes));
		soff += sizeof(ShakeModes);

		MemoryTools::CopyFromObject(&IsAuthenticated, state, soff, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyFromObject(&IsEncryption, state, soff, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyFromObject(&IsInitialized, state, soff, sizeof(bool));

		return state;
	}
};

//~~~Constructor~~~//

RCS::RCS(bool Authenticate)
	:
	m_rcsState(new RcsState(Authenticate)),
	m_macAuthenticator(nullptr),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

RCS::RCS(SecureVector<uint8_t> &State)
	:
	m_rcsState(State.size() > STATE_THRESHOLD ? new RcsState(State) :
		throw CryptoSymmetricException(std::string("RCS"), std::string("Constructor"), std::string("The State array is invalid!"), ErrorCodes::InvalidKey)),
	m_macAuthenticator(m_rcsState->Authenticator == KmacModes::None ? 
		nullptr :
		new KMAC(m_rcsState->Authenticator)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
	if (m_rcsState->Authenticator != KmacModes::None)
	{
		// initialize the mac
		SymmetricKey kpm(m_rcsState->MacKey);
		m_macAuthenticator->Initialize(kpm);
	}
}

RCS::~RCS()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers RCS::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() && m_macAuthenticator != nullptr ?
		static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()) : 
		StreamAuthenticators::None;

	tmpn = StreamCipherConvert::FromDescription(StreamCiphers::RCS, auth);

	return tmpn;
}

const bool RCS::IsAuthenticator()
{
	return m_rcsState->IsAuthenticated;
}

const bool RCS::IsEncryption()
{
	return m_rcsState->IsEncryption;
}

const bool RCS::IsInitialized()
{
	return m_rcsState->IsInitialized;
}

const bool RCS::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &RCS::LegalKeySizes()
{
	return m_rcsState->LegalKeySizes;
}

const std::string RCS::Name()
{
	std::string name;

	name = StreamCipherConvert::ToName(Enumeral());

	return name;
}

const std::vector<uint8_t> RCS::Nonce()
{
	return m_rcsState->Nonce;
}

const size_t RCS::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &RCS::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<uint8_t> RCS::Tag()
{
	if (m_rcsState->MacTag.size() == 0 || IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(std::string("RCS"), std::string("Tag"), std::string("The cipher is not initialized for authentication or has not run!"), ErrorCodes::NotInitialized);
	}

	return SecureUnlock(m_rcsState->MacTag);
}

const void RCS::Tag(SecureVector<uint8_t> &Output)
{
	if (m_rcsState->MacTag.size() == 0 || IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(std::string("RCS"), std::string("Tag"), std::string("The cipher is not initialized for authentication or has not run!"), ErrorCodes::NotInitialized);
	}

	SecureCopy(m_rcsState->MacTag, 0, Output, 0, m_rcsState->MacTag.size());
}

const size_t RCS::TagSize()
{
	if (IsInitialized() == false)
	{
		throw CryptoSymmetricException(std::string("RCS"), std::string("TagSize"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}

	return IsAuthenticator() ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void RCS::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	size_t i;

	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().IVSize() != BLOCK_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Requires a nonce equal in size to the ciphers block size!"), ErrorCodes::InvalidNonce);
	}

	if (m_parallelProfile.IsParallel())
	{
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	// reset for a new key
	if (IsInitialized() == true)
	{
		Reset();
	}

	// set the initial processed-bytes count to one
	m_rcsState->Counter = 1;

	// set the number of rounds -v1.0d
	m_rcsState->Rounds = (Parameters.KeySizes().KeySize() == IK256_SIZE) ?
		RK256_COUNT : 
		(Parameters.KeySizes().KeySize() == IK512_SIZE) ?
			RK512_COUNT : 
			RK1024_COUNT;

	if (m_rcsState->IsAuthenticated)
	{
		m_rcsState->Authenticator = (Parameters.KeySizes().KeySize() == IK128_SIZE) ?
			KmacModes::KMAC128 :
			(Parameters.KeySizes().KeySize() == IK512_SIZE) ?
			KmacModes::KMAC512 :
			KmacModes::KMAC256;

		m_macAuthenticator.reset(new KMAC(m_rcsState->Authenticator));
	}

	// store the customization string -v1.0d
	if (Parameters.KeySizes().InfoSize() != 0)
	{
		m_rcsState->Custom.resize(Parameters.KeySizes().InfoSize());
		// copy the user defined string to the customization parameter
		MemoryTools::Copy(Parameters.Info(), 0, m_rcsState->Custom, 0, Parameters.KeySizes().InfoSize());
	}

	// create the cSHAKE name string
	std::string tmpn = Name();

	// add mac counter, key-size bits, and algorithm name to name string
	m_rcsState->Name.resize(sizeof(uint64_t) + sizeof(uint16_t) + tmpn.size());
	// mac counter is always first 8 bytes
	IntegerTools::Le64ToBytes(m_rcsState->Counter, m_rcsState->Name, 0);
	// add the cipher key size in bits as an unsigned int16_t integer
	uint16_t kbits = static_cast<uint16_t>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_rcsState->Name, sizeof(uint64_t));
	// copy the name string to state
	MemoryTools::CopyFromObject(tmpn.data(), m_rcsState->Name, sizeof(uint64_t) + sizeof(uint16_t), tmpn.size());

	// copy the nonce to state
	MemoryTools::Copy(Parameters.IV(), 0, m_rcsState->Nonce, 0, BLOCK_SIZE);

	// cipher key size determines key expansion function and Mac generator type; 256 or 512-bit
	m_rcsState->Mode = (Parameters.KeySizes().KeySize() == IK512_SIZE) ?
		ShakeModes::SHAKE512 : ShakeModes::SHAKE256;
	//	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x43, 0x53, 0x4B, 0x32, 0x35, 0x36
	Kdf::SHAKE gen(m_rcsState->Mode);
	// initialize cSHAKE with k,c,n
	gen.Initialize(Parameters.SecureKey(), m_rcsState->Custom, m_rcsState->Name);

#if defined(CEX_HAS_AVX)

	// calculate the size of the round-key array
	const size_t RNKLEN = static_cast<size_t>(BLOCK_SIZE / sizeof(m_rcsState->RoundKeys[0])) * static_cast<size_t>(m_rcsState->Rounds + 1UL);
	m_rcsState->RoundKeys.resize(RNKLEN);
	SecureVector<uint8_t> tmpr(RNKLEN * sizeof(m_rcsState->RoundKeys[0]));
	// generate the cipher round-keys
	gen.Generate(tmpr);

	// copy p-rand bytes to round keys
	for (i = 0; i < RNKLEN; ++i)
	{
#	if defined(CEX_EXTENDED_AESNI) && defined(CEX_HAS_AVX2)
		m_rcsState->RoundKeys[i] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&tmpr[i * sizeof(__m256i)]));
#	else
		m_rcsState->RoundKeys[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&tmpr[i * sizeof(__m128i)]));
#	endif
	}

	MemoryTools::Clear(tmpr, 0, tmpr.size());

#else

	// size the round key array
	const size_t RNKLEN = static_cast<size_t>(BLOCK_SIZE / sizeof(uint32_t)) * static_cast<size_t>(m_rcsState->Rounds + 1UL);
	m_rcsState->RoundKeys.resize(RNKLEN);
	// generate the round keys to a temporary uint8_t array
	SecureVector<uint8_t> tmpr(RNKLEN * sizeof(uint32_t));
	// generate the ciphers round-keys
	gen.Generate(tmpr);

	// realign in big endian format for ACS test vectors; RCS is the fallback to the AES-NI implementation
	for (i = 0; i < tmpr.size() / sizeof(uint32_t); ++i)
	{
		m_rcsState->RoundKeys[i] = IntegerTools::BeBytesTo32(tmpr, i * sizeof(uint32_t));
	}

	MemoryTools::Clear(tmpr, 0, tmpr.size());

#endif

	if (IsAuthenticator())
	{
		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[0];
		SecureVector<uint8_t> mack(ks.KeySize());
		gen.Generate(mack);
		// initialize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_rcsState->MacKey.resize(mack.size());
		SecureMove(mack, 0, m_rcsState->MacKey, 0, mack.size());
		m_rcsState->MacTag.resize(m_macAuthenticator->TagSize());
	}

	m_rcsState->IsEncryption = Encryption;
	m_rcsState->IsInitialized = true;
}

void RCS::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void RCS::SetAssociatedData(const std::vector<uint8_t> &Input, size_t Offset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
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

void RCS::Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the block-size!");

	if (IsEncryption() == true)
	{
		if (IsAuthenticator() == true)
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not int64_t enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce
			m_macAuthenticator->Update(m_rcsState->Nonce, 0, BLOCK_SIZE);
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the processed bytes counter
			m_rcsState->Counter += Length;
			// finalize the mac and copy the tag to the end of the output stream
			Finalize(m_rcsState, m_macAuthenticator);
			MemoryTools::Copy(m_rcsState->MacTag, 0, Output, OutOffset + Length, m_rcsState->MacTag.size());
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
			m_macAuthenticator->Update(m_rcsState->Nonce, 0, BLOCK_SIZE);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the processed bytes counter
			m_rcsState->Counter += Length;
			// finalize the mac and verify
			Finalize(m_rcsState, m_macAuthenticator);

			if (IntegerTools::Compare(Input, InOffset + Length, m_rcsState->MacTag, 0, m_rcsState->MacTag.size()) == false)
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void RCS::Finalize(std::unique_ptr<RcsState> &State, std::unique_ptr<IMac> &Authenticator)
{
	std::vector<uint8_t> mctr(sizeof(uint64_t));
	uint64_t mlen;

	// 1.1a: add the number of bytes processed by the mac, including the nonce and this terminating string
	mlen = State->Counter + State->Nonce.size() + mctr.size();
	IntegerTools::Le64ToBytes(mlen, mctr, 0);

	// add the termination string to the mac
	Authenticator->Update(mctr, 0, mctr.size());

	// 1.0e: finalize the mac code to state
	Authenticator->Finalize(State->MacTag, 0);
}

void RCS::Generate(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length, std::vector<uint8_t> &Counter)
{
	size_t bctr;

	bctr = 0;

	// Note: The counter length passed into LEIncrement, only processes the first 16 bytes
	// as the full counter length. This is because this cipher is not expected to encrypt
	// more that 2^128 bytes of data with a single key.

#if defined(CEX_HAS_AVX512)

	const size_t AVX512BLK = 2 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<uint8_t> tmpc(AVX512BLK);

		// stagger counters and process 2 blocks with avx512
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform512(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVX512BLK;
		}
	}

#elif defined(CEX_HAS_AVX2)

	const size_t AVX2BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		std::vector<uint8_t> tmpc(AVX2BLK);

		// stagger counters and process 8 blocks with avx2
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 64, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 96, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 128, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 160, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 192, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 224, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform2048(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVX2BLK;
		}
	}

#elif defined(CEX_HAS_AVX)

	const size_t AVXBLK = 4 * BLOCK_SIZE;

	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<uint8_t> tmpc(AVXBLK);

		// 4 blocks with avx
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 64, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 96, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform1024(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVXBLK;
		}
	}

#endif

	const size_t BLKALN = Length - (Length % BLOCK_SIZE);

	while (bctr != BLKALN)
	{
		Transform256(Counter, 0, Output, OutOffset + bctr);
		IntegerTools::LeIncrement(Counter, 16);
		bctr += BLOCK_SIZE;
	}

	if (bctr != Length)
	{
		std::vector<uint8_t> otp(BLOCK_SIZE);
		Transform256(Counter, 0, otp, 0);
		IntegerTools::LeIncrement(Counter, 16);
		const size_t RMDLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - RMDLEN), RMDLEN);
	}
}

#if defined(CEX_HAS_AVX)

#	if defined(CEX_HAS_AVX512)
__m512i ACS::Load256To512(__m256i &A, __m256i &B)
{
	__m512i x;

	x = _mm512_setzero_si512();
	x = _mm512_inserti32x8(x, A, 0);
	x = _mm512_inserti32x8(x, B, 1);

	return x;
}

__m512i ACS::Shuffle512(const __m512i &Value, const __m512i &Mask)
{
	return _mm512_or_si512(_mm512_shuffle_epi8(Value, _mm512_add_epi8(Mask, NI512K0)),
		_mm512_shuffle_epi8(_mm512_permutex_epi64(Value, 0x4E), _mm512_add_epi8(Mask, NI512K1)));
}
#	endif

#	if defined(CEX_EXTENDED_AESNI)
__m256i ACS::Shuffle256(const __m256i &Value, const __m256i &Mask)
{
	return _mm256_or_si256(_mm256_shuffle_epi8(Value, _mm256_add_epi8(Mask, NI256K0)),
		_mm256_shuffle_epi8(_mm256_permute4x64_epi64(Value, 0x4E), _mm256_add_epi8(Mask, NI256K1)));
}
#	endif

#else
CEX_OPTIMIZE_IGNORE
void RCS::PrefetchSbox()
{
	// timing defence: pre-load sbox into l1 cache
	MemoryTools::PrefetchL1(SBox, 0, SBox.size());
}
CEX_OPTIMIZE_RESUME
#endif

void RCS::Process(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	size_t i;

	const size_t PRLBLK = m_parallelProfile.ParallelBlockSize();

	if (m_parallelProfile.IsParallel() && Length >= PRLBLK)
	{
		const size_t BLKCNT = Length / PRLBLK;

		for (i = 0; i < BLKCNT; ++i)
		{
			ProcessParallel(Input, InOffset + (i * PRLBLK), Output, OutOffset + (i * PRLBLK), PRLBLK);
		}

		const size_t RMDLEN = Length - (PRLBLK * BLKCNT);

		if (RMDLEN != 0)
		{
			const size_t BLKOFT = (PRLBLK * BLKCNT);
			ProcessSequential(Input, InOffset + BLKOFT, Output, OutOffset + BLKOFT, RMDLEN);
		}
	}
	else
	{
		ProcessSequential(Input, InOffset, Output, OutOffset, Length);
	}
}

void RCS::ProcessParallel(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	const size_t OUTLEN = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
	std::vector<uint8_t> tmpc(BLOCK_SIZE);

	ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpc, CNKLEN, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<uint8_t> thdc(BLOCK_SIZE);
		// offset counter by chunk size / block size  
		IntegerTools::LeIncrease8(m_rcsState->Nonce, thdc, static_cast<uint32_t>(CTRLEN * i));
		const size_t STMPOS = i * CNKLEN;
		// generate random at output offset
		this->Generate(Output, OutOffset + STMPOS, CNKLEN, thdc);
		// xor with input at offsets
		MemoryTools::XOR(Input, InOffset + STMPOS, Output, OutOffset + STMPOS, CNKLEN);

		// store last counter
		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			MemoryTools::Copy(thdc, 0, tmpc, 0, BLOCK_SIZE);
		}
	});

	// copy last counter to class variable
	MemoryTools::Copy(tmpc, 0, m_rcsState->Nonce, 0, BLOCK_SIZE);

	// last block processing
	const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
	if (ALNLEN < OUTLEN)
	{
		const size_t FNLLEN = OUTLEN - ALNLEN;
		InOffset += ALNLEN;
		OutOffset += ALNLEN;

		Generate(Output, OutOffset, FNLLEN, m_rcsState->Nonce);

		for (size_t i = 0; i < FNLLEN; ++i)
		{
			Output[OutOffset + i] ^= Input[InOffset + i];
		}
	}
}

void RCS::ProcessSequential(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	// get block aligned
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	size_t i;

	// generate random
	Generate(Output, OutOffset, Length, m_rcsState->Nonce);

	if (ALNLEN != 0)
	{
		MemoryTools::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
	}

	// get the remaining bytes
	if (ALNLEN != Length)
	{
		for (i = ALNLEN; i < Length; ++i)
		{
			Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
}

void RCS::Reset()
{
	m_rcsState->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}

	m_parallelProfile.Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
}

SecureVector<uint8_t> RCS::Serialize()
{
	SecureVector<uint8_t> tmps = m_rcsState->Serialize();

	return tmps;
}

void RCS::Transform256(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
#if defined(CEX_HAS_AVX)
#	if defined(CEX_EXTENDED_AESNI)

	static const __m256i SWMASK = _mm256_setr_epi8(0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19, 
		16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3);
	const size_t RNDCNT = m_rcsState->RoundKeys.size() - 2;
	size_t kctr;
	__m256i x;

	kctr = 0; 

	x = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset]));
	x = _mm256_xor_si256(x, m_rcsState->RoundKeys[kctr]);

	while (kctr < RNDCNT)
	{
		++kctr;
		x = Shuffle256(x, SWMASK);
		x = _mm256_aesenc_epi128(x, m_rcsState->RoundKeys[kctr]);
	}

	++kctr;
	x = Shuffle256(x, SWMASK);
	_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_aesenclast_epi128(x, m_rcsState->RoundKeys[kctr]));

#	else

	const size_t HLFBLK = 16;
	const size_t RNDCNT = m_rcsState->RoundKeys.size() - 3;
	size_t kctr;

	__m128i blk1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
	__m128i blk2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + HLFBLK]));
	__m128i tmp1;
	__m128i tmp2;

	kctr = 0;
	blk1 = _mm_xor_si128(blk1, m_rcsState->RoundKeys[kctr]);
	++kctr;
	blk2 = _mm_xor_si128(blk2, m_rcsState->RoundKeys[kctr]);

	while (kctr != RNDCNT)
	{
		// mix the blocks
		tmp1 = _mm_blendv_epi8(blk1, blk2, NIBMASK);
		tmp2 = _mm_blendv_epi8(blk2, blk1, NIBMASK);
		// shuffle
		tmp1 = _mm_shuffle_epi8(tmp1, NISMASK);
		tmp2 = _mm_shuffle_epi8(tmp2, NISMASK);
		++kctr;
		// encrypt the first half-block
		blk1 = _mm_aesenc_si128(tmp1, m_rcsState->RoundKeys[kctr]);
		++kctr;
		// encrypt the second half-block
		blk2 = _mm_aesenc_si128(tmp2, m_rcsState->RoundKeys[kctr]);
	}

	// final block
	tmp1 = _mm_blendv_epi8(blk1, blk2, NIBMASK);
	tmp2 = _mm_blendv_epi8(blk2, blk1, NIBMASK);
	tmp1 = _mm_shuffle_epi8(tmp1, NISMASK);
	tmp2 = _mm_shuffle_epi8(tmp2, NISMASK);
	++kctr;
	blk1 = _mm_aesenclast_si128(tmp1, m_rcsState->RoundKeys[kctr]);
	++kctr;
	blk2 = _mm_aesenclast_si128(tmp2, m_rcsState->RoundKeys[kctr]);

	// store in output
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), blk1);
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + HLFBLK]), blk2);

#	endif
#else

	SecureVector<uint8_t> state(BLOCK_SIZE, 0x00);
	size_t i;

	MemoryTools::Copy(Input, InOffset, state, 0, BLOCK_SIZE);
	KeyAddition(state, m_rcsState->RoundKeys, 0);

	// pre-load the s-box into L1 cache
#	if defined(CEX_PREFETCH_RIJNDAEL_TABLES)
	PrefetchSbox();
#	endif

	for (i = 1; i < m_rcsState->Rounds; ++i)
	{
		Substitution(state);
		ShiftRows256(state);
		MixColumns(state);
		KeyAddition(state, m_rcsState->RoundKeys, (i << 3UL));
	}

	Substitution(state);
	ShiftRows256(state);
	KeyAddition(state, m_rcsState->RoundKeys, static_cast<size_t>(m_rcsState->Rounds) << 3UL);

	MemoryTools::Copy(state, 0, Output, OutOffset, BLOCK_SIZE);
#endif
}

void RCS::Transform512(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)//255..208 0..208
{
#if defined(CEX_HAS_AVX512)

	const __m512i SWMASKL = _mm512_setr_epi8(
		0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19, 16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3,
		0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19, 16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3);

	const size_t RNDCNT = m_rcsState->RoundKeys.size() - 2;
	size_t kctr;
	__m512i x;

	kctr = 0;
	x = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset]));
	x = _mm512_xor_si512(x, Load256To512(m_rcsState->RoundKeys[kctr], m_rcsState->RoundKeys[kctr]));

	while (kctr < RNDCNT)
	{
		++kctr;
		x = Shuffle512(x, SWMASKL);
		x = _mm512_aesenc_epi128(x, Load256To512(m_rcsState->RoundKeys[kctr], m_rcsState->RoundKeys[kctr]));
	}

	++kctr;
	x = Shuffle512(x, SWMASKL);
	_mm512_storeu_si512(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm512_aesenclast_epi128(x, Load256To512(m_rcsState->RoundKeys[kctr], m_acsState->RoundKeys[kctr])));

#else

	Transform256(Input, InOffset, Output, OutOffset);
	Transform256(Input, InOffset + 32, Output, OutOffset + 32);

#endif
}

void RCS::Transform1024(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Transform256(Input, InOffset, Output, OutOffset);
	Transform256(Input, InOffset + 32, Output, OutOffset + 32);
	Transform256(Input, InOffset + 64, Output, OutOffset + 64);
	Transform256(Input, InOffset + 96, Output, OutOffset + 96);
}

void RCS::Transform2048(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Transform1024(Input, InOffset, Output, OutOffset);
	Transform1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void RCS::Transform4096(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	Transform2048(Input, InOffset, Output, OutOffset);
	Transform2048(Input, InOffset + 256, Output, OutOffset + 256);
}

NAMESPACE_STREAMEND
