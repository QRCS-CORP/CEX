#include "ACS.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "KMAC.h"
#include "MemoryTools.h"
#include "SHAKE.h"
#include "StreamAuthenticators.h"
#include <immintrin.h>

NAMESPACE_STREAM

using Tools::IntegerTools;
using Mac::KMAC;
using Tools::MemoryTools;
using Tools::ParallelTools;
using Enumeration::ShakeModes;
using Enumeration::StreamAuthenticators;
using Enumeration::StreamCipherConvert;

#if defined(CEX_HAS_AVX512)
	const __m512i ACS::NI512K0 = _mm512_set_epi64(17361641481138401520, 17361641481138401520, 8102099357864587376, 8102099357864587376,
		17361641481138401520, 17361641481138401520, 8102099357864587376, 8102099357864587376);
	const __m512i ACS::NI512K1 = _mm512_set_epi64(8102099357864587376, 8102099357864587376, 17361641481138401520, 17361641481138401520,
		8102099357864587376, 8102099357864587376, 17361641481138401520, 17361641481138401520);
#endif
#if defined(CEX_EXTENDED_AESNI)
	const __m256i ACS::NI256K0 = _mm256_set_epi64x(17361641481138401520, 17361641481138401520, 8102099357864587376, 8102099357864587376);
	const __m256i ACS::NI256K1 = _mm256_set_epi64x(8102099357864587376, 8102099357864587376, 17361641481138401520, 17361641481138401520);
#else
	const __m128i ACS::NIBMASK = _mm_set_epi32(0x80000000UL, 0x80800000UL, 0x80800000UL, 0x80808000UL);
	const __m128i ACS::NISMASK = _mm_setr_epi8(0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3);
#endif

class ACS::AcsState
{
public:

#if defined(CEX_EXTENDED_AESNI)
	std::vector<__m256i> RoundKeys;
#else
	std::vector<__m128i> RoundKeys;
#endif
	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	SecureVector<byte> Name;
	std::vector<SymmetricKeySize> LegalKeySizes;
	std::vector<byte> Nonce;
	ulong Counter;
	ushort Rounds;
	KmacModes Authenticator;
	ShakeModes Mode;
	bool IsAuthenticated;
	bool IsEncryption;
	bool Initialized;

	AcsState(bool Authenticate)
		:
		RoundKeys(0),
		Custom(0),
		MacKey(0),
		MacTag(0),
		Name(0),
		LegalKeySizes{
			SymmetricKeySize(IK256_SIZE, BLOCK_SIZE, INFO_SIZE),
			SymmetricKeySize(IK512_SIZE, BLOCK_SIZE, INFO_SIZE),
			SymmetricKeySize(IK1024_SIZE, BLOCK_SIZE, INFO_SIZE) },
		Nonce(BLOCK_SIZE, 0x00),
		Counter(0),
		Rounds(0),
		Authenticator(Authenticator),
		Mode(ShakeModes::None),
		IsAuthenticated(Authenticate),
		IsEncryption(false),
		Initialized(false)
	{
	}

	AcsState(SecureVector<byte> &State)
		:
		RoundKeys(0),
		Custom(0),
		MacKey(0),
		MacTag(0),
		Name(0),
		LegalKeySizes{
			SymmetricKeySize(IK256_SIZE, BLOCK_SIZE, INFO_SIZE),
			SymmetricKeySize(IK512_SIZE, BLOCK_SIZE, INFO_SIZE),
			SymmetricKeySize(IK1024_SIZE, BLOCK_SIZE, INFO_SIZE) },
		Nonce(BLOCK_SIZE, 0x00),
		Counter(0),
		Rounds(0),
		Authenticator(KmacModes::None),
		Mode(ShakeModes::None),
		IsAuthenticated(false),
		IsEncryption(false),
		Initialized(false)
	{
		DeSerialize(State);
	}

	~AcsState()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(__m128i));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		LegalKeySizes.clear();

		Counter = 0;
		Rounds = 0;
		Authenticator = KmacModes::None;
		Mode = ShakeModes::None;
		IsAuthenticated = false;
		IsEncryption = false;
		Initialized = false;
	}

	void DeSerialize(SecureVector<byte> &SecureState)
	{
		size_t soff;
		ushort vlen;

		soff = 0;
		vlen = 0;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		RoundKeys.resize(vlen / sizeof(__m128i));
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, RoundKeys, 0, vlen);
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Custom.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Custom, 0, Custom.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		MacKey.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, MacKey, 0, MacKey.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		MacTag.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, MacTag, 0, MacTag.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Name.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Name, 0, Name.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Nonce.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Nonce, 0, Nonce.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &Counter, sizeof(ulong));
		soff += sizeof(ulong);
		MemoryTools::CopyToObject(SecureState, soff, &Rounds, sizeof(ushort));
		soff += sizeof(ushort);

		MemoryTools::CopyToObject(SecureState, soff, &Authenticator, sizeof(KmacModes));
		soff += sizeof(KmacModes);
		MemoryTools::CopyToObject(SecureState, soff, &Mode, sizeof(ShakeModes));
		soff += sizeof(ShakeModes);

		MemoryTools::CopyToObject(SecureState, soff, &IsAuthenticated, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyToObject(SecureState, soff, &IsEncryption, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyToObject(SecureState, soff, &Initialized, sizeof(bool));
	}

	void Reset()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(RoundKeys[0]));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		Counter = 0;
		Rounds = 0;
		IsEncryption = false;
		Initialized = false;
	}

	SecureVector<byte> Serialize()
	{
		const size_t STALEN = (RoundKeys.size() * sizeof(RoundKeys[0])) + Custom.size() + MacKey.size() + MacTag.size() +
			Name.size() + Nonce.size() + sizeof(ulong) + sizeof(ushort) + sizeof(KmacModes) + sizeof(ShakeModes) + (3 * sizeof(bool)) + (7 * sizeof(ushort));

		size_t soff;
		ushort vlen;
		SecureVector<byte> state(STALEN);

		soff = 0;
		vlen = static_cast<ushort>(RoundKeys.size() * sizeof(RoundKeys[0]));
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(RoundKeys, 0, state, soff, static_cast<size_t>(vlen));
		soff += vlen;

		vlen = static_cast<ushort>(Custom.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Custom, 0, state, soff, Custom.size());
		soff += Custom.size();

		vlen = static_cast<ushort>(MacKey.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(MacKey, 0, state, soff, MacKey.size());
		soff += MacKey.size();

		vlen = static_cast<ushort>(MacTag.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(MacTag, 0, state, soff, MacTag.size());
		soff += MacTag.size();

		vlen = static_cast<ushort>(Name.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Name, 0, state, soff, Name.size());
		soff += Name.size();

		vlen = static_cast<ushort>(Nonce.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Nonce, 0, state, soff, Nonce.size());
		soff += Nonce.size();

		MemoryTools::CopyFromObject(&Counter, state, soff, sizeof(ulong));
		soff += sizeof(ulong);
		MemoryTools::CopyFromObject(&Rounds, state, soff, sizeof(ushort));
		soff += sizeof(ushort);

		MemoryTools::CopyFromObject(&Authenticator, state, soff, sizeof(KmacModes));
		soff += sizeof(KmacModes);
		MemoryTools::CopyFromObject(&Mode, state, soff, sizeof(ShakeModes));
		soff += sizeof(ShakeModes);

		MemoryTools::CopyFromObject(&IsAuthenticated, state, soff, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyFromObject(&IsEncryption, state, soff, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyFromObject(&Initialized, state, soff, sizeof(bool));

		return state;
	}
};

//~~~Constructor~~~//

ACS::ACS(bool Authenticate)
	:
	m_acsState(new AcsState(Authenticate)),
	m_macAuthenticator(nullptr),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
#if !defined(CEX_AVX_INTRINSICS)
	throw CryptoSymmetricException(StreamCipherConvert::ToName(StreamCiphers::RCS), std::string("Constructor"), std::string("AVX is not supported on this system!"), ErrorCodes::NotSupported);
#endif
}

ACS::ACS(SecureVector<byte> &State)
	:
	m_acsState(State.size() > STATE_THRESHOLD ? new AcsState(State) :
		throw CryptoSymmetricException(std::string("ACS"), std::string("Constructor"), std::string("The State array is invalid!"), ErrorCodes::InvalidKey)),
	m_macAuthenticator(m_acsState->Authenticator == KmacModes::None ?
		nullptr :
		new KMAC(m_acsState->Authenticator)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
#if !defined(CEX_AVX_INTRINSICS)
	throw CryptoSymmetricException(StreamCipherConvert::ToName(StreamCiphers::RCS), std::string("Constructor"), std::string("AVX is not supported on this system!"), ErrorCodes::NotSupported);
#endif

	if (m_acsState->Authenticator != KmacModes::None)
	{
		// initialize the mac
		SymmetricKey kpm(m_acsState->MacKey);
		m_macAuthenticator->Initialize(kpm);
	}
}

ACS::~ACS()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers ACS::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() && m_macAuthenticator != nullptr ?
		static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()) :
		StreamAuthenticators::None;

	tmpn = StreamCipherConvert::FromDescription(StreamCiphers::RCS, auth);

	return tmpn;
}

const bool ACS::IsAuthenticator()
{
	return m_acsState->IsAuthenticated;
}

const bool ACS::IsEncryption()
{
	return m_acsState->IsEncryption;
}

const bool ACS::IsInitialized()
{
	return m_acsState->Initialized;
}

const bool ACS::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &ACS::LegalKeySizes()
{
	return m_acsState->LegalKeySizes;
}

const std::string ACS::Name()
{
	std::string name;

	name = StreamCipherConvert::ToName(Enumeral());

	return name;
}

const std::vector<byte> ACS::Nonce()
{
	return m_acsState->Nonce;
}

const size_t ACS::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ACS::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> ACS::Tag()
{
	if (m_acsState->MacTag.size() == 0 || IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(std::string("RCS"), std::string("Tag"), std::string("The cipher is not initialized for authentication or has not run!"), ErrorCodes::NotInitialized);
	}

	return SecureUnlock(m_acsState->MacTag);
}

const void ACS::Tag(SecureVector<byte> &Output)
{
	if (m_acsState->MacTag.size() == 0 || IsAuthenticator() == false)
	{
		throw CryptoSymmetricException(std::string("RCS"), std::string("Tag"), std::string("The cipher is not initialized for authentication or has not run!"), ErrorCodes::NotInitialized);
	}

	SecureCopy(m_acsState->MacTag, 0, Output, 0, m_acsState->MacTag.size());
}

const size_t ACS::TagSize()
{
	if (IsInitialized() == false)
	{
		throw CryptoSymmetricException(std::string("RCS"), std::string("TagSize"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}

	return IsAuthenticator() ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void ACS::Initialize(bool Encryption, ISymmetricKey &Parameters)
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
	m_acsState->Counter = 1;

	// set the number of rounds -v1.0d
	m_acsState->Rounds = (Parameters.KeySizes().KeySize() == IK256_SIZE) ?
		RK256_COUNT :
		(Parameters.KeySizes().KeySize() == IK512_SIZE) ?
			RK512_COUNT :
			RK1024_COUNT;

	if (m_acsState->IsAuthenticated)
	{
		m_acsState->Authenticator = (Parameters.KeySizes().KeySize() == IK1024_SIZE) ?
			KmacModes::KMAC1024 :
			(Parameters.KeySizes().KeySize() == IK512_SIZE) ?
			KmacModes::KMAC512 :
			KmacModes::KMAC256;

		m_macAuthenticator.reset(new KMAC(m_acsState->Authenticator));
	}

	// store the customization string -v1.0d
	if (Parameters.KeySizes().InfoSize() != 0)
	{
		m_acsState->Custom.resize(Parameters.KeySizes().InfoSize());
		// copy the user defined string to the customization parameter
		MemoryTools::Copy(Parameters.Info(), 0, m_acsState->Custom, 0, Parameters.KeySizes().InfoSize());
	}

	// create the cSHAKE name string
	std::string tmpn = Name();
	// add mac counter, key-size bits, and algorithm name to name string
	m_acsState->Name.resize(sizeof(ulong) + sizeof(ushort) + tmpn.size());
	// mac counter is always first 8 bytes of name
	IntegerTools::Le64ToBytes(m_acsState->Counter, m_acsState->Name, 0);
	// add the cipher key size in bits as an unsigned 16-bit integer
	ushort kbits = static_cast<ushort>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_acsState->Name, sizeof(ulong));
	// copy the name string to state
	MemoryTools::CopyFromObject(tmpn.data(), m_acsState->Name, sizeof(ulong) + sizeof(ushort), tmpn.size());

	// copy the nonce to state
	MemoryTools::Copy(Parameters.IV(), 0, m_acsState->Nonce, 0, BLOCK_SIZE);

	// cipher key size determines key expansion function and Mac generator type; 256 or 512-bit
	m_acsState->Mode = (Parameters.KeySizes().KeySize() == IK512_SIZE) ?
		ShakeModes::SHAKE512 : 
		(Parameters.KeySizes().KeySize() == IK256_SIZE) ?
			ShakeModes::SHAKE256 : 
			ShakeModes::SHAKE1024;

	// initialize the generator
	Kdf::SHAKE gen(m_acsState->Mode);
	// key with cSHAKE(k,c,n)
	gen.Initialize(Parameters.SecureKey(), m_acsState->Custom, m_acsState->Name);

	// calculate the size of the round-key array
	const size_t RNKLEN = static_cast<size_t>(BLOCK_SIZE / sizeof(m_acsState->RoundKeys[0])) * static_cast<size_t>(m_acsState->Rounds + 1UL);
	m_acsState->RoundKeys.resize(RNKLEN);
	SecureVector<byte> tmpr(RNKLEN * sizeof(m_acsState->RoundKeys[0]));
	// generate the cipher round-keys
	gen.Generate(tmpr);

	// copy p-rand bytes to round keys
	for (i = 0; i < RNKLEN; ++i)
	{
#if defined(CEX_EXTENDED_AESNI) && defined(CEX_HAS_AVX2)
		m_acsState->RoundKeys[i] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&tmpr[i * sizeof(__m256i)]));
#else
		m_acsState->RoundKeys[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&tmpr[i * sizeof(__m128i)]));
#endif
	}

	MemoryTools::Clear(tmpr, 0, tmpr.size());

	if (IsAuthenticator())
	{
		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
		SecureVector<byte> mack(ks.KeySize());
		gen.Generate(mack);
		// initialize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_acsState->MacKey.resize(mack.size());
		SecureMove(mack, 0, m_acsState->MacKey, 0, mack.size());
		m_acsState->MacTag.resize(m_macAuthenticator->TagSize());
	}

	m_acsState->IsEncryption = Encryption;
	m_acsState->Initialized = true;
}

void ACS::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void ACS::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
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
		std::vector<byte> code(sizeof(uint));
		// version 1.1a add AD and encoding to hash
		m_macAuthenticator->Update(Input, Offset, Length);
		IntegerTools::Le32ToBytes(static_cast<uint>(Length), code, 0);
		m_macAuthenticator->Update(code, 0, code.size());
	}
}

void ACS::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the block-size!");

	if (IsEncryption() == true)
	{
		if (IsAuthenticator() == true)
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not long enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce
			m_macAuthenticator->Update(m_acsState->Nonce, 0, BLOCK_SIZE);
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the processed bytes counter
			m_acsState->Counter += Length;
			// finalize the mac and copy the tag to the end of the output stream
			Finalize(m_acsState, m_macAuthenticator);
			MemoryTools::Copy(m_acsState->MacTag, 0, Output, OutOffset + Length, m_acsState->MacTag.size());
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
			m_macAuthenticator->Update(m_acsState->Nonce, 0, BLOCK_SIZE);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the processed bytes counter
			m_acsState->Counter += Length;
			// finalize the mac and verify
			Finalize(m_acsState, m_macAuthenticator);

			if (IntegerTools::Compare(Input, InOffset + Length, m_acsState->MacTag, 0, m_acsState->MacTag.size()) == false)
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void ACS::Finalize(std::unique_ptr<AcsState> &State, std::unique_ptr<IMac> &Authenticator)
{
	std::vector<byte> mctr(sizeof(ulong));
	ulong mlen;

	// 1.1a: add the number of bytes processed by the mac, including the nonce and this terminating string
	mlen = State->Counter + State->Nonce.size() + mctr.size();
	IntegerTools::Le64ToBytes(mlen, mctr, 0);

	// add the termination string to the mac
	Authenticator->Update(mctr, 0, mctr.size());

	// 1.0e: finalize the mac code to state
	Authenticator->Finalize(State->MacTag, 0);
}

void ACS::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<byte> &Counter)
{
	size_t bctr;

	bctr = 0;

#if defined(CEX_HAS_AVX512)

	const size_t AVX512BLK = 2 * BLOCK_SIZE;
	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<byte> tmpc(AVX512BLK);

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
		std::vector<byte> otp(BLOCK_SIZE);
		Transform256(Counter, 0, otp, 0);
		IntegerTools::LeIncrement(Counter, 16);
		const size_t RMDLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - RMDLEN), RMDLEN);
	}
}

#if defined(CEX_HAS_AVX512)
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
#endif

#if defined(CEX_EXTENDED_AESNI)
__m256i ACS::Shuffle256(const __m256i &Value, const __m256i &Mask)
{
	return _mm256_or_si256(_mm256_shuffle_epi8(Value, _mm256_add_epi8(Mask, NI256K0)),
		_mm256_shuffle_epi8(_mm256_permute4x64_epi64(Value, 0x4E), _mm256_add_epi8(Mask, NI256K1)));
}
#endif

void ACS::Process(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
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

void ACS::ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t OUTLEN = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
	std::vector<byte> tmpc(BLOCK_SIZE);

	ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpc, CNKLEN, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<byte> thdc(BLOCK_SIZE);
		// offset counter by chunk size / block size  
		IntegerTools::LeIncrease8(m_acsState->Nonce, thdc, static_cast<uint>(CTRLEN * i));
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
	MemoryTools::Copy(tmpc, 0, m_acsState->Nonce, 0, BLOCK_SIZE);

	// last block processing
	const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
	if (ALNLEN < OUTLEN)
	{
		const size_t FNLLEN = OUTLEN - ALNLEN;
		InOffset += ALNLEN;
		OutOffset += ALNLEN;

		Generate(Output, OutOffset, FNLLEN, m_acsState->Nonce);

		for (size_t i = 0; i < FNLLEN; ++i)
		{
			Output[OutOffset + i] ^= Input[InOffset + i];
		}
	}
}

void ACS::ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	// get block aligned
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	size_t i;

	// generate random
	Generate(Output, OutOffset, Length, m_acsState->Nonce);

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

void ACS::Reset()
{
	m_acsState->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}

	m_parallelProfile.Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
}

SecureVector<byte> ACS::Serialize()
{
	SecureVector<byte> tmps = m_acsState->Serialize();

	return tmps;
}

void ACS::Transform256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)// 0, 255..208
{
#if defined(CEX_EXTENDED_AESNI)

	static const __m256i SWMASK = _mm256_setr_epi8(0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19, 
		16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3);
	const size_t RNDCNT = m_acsState->RoundKeys.size() - 2;
	size_t kctr;
	__m256i x;

	kctr = 0; 

	x = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset]));
	x = _mm256_xor_si256(x, m_acsState->RoundKeys[kctr]);

	while (kctr < RNDCNT)
	{
		++kctr;
		x = Shuffle256(x, SWMASK);
		x = _mm256_aesenc_epi128(x, m_acsState->RoundKeys[kctr]);
	}

	++kctr;
	x = Shuffle256(x, SWMASK);
	_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_aesenclast_epi128(x, m_acsState->RoundKeys[kctr]));

#else

	const size_t HLFBLK = 16;
	const size_t RNDCNT = m_acsState->RoundKeys.size() - 3;
	size_t kctr;

	__m128i blk1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
	__m128i blk2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + HLFBLK]));
	__m128i tmp1;
	__m128i tmp2;

	kctr = 0;
	blk1 = _mm_xor_si128(blk1, m_acsState->RoundKeys[kctr]);
	++kctr;
	blk2 = _mm_xor_si128(blk2, m_acsState->RoundKeys[kctr]);

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
		blk1 = _mm_aesenc_si128(tmp1, m_acsState->RoundKeys[kctr]);
		++kctr;
		// encrypt the second half-block
		blk2 = _mm_aesenc_si128(tmp2, m_acsState->RoundKeys[kctr]);
	}

	// final block
	tmp1 = _mm_blendv_epi8(blk1, blk2, NIBMASK);
	tmp2 = _mm_blendv_epi8(blk2, blk1, NIBMASK);
	tmp1 = _mm_shuffle_epi8(tmp1, NISMASK);
	tmp2 = _mm_shuffle_epi8(tmp2, NISMASK);
	++kctr;
	blk1 = _mm_aesenclast_si128(tmp1, m_acsState->RoundKeys[kctr]);
	++kctr;
	blk2 = _mm_aesenclast_si128(tmp2, m_acsState->RoundKeys[kctr]);

	// store in output
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), blk1);
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + HLFBLK]), blk2);

#endif
}

void ACS::Transform512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)//255..208 0..208
{
#if defined(CEX_HAS_AVX512)

	const __m512i SWMASKL = _mm512_setr_epi8(
		0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19, 16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3,
		0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19, 16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3);

	const size_t RNDCNT = m_acsState->RoundKeys.size() - 2;
	size_t kctr;
	__m512i x;

	kctr = 0;
	x = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset]));
	x = _mm512_xor_si512(x, Load256To512(m_acsState->RoundKeys[kctr], m_acsState->RoundKeys[kctr]));

	while (kctr < RNDCNT)
	{
		++kctr;
		x = Shuffle512(x, SWMASKL);
		x = _mm512_aesenc_epi128(x, Load256To512(m_acsState->RoundKeys[kctr], m_acsState->RoundKeys[kctr]));
	}

	++kctr;
	x = Shuffle512(x, SWMASKL);
	_mm512_storeu_si512(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm512_aesenclast_epi128(x, Load256To512(m_acsState->RoundKeys[kctr], m_acsState->RoundKeys[kctr])));

#else

	Transform256(Input, InOffset, Output, OutOffset);
	Transform256(Input, InOffset + 32, Output, OutOffset + 32);

#endif
}

NAMESPACE_STREAMEND
