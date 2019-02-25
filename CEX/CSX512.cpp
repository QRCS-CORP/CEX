#include "CSX512.h"
#include "ChaCha.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "ParallelTools.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

#if defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_STREAM

using Utility::IntegerTools;
using Utility::MemoryTools;
using Utility::ParallelTools;

class CSX512::CSX512State
{
public:

	std::array<uint, 2> Nonce = { 0UL };
	std::array<uint, 14> State = { 0UL };
	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	ulong Counter;
	bool Encryption;
	bool Initialized;

	CSX512State()
		:
		Custom(0),
		MacKey(0),
		MacTag(0),
		Counter(0),
		Encryption(false),
		Initialized(false)
	{
	}

	~CSX512State()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Nonce, 0, Nonce.size() * sizeof(uint));
		MemoryTools::Clear(State, 0, State.size() * sizeof(uint));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		Encryption = false;
		Initialized = false;
	}
};

const std::string CSX512::CLASS_NAME("CSX512");
const std::vector<byte> CSX512::SIGMA_INFO = { 0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x36, 0x34, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B };

//~~~Constructor~~~//

CSX512::CSX512(StreamAuthenticators AuthenticatorType)
	:
	m_csx512State(new CSX512State),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, 0, INFO_SIZE) },
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

CSX512::~CSX512()
{
	if (m_csx512State != nullptr)
	{
		m_csx512State->Reset();
		m_csx512State.reset(nullptr);
	}
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}

	IntegerTools::Clear(m_legalKeySizes);
}

//~~~Accessors~~~//

const StreamCiphers CSX512::Enumeral()
{
	return StreamCiphers::CSX512;
}

const bool CSX512::IsAuthenticator()
{
	return static_cast<bool>(m_macAuthenticator != nullptr);
}

const bool CSX512::IsEncryption()
{
	return m_csx512State->Encryption;
}

const bool CSX512::IsInitialized()
{
	return m_csx512State->Initialized;
}

const bool CSX512::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &CSX512::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string CSX512::Name()
{
	std::string name = CLASS_NAME;

#if defined(CEX_CHACHA512_STRONG)
	name += std::string("P80");
#else
	name += std::string("P40");
#endif

	if (IsAuthenticator())
	{
		name += std::string("-") + Enumeration::StreamAuthenticatorConvert::ToName(static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()));
	}

	return name;
}

const size_t CSX512::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &CSX512::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> CSX512::Tag()
{
	return Unlock(m_csx512State->MacTag);
}

const void CSX512::Tag(SecureVector<byte> &Output)
{
	Copy(m_csx512State->MacTag, 0, Output, 0, m_csx512State->MacTag.size());
}

const size_t CSX512::TagSize()
{
	return IsAuthenticator() ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void CSX512::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.Key().size() != KEY_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
	if (Parameters.Nonce().size() != 0)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The nonce is not required with CSX512!"), ErrorCodes::InvalidNonce);
	}
	if (Parameters.Info().size() > 0 && Parameters.Info().size() != INFO_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The distribution code must be no larger than DistributionCodeMax!"), ErrorCodes::InvalidInfo);
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

	SecureVector<byte> code(INFO_SIZE);

	if (Parameters.Info().size() != 0)
	{
		// custom code
		MemoryTools::Copy(Parameters.Info(), 0, code, 0, Parameters.Info().size());
	}
	else
	{
		// standard
		MemoryTools::Copy(SIGMA_INFO, 0, code, 0, SIGMA_INFO.size());
	}

	if (!IsAuthenticator())
	{
		// add key and nonce to state
		Load(Parameters.SecureKey(), code);
	}
	else
	{
		// set the initial counter value
		m_csx512State->Counter = 1;

		// create the cSHAKE customization string
		m_csx512State->Custom.resize(sizeof(ulong) + Name().size());
		// add mac counter and algorithm name to customization string
		IntegerTools::Le64ToBytes(m_csx512State->Counter, m_csx512State->Custom, 0);
		MemoryTools::Copy(Name(), 0, m_csx512State->Custom, sizeof(ulong), Name().size());

		// initialize cSHAKE
		Kdf::SHAKE gen(ShakeModes::SHAKE512);
		gen.Initialize(Parameters.SecureKey(), m_csx512State->Custom);

		// generate the new cipher key
		SecureVector<byte> ck(KEY_SIZE);
		gen.Generate(ck);

		// load the ciphers state
		Load(ck, code);

		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
		SecureVector<byte> mack(ks.KeySize());
		gen.Generate(mack);
		// initialize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_csx512State->MacKey.resize(mack.size());
		Move(mack, m_csx512State->MacKey, 0);
		m_csx512State->MacTag.resize(TagSize());
	}

	m_csx512State->Encryption = Encryption;
	m_csx512State->Initialized = true;
}

void CSX512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void CSX512::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
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

void CSX512::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
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
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<byte>>(m_csx512State->Nonce[0]), 0, sizeof(uint));
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<byte>>(m_csx512State->Nonce[1]), 0, sizeof(uint));
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
		if (IsAuthenticator())
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<byte>>(m_csx512State->Nonce[0]), 0, sizeof(uint));
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<byte>>(m_csx512State->Nonce[1]), 0, sizeof(uint));
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_csx512State->Counter += Length;
			// finalize the mac and verify
			Finalize(m_csx512State, m_macAuthenticator);

			if (!IntegerTools::Compare(Input, InOffset + Length, m_csx512State->MacTag, 0, m_csx512State->MacTag.size()))
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
	// generate the mac code
	Authenticator->Finalize(State->MacTag, 0);

	// customization string is: mac counter + algorithm name
	IntegerTools::Le64ToBytes(State->Counter, State->Custom, 0);

	// extract the new mac key
	Kdf::SHAKE gen(ShakeModes::SHAKE512);
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

void CSX512::Generate(std::unique_ptr<CSX512State> &State, std::vector<byte> &Output, const size_t OutOffset, std::array<uint, 2> &Counter, const size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(__AVX512__)

	const size_t AVX512BLK = 16 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<uint, 32> tmpc;

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

#elif defined(__AVX2__)

	const size_t AVX2BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<uint, 16> tmpc;

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

#elif defined(__AVX__)

	const size_t AVXBLK = 4 * BLOCK_SIZE;

	if (Length >= AVXBLK)
	{
		const size_t SEGALN = Length - (Length % AVXBLK);
		std::array<uint, 8> tmpc;

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
		ChaCha::PermuteP512C(Output, OutOffset + ctr, Counter, State->State, ROUND_COUNT);
		IntegerTools::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<byte> otp(BLOCK_SIZE, 0);
		ChaCha::PermuteP512C(otp, 0, Counter, State->State, ROUND_COUNT);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
		IntegerTools::LeIncrementW(Counter);
	}
}

void CSX512::Load(const SecureVector<byte> &Key, const SecureVector<byte> &Code)
{
#if defined(CEX_IS_LITTLE_ENDIAN)
	MemoryTools::Copy(Key, 0, m_csx512State->State, 0, STATE_SIZE * sizeof(uint));
	MemoryTools::Copy(Key, STATE_SIZE * sizeof(uint), m_csx512State->Nonce, 0, NONCE_SIZE * sizeof(uint));
#else
	m_csx512State->State[0] = IntegerTools::LeBytesTo32(Key, 0);
	m_csx512State->State[1] = IntegerTools::LeBytesTo32(Key, 4);
	m_csx512State->State[2] = IntegerTools::LeBytesTo32(Key, 8);
	m_csx512State->State[3] = IntegerTools::LeBytesTo32(Key, 12);
	m_csx512State->State[4] = IntegerTools::LeBytesTo32(Key, 16);
	m_csx512State->State[5] = IntegerTools::LeBytesTo32(Key, 20);
	m_csx512State->State[6] = IntegerTools::LeBytesTo32(Key, 24);
	m_csx512State->State[7] = IntegerTools::LeBytesTo32(Key, 28);
	m_csx512State->State[8] = IntegerTools::LeBytesTo32(Key, 32);
	m_csx512State->State[9] = IntegerTools::LeBytesTo32(Key, 36);
	m_csx512State->State[10] = IntegerTools::LeBytesTo32(Key, 40);
	m_csx512State->State[11] = IntegerTools::LeBytesTo32(Key, 44);
	m_csx512State->State[12] = IntegerTools::LeBytesTo32(Key, 48);
	m_csx512State->State[13] = IntegerTools::LeBytesTo32(Key, 52);
	m_csx512State->Nonce[0] = IntegerTools::LeBytesTo32(Key, 56);
	m_csx512State->Nonce[1] = IntegerTools::LeBytesTo32(Key, 60);
#endif

	m_csx512State->State[4] += IntegerTools::LeBytesTo32(Code, 0);
	m_csx512State->State[5] += IntegerTools::LeBytesTo32(Code, 4);
	m_csx512State->State[6] += IntegerTools::LeBytesTo32(Code, 8);
	m_csx512State->State[7] += IntegerTools::LeBytesTo32(Code, 12);
}

void CSX512::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
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
		std::vector<uint> tmpCtr(NONCE_SIZE);

		ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			std::array<uint, 2> thdCtr;
			// offset counter by chunk size / block size
			IntegerTools::LeIncreaseW(m_csx512State->Nonce, thdCtr, CTRLEN * i);
			// create random at offset position
			this->Generate(m_csx512State, Output, OutOffset + (i * CNKLEN), thdCtr, CNKLEN);
			// xor with input at offset
			MemoryTools::XOR(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(uint));
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpCtr, 0, m_csx512State->Nonce, 0, NONCE_SIZE * sizeof(uint));

		// last block processing
		if (RNDLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN % RNDLEN;
			Generate(m_csx512State, Output, RNDLEN, m_csx512State->Nonce, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[i + OutOffset + RNDLEN] ^= static_cast<byte>(Input[i + InOffset + RNDLEN]);
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
