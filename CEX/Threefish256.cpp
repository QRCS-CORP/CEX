#include "Threefish256.h"
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

const std::string Threefish256::CLASS_NAME("Threefish256");
const std::vector<byte> Threefish256::OMEGA_INFO = { 0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73, 0x68, 0x50, 0x32, 0x35, 0x36, 0x52, 0x37, 0x32 };

struct Threefish256::Threefish256State
{
	// counter
	std::array<ulong, 2> C;
	// key
	std::array<ulong, 4> K;
	// tweak
	std::array<ulong, 2> T;

	Threefish256State()
	{
		Reset();
	}

	void Reset()
	{
		// 128 bits of counter
		MemoryTools::Clear(C, 0, C.size() * sizeof(ulong));
		MemoryTools::Clear(K, 0, K.size() * sizeof(ulong));
		MemoryTools::Clear(T, 0, T.size() * sizeof(ulong));
	}
};

//~~~Constructor~~~//

Threefish256::Threefish256(StreamAuthenticators AuthenticatorType)
	:
	m_authenticatorType(AuthenticatorType != StreamAuthenticators::HMACSHA512 && AuthenticatorType != StreamAuthenticators::KMAC512 && AuthenticatorType != StreamAuthenticators::KMAC1024 ? AuthenticatorType :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The authenticator must be a 256 MAC function!"), ErrorCodes::IllegalOperation)),
	m_cipherState(new Threefish256State),
	m_shakeCustom(0),
	m_isAuthenticated(AuthenticatorType != StreamAuthenticators::None),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, NONCE_SIZE * sizeof(ulong), INFO_SIZE) },
	m_macAuthenticator(m_authenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_macCounter(0),
	m_macKey(0),
	m_macTag(0),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

Threefish256::~Threefish256()
{
	if (!m_isDestroyed)
	{
		m_authenticatorType = StreamAuthenticators::None;
		m_isAuthenticated = false;
		m_isDestroyed = true;
		m_isInitialized = false;
		m_macCounter = 0;

		if (m_cipherState != nullptr)
		{
			m_cipherState->Reset();
			m_cipherState.reset(nullptr);
		}
		if (m_macAuthenticator != nullptr)
		{
			m_macAuthenticator.reset(nullptr);
		}

		IntegerTools::Clear(m_shakeCustom);
		IntegerTools::Clear(m_legalKeySizes);
		IntegerTools::Clear(m_macKey);
		IntegerTools::Clear(m_macTag);
	}
}

//~~~Accessors~~~//

const size_t Threefish256::BlockSize()
{
	return BLOCK_SIZE;
}

const size_t Threefish256::DistributionCodeMax()
{
	return INFO_SIZE;
}

const StreamCiphers Threefish256::Enumeral()
{
	return StreamCiphers::Threefish256;
}

const bool Threefish256::IsAuthenticator()
{
	return m_isAuthenticated;
}

const bool Threefish256::IsInitialized()
{
	return m_isInitialized;
}

const bool Threefish256::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &Threefish256::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string Threefish256::Name()
{
	std::string name;

	switch (m_authenticatorType)
	{
		case StreamAuthenticators::HMACSHA256:
		{
			name = CLASS_NAME + "-HMAC-SHA256";
			break;
		}
		case StreamAuthenticators::HMACSHA512:
		{
			name = CLASS_NAME + "-HMAC-SHA512";
			break;
		}
		case StreamAuthenticators::KMAC256:
		{
			name = CLASS_NAME + "-KMAC256";
			break;
		}
		case StreamAuthenticators::KMAC512:
		{
			name = CLASS_NAME + "-KMAC512";
			break;
		}
		case StreamAuthenticators::KMAC1024:
		{
			name = CLASS_NAME + "-KMAC1024";
			break;
		}
		default:
		{
			name = CLASS_NAME;
		}
	}

	return name;
}

const size_t Threefish256::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &Threefish256::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> &Threefish256::Tag()
{
	return m_macTag;
}

const size_t Threefish256::TagSize()
{
	return m_macAuthenticator != nullptr ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void Threefish256::Authenticator(StreamAuthenticators AuthenticatorType)
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}

	if (AuthenticatorType != StreamAuthenticators::None)
	{
		m_macAuthenticator.reset(Helper::MacFromName::GetInstance(AuthenticatorType));
	}

	m_authenticatorType = AuthenticatorType;
}

void Threefish256::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.Key().size() != KEY_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
	if (Parameters.Nonce().size() != (NONCE_SIZE * sizeof(ulong)))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Nonce must be 16 bytes!"), ErrorCodes::InvalidNonce);
	}
	if (Parameters.Info().size() > 0 && Parameters.Info().size() != INFO_SIZE)
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
	Reset();

	// copy nonce
	m_cipherState->C[0] = IntegerTools::LeBytesTo64(Parameters.Nonce(), 0);
	m_cipherState->C[1] = IntegerTools::LeBytesTo64(Parameters.Nonce(), 8);

	if (Parameters.Info().size() != 0)
	{
		// custom code
		m_cipherState->T[0] = IntegerTools::LeBytesTo64(Parameters.Info(), 0);
		m_cipherState->T[1] = IntegerTools::LeBytesTo64(Parameters.Info(), 8);
	}
	else
	{
		// default tweak
		m_cipherState->T[0] = IntegerTools::LeBytesTo64(OMEGA_INFO, 0);
		m_cipherState->T[1] = IntegerTools::LeBytesTo64(OMEGA_INFO, 8);
	}

	if (m_authenticatorType == StreamAuthenticators::None)
	{
		m_cipherState->K[0] = IntegerTools::LeBytesTo64(Parameters.Key(), 0);
		m_cipherState->K[1] = IntegerTools::LeBytesTo64(Parameters.Key(), 8);
		m_cipherState->K[2] = IntegerTools::LeBytesTo64(Parameters.Key(), 16);
		m_cipherState->K[3] = IntegerTools::LeBytesTo64(Parameters.Key(), 24);
	}
	else
	{
		// set the initial counter value
		m_macCounter = 1;

		// create the cSHAKE customization string
		m_shakeCustom.resize(sizeof(ulong) + Name().size());
		// add mac counter and algorithm name to customization string
		IntegerTools::Le64ToBytes(m_macCounter, m_shakeCustom, 0);
		MemoryTools::Copy(Name(), 0, m_shakeCustom, sizeof(ulong), Name().size());

		// initialize cSHAKE
		SHAKE gen(ShakeModes::SHAKE256);
		gen.Initialize(Parameters.Key(), m_shakeCustom);
		// generate the new cipher key
		std::vector<byte> ck(KEY_SIZE);
		gen.Generate(ck);

		// copy key to state
		m_cipherState->K[0] = IntegerTools::LeBytesTo64(ck, 0);
		m_cipherState->K[1] = IntegerTools::LeBytesTo64(ck, 8);
		m_cipherState->K[2] = IntegerTools::LeBytesTo64(ck, 16);
		m_cipherState->K[3] = IntegerTools::LeBytesTo64(ck, 24);

		// generate the mac key
		std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
		gen.Generate(mack);
		// initailize the mac
		m_macAuthenticator->Initialize(SymmetricKey(mack));
		// store the key
		m_macKey = LockClear(mack);
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void Threefish256::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void Threefish256::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}

	// update the authenticator
	m_macAuthenticator->Update(Input, Offset, Length);
}

void Threefish256::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (m_isEncryption)
	{
		if (m_isAuthenticated)
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_cipherState->C[0]), 0, sizeof(ulong));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_cipherState->C[1]), 0, sizeof(ulong));
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_macCounter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_macTag, 0, m_macTag.size());
			MemoryTools::Copy(m_macTag, 0, Output, OutOffset + Length, m_macTag.size());
		}
		else
		{
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		if (m_isAuthenticated)
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_cipherState->C[0]), 0, sizeof(ulong));
			m_macAuthenticator->Update(IntegerTools::Le64ToBytes<std::vector<byte>>(m_cipherState->C[1]), 0, sizeof(ulong));
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_macCounter += Length;
			// finalize the mac and verify
			Finalize(m_macTag, 0, m_macTag.size());

			if (!IntegerTools::Compare(Input, InOffset + Length, m_macTag, 0, m_macTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void Threefish256::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricException(Name(), std::string("Finalize"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricException(Name(), std::string("Finalize"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}
	if (Length > m_macAuthenticator->TagSize())
	{
		throw CryptoSymmetricException(Name(), std::string("Finalize"), std::string("The MAC code specified is longer than the maximum length!"), ErrorCodes::InvalidParam);
	}

	// generate the mac code
	std::vector<byte> code(m_macAuthenticator->TagSize());
	m_macAuthenticator->Finalize(code, 0);
	MemoryTools::Copy(code, 0, Output, OutOffset, code.size() < Length ? code.size() : Length);

	// customization string is: mac counter + algorithm name
	IntegerTools::Le64ToBytes(m_macCounter, m_shakeCustom, 0);

	// extract the new mac key
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(UnlockClear(m_macKey), m_shakeCustom);
	std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
	gen.Generate(mack);
	// reset the generator with the new key
	m_macAuthenticator->Initialize(SymmetricKey(mack));
	// store the key
	m_macKey = LockClear(mack);
}

void Threefish256::Generate(std::array<ulong, 2> &Counter, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
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
			Threefish::PemuteP4x512H(m_cipherState->K, ctr16, m_cipherState->T, tmp32, ROUND_COUNT);
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
			Threefish::PemuteP4x256H(m_cipherState->K, ctr8, m_cipherState->T, tmp16, ROUND_COUNT);
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
		Threefish::PemuteP256C(m_cipherState->K, Counter, m_cipherState->T, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR72P256U(m_cipherState->K, Counter, m_cipherState->T, tmp);
#endif
		MemoryTools::Copy(tmp, 0, Output, OutOffset + ctr, BLOCK_SIZE);
		IntegerTools::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP256C(m_cipherState->K, Counter, m_cipherState->T, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR72P256U(m_cipherState->K, Counter, m_cipherState->T, tmp);
#endif
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(tmp, 0, Output, OutOffset + ctr, FNLLEN);
		IntegerTools::LeIncrementW(Counter);
	}
}

void Threefish256::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t PRCLEN = Length;

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(m_cipherState->C, Output, OutOffset, PRCLEN);
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
			IntegerTools::LeIncreaseW(m_cipherState->C, thdCtr, (CTROFT * i));
			// create random at offset position
			this->Generate(thdCtr, Output, OutOffset + (i * CNKLEN), CNKLEN);
			// xor with input at offset
			MemoryTools::XOR(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(ulong));
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpCtr, 0, m_cipherState->C, 0, NONCE_SIZE * sizeof(ulong));

		// last block processing
		if (RNDLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN % RNDLEN;
			Generate(m_cipherState->C, Output, RNDLEN, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[i + OutOffset + RNDLEN] ^= Input[i + InOffset + RNDLEN];
			}
		}
	}
}

void Threefish256::Reset()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator->Reset();
		m_macTag.resize(m_macAuthenticator->TagSize());
	}

	m_isInitialized = false;
	m_cipherState->Reset();
}

NAMESPACE_STREAMEND
