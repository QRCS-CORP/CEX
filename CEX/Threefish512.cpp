#include "Threefish512.h"
#include "IntUtils.h"
#include "MacFromName.h"
#include "MemUtils.h"
#include "ParallelUtils.h"
#include "SHAKE.h"
#include "SymmetricKey.h"
#include "Threefish.h"

#if defined(__AVX2__)
#	include "ULong256.h"
#elif defined(__AVX__)
#	include "ULong128.h"
#endif

NAMESPACE_STREAM

using Utility::IntUtils;
using Utility::MemUtils;
using Utility::ParallelUtils;

const std::string Threefish512::CLASS_NAME("Threefish512");
const std::vector<byte> Threefish512::CSHAKE_CUST = { 0x54, 0x53, 0x58, 0x35, 0x31, 0x32 };
const std::vector<byte> Threefish512::OMEGA_INFO = { 0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73, 0x68, 0x50, 0x35, 0x31, 0x32, 0x52, 0x39, 0x36 };

struct Threefish512::Threefish512State
{
	// counter
	std::array<ulong, 2> C;
	// key
	std::array<ulong, 8> K;
	// tweak
	std::array<ulong, 2> T;

	Threefish512State()
	{
		Reset();
	}

	void Reset()
	{
		// 128 bits of counter
		C[0] = 0;
		C[1] = 0;
		MemUtils::Clear(K, 0, K.size() * sizeof(ulong));
		MemUtils::Clear(T, 0, T.size() * sizeof(ulong));
	}
};

//~~~Constructor~~~//

Threefish512::Threefish512(StreamAuthenticators AuthenticatorType)
	:
	m_authenticatorType(AuthenticatorType != StreamAuthenticators::KMAC1024 ? AuthenticatorType :
		throw CryptoSymmetricCipherException("Threefish512:CTor", "The authenticator must be a 256 or 512-bit MAC function!")),
	m_cipherState(new Threefish512State),
	m_isAuthenticated(AuthenticatorType != StreamAuthenticators::None),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, NONCE_SIZE * sizeof(ulong), INFO_SIZE) },
	m_macAuthenticator(m_authenticatorType == StreamAuthenticators::None ? nullptr : 
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_macCounter(0),
	m_macKey(nullptr),
	m_macTag(0),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

Threefish512::~Threefish512()
{
	if (!m_isDestroyed)
	{
		m_authenticatorType = StreamAuthenticators::None;
		m_isAuthenticated = false;
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_macCounter = 0;
		m_parallelProfile.Reset(); 

		if (m_cipherState != nullptr)
		{
			m_cipherState->Reset();
			m_cipherState.reset(nullptr);
		}
		if (m_macAuthenticator != nullptr)
		{
			m_macAuthenticator.reset(nullptr);
		}
		if (m_macKey != nullptr)
		{
			m_macKey.reset(nullptr);
		}

		IntUtils::ClearVector(m_legalKeySizes);
		IntUtils::ClearVector(m_macTag);
	}
}

//~~~Accessors~~~//

void Threefish512::Authenticator(StreamAuthenticators AuthenticatorType)
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

const size_t Threefish512::BlockSize()
{
	return BLOCK_SIZE;
}

const size_t Threefish512::DistributionCodeMax()
{
	return INFO_SIZE;
}

const StreamCiphers Threefish512::Enumeral()
{
	return StreamCiphers::Threefish512;
}

const bool Threefish512::IsAuthenticator()
{
	return m_isAuthenticated;
}

const bool Threefish512::IsInitialized()
{
	return m_isInitialized;
}

const bool Threefish512::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &Threefish512::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string Threefish512::Name()
{
	switch (m_authenticatorType)
	{
		case StreamAuthenticators::HMACSHA256:
		{
			return CLASS_NAME + "-HMACSHA256";
		}
		case StreamAuthenticators::HMACSHA512:
		{
			return CLASS_NAME + "-HMACSHA512";
		}
		case StreamAuthenticators::KMAC256:
		{
			return CLASS_NAME + "-KMAC256";
		}
		case StreamAuthenticators::KMAC512:
		{
			return CLASS_NAME + "-KMAC512";
		}
		case StreamAuthenticators::KMAC1024:
		{
			return CLASS_NAME + "-KMAC1024";
		}
		default:
		{
			return CLASS_NAME;
		}
	}
}

const size_t Threefish512::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &Threefish512::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> &Threefish512::Tag()
{
	return m_macTag;
}

const size_t Threefish512::TagSize()
{
	return m_macAuthenticator != nullptr ? m_macAuthenticator->MacSize() : 0;
}

//~~~Public Functions~~~//

void Threefish512::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (KeyParams.Key().size() != KEY_SIZE)
	{
		throw CryptoSymmetricCipherException("Threefish512:Initialize", "Key must be 64 bytes!");
	}
	if (KeyParams.Nonce().size() != (NONCE_SIZE * sizeof(ulong)))
	{
		throw CryptoSymmetricCipherException("Threefish512:Initialize", "Nonce must be 16 bytes!");
	}
	if (KeyParams.Info().size() > 0 && KeyParams.Info().size() > INFO_SIZE)
	{
		throw CryptoSymmetricCipherException("Threefish512:Initialize", "Info must be no more than 16 bytes!");
	}

	if (m_parallelProfile.IsParallel())
	{
		if (m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoSymmetricCipherException("Threefish512:Initialize", "The parallel profile block sizes are misconfigured!");
		}
		if (m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoSymmetricCipherException("Threefish512:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
		}
	}

	// reset the counter and mac
	Reset();

	// copy nonce
	m_cipherState->C[0] = IntUtils::LeBytesTo64(KeyParams.Nonce(), 0);
	m_cipherState->C[1] = IntUtils::LeBytesTo64(KeyParams.Nonce(), 8);

	if (KeyParams.Info().size() != 0)
	{
		// custom code
		m_cipherState->T[0] = IntUtils::LeBytesTo64(KeyParams.Info(), 0);
		m_cipherState->T[1] = IntUtils::LeBytesTo64(KeyParams.Info(), 8);
	}
	else
	{
		// default tweak
		m_cipherState->T[0] = IntUtils::LeBytesTo64(OMEGA_INFO, 0);
		m_cipherState->T[1] = IntUtils::LeBytesTo64(OMEGA_INFO, 8);
	}

	if (m_authenticatorType == StreamAuthenticators::None)
	{
		m_cipherState->K[0] = IntUtils::LeBytesTo64(KeyParams.Key(), 0);
		m_cipherState->K[1] = IntUtils::LeBytesTo64(KeyParams.Key(), 8);
		m_cipherState->K[2] = IntUtils::LeBytesTo64(KeyParams.Key(), 16);
		m_cipherState->K[3] = IntUtils::LeBytesTo64(KeyParams.Key(), 24);
		m_cipherState->K[4] = IntUtils::LeBytesTo64(KeyParams.Key(), 32);
		m_cipherState->K[5] = IntUtils::LeBytesTo64(KeyParams.Key(), 40);
		m_cipherState->K[6] = IntUtils::LeBytesTo64(KeyParams.Key(), 48);
		m_cipherState->K[7] = IntUtils::LeBytesTo64(KeyParams.Key(), 56);
	}
	else
	{
		// set the initial counter value
		m_macCounter = 1;

		// create the cSHAKE customization string
		std::vector<byte> cst(CSHAKE_CUST.size() + sizeof(ulong));
		MemUtils::Copy(CSHAKE_CUST, 0, cst, 0, CSHAKE_CUST.size());
		IntUtils::Le64ToBytes(m_macCounter, cst, CSHAKE_CUST.size());

		// initialize cSHAKE
		Kdf::SHAKE gen(ShakeModes::SHAKE512);
		gen.Initialize(KeyParams.Key(), cst);

		// generate the new cipher key
		std::vector<byte> ck(KEY_SIZE);
		gen.Generate(ck);

		// copy key to state
		m_cipherState->K[0] = IntUtils::LeBytesTo64(ck, 0);
		m_cipherState->K[1] = IntUtils::LeBytesTo64(ck, 8);
		m_cipherState->K[2] = IntUtils::LeBytesTo64(ck, 16);
		m_cipherState->K[3] = IntUtils::LeBytesTo64(ck, 24);
		m_cipherState->K[4] = IntUtils::LeBytesTo64(ck, 32);
		m_cipherState->K[5] = IntUtils::LeBytesTo64(ck, 40);
		m_cipherState->K[6] = IntUtils::LeBytesTo64(ck, 48);
		m_cipherState->K[7] = IntUtils::LeBytesTo64(ck, 56);

		// generate the mac key
		std::vector<byte> mk(m_macAuthenticator->LegalKeySizes()[1].KeySize());
		gen.Generate(mk);
		m_macKey.reset(new SymmetricSecureKey(mk));
		m_macAuthenticator->Initialize(*m_macKey.get());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void Threefish512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricCipherException("Threefish512:ParallelMaxDegree", "Degree setting is invalid!");
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void Threefish512::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException("Threefish512:Finalize", "The cipher has not been initialized!");
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricCipherException("Threefish512:Finalize", "The cipher has not been configured for authentication!");
	}

	// update the authenticator
	m_macAuthenticator->Update(Input, Offset, Length);
}

void Threefish512::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	Process(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Functions~~~//

void Threefish512::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException("Threefish512:Finalize", "The cipher has not been initialized!");
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricCipherException("Threefish512:Finalize", "The cipher has not been configured for authentication!");
	}
	if (Length > m_macAuthenticator->MacSize())
	{
		throw CryptoSymmetricCipherException("Threefish512:Finalize", "The MAC code specified is longer than the maximum length!");
	}

	// generate the mac code
	std::vector<byte> code(m_macAuthenticator->MacSize());
	m_macAuthenticator->Finalize(code, 0);
	MemUtils::Copy(code, 0, Output, OutOffset, code.size() < Length ? code.size() : Length);

	// customization string is TSX512+counter
	std::vector<byte> cst(CSHAKE_CUST.size() + sizeof(ulong));
	MemUtils::Copy(CSHAKE_CUST, 0, cst, 0, CSHAKE_CUST.size());
	IntUtils::Le64ToBytes(m_macCounter, cst, CSHAKE_CUST.size());

	// extract the new mac key
	std::vector<byte> mk(m_macAuthenticator->LegalKeySizes()[1].KeySize());
	Kdf::SHAKE gen(ShakeModes::SHAKE512);
	gen.Initialize(m_macKey->Key(), cst);
	gen.Generate(mk);

	// reset the generator with the new key
	m_macKey.reset(new SymmetricSecureKey(mk));
	m_macAuthenticator->Initialize(*m_macKey.get());
}

void Threefish512::Generate(std::array<ulong, 2> &Counter, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(__AVX512__)

	const size_t AVX512BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<ulong, 16> ctr16;
		std::array<ulong, 64> tmp64;

		// process 8 blocks
		while (ctr != SEGALN)
		{
			MemUtils::Copy(Counter, 0, ctr16, 0, 8);
			MemUtils::Copy(Counter, 1, ctr16, 8, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr16, 1, 8);
			MemUtils::Copy(Counter, 1, ctr16, 9, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr16, 2, 8);
			MemUtils::Copy(Counter, 1, ctr16, 10, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr16, 3, 8);
			MemUtils::Copy(Counter, 1, ctr16, 11, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr16, 4, 8);
			MemUtils::Copy(Counter, 1, ctr16, 12, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr16, 5, 8);
			MemUtils::Copy(Counter, 1, ctr16, 13, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr16, 6, 8);
			MemUtils::Copy(Counter, 1, ctr16, 14, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr16, 7, 8);
			MemUtils::Copy(Counter, 1, ctr16, 15, 8);
			IntUtils::LeIncrementW(Counter);
			Threefish::PemuteP8x512H(m_cipherState->K, ctr16, m_cipherState->T, tmp64, ROUND_COUNT);
			MemUtils::Copy(tmp64, 0, Output, OutOffset + ctr, AVX2BLK);
			ctr += AVX512BLK;
		}
	}

#elif defined(__AVX2__)

	const size_t AVX2BLK = 4 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<ulong, 8> ctr8;
		std::array<ulong, 32> tmp32;

		// process 4 blocks
		while (ctr != SEGALN)
		{
			MemUtils::Copy(Counter, 0, ctr8, 0, 8);
			MemUtils::Copy(Counter, 1, ctr8, 4, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr8, 1, 8);
			MemUtils::Copy(Counter, 1, ctr8, 5, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr8, 2, 8);
			MemUtils::Copy(Counter, 1, ctr8, 6, 8);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctr8, 3, 8);
			MemUtils::Copy(Counter, 1, ctr8, 7, 8);
			IntUtils::LeIncrementW(Counter);
			Threefish::PemuteP4x512H(m_cipherState->K, ctr8, m_cipherState->T, tmp32, ROUND_COUNT);
			MemUtils::Copy(tmp32, 0, Output, OutOffset + ctr, AVX2BLK);
			ctr += AVX2BLK;
		}
	}

#endif

	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	std::array<ulong, 8> tmp;

	while (ctr != ALNLEN)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP512C(m_cipherState->K, Counter, m_cipherState->T, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR96P512U(m_cipherState->K, Counter, m_cipherState->T, tmp);
#endif
		MemUtils::Copy(tmp, 0, Output, OutOffset + ctr, BLOCK_SIZE);
		IntUtils::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
#if defined(CEX_CIPHER_COMPACT)
		Threefish::PemuteP512C(m_cipherState->K, Counter, m_cipherState->T, tmp, ROUND_COUNT);
#else
		Threefish::PemuteR96P512U(m_cipherState->K, Counter, m_cipherState->T, tmp);
#endif
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemUtils::Copy(tmp, 0, Output, OutOffset + ctr, FNLLEN);
		IntUtils::LeIncrementW(Counter);
	}
}

void Threefish512::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
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
			MemUtils::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
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

		ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTROFT](size_t i)
		{
			// thread level counter
			std::array<ulong, NONCE_SIZE> thdCtr;
			// offset counter by chunk size
			IntUtils::LeIncreaseW(m_cipherState->C, thdCtr, (CTROFT * i));
			// create random at offset position
			this->Generate(thdCtr, Output, OutOffset + (i * CNKLEN), CNKLEN);
			// xor with input at offset
			MemUtils::XOR(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemUtils::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(ulong));
			}
		});

		// copy last counter to class variable
		MemUtils::Copy(tmpCtr, 0, m_cipherState->C, 0, NONCE_SIZE * sizeof(ulong));

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

	if (m_isAuthenticated)
	{
		m_macCounter += Length;

		if (m_isEncryption)
		{
			m_macAuthenticator->Update(Output, OutOffset, Length);
			m_macAuthenticator->Update(IntUtils::Le64ToBytes<std::vector<byte>>(m_cipherState->C[0]), 0, sizeof(ulong));
			m_macAuthenticator->Update(IntUtils::Le64ToBytes<std::vector<byte>>(m_cipherState->C[1]), 0, sizeof(ulong));

			Finalize(m_macTag, 0, m_macTag.size());
			MemUtils::Copy(m_macTag, 0, Output, OutOffset + Length, m_macTag.size());
		}
		else
		{
			m_macAuthenticator->Update(Input, InOffset, Length);
			m_macAuthenticator->Update(IntUtils::Le64ToBytes<std::vector<byte>>(m_cipherState->C[0]), 0, sizeof(ulong));
			m_macAuthenticator->Update(IntUtils::Le64ToBytes<std::vector<byte>>(m_cipherState->C[1]), 0, sizeof(ulong));

			Finalize(m_macTag, 0, m_macTag.size());

			if (!IntUtils::Compare(Input, InOffset + Length, m_macTag, 0, m_macTag.size()))
			{
				throw CryptoAuthenticationFailure("Threefish512:Process", "The authentication tag does not match!");
			}
		}
	}
}

void Threefish512::Reset()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator->Reset();
		m_macTag.resize(m_macAuthenticator->MacSize());
	}

	m_isInitialized = false;
	m_cipherState->Reset();
}

NAMESPACE_STREAMEND
