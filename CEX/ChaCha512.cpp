#include "ChaCha512.h"
#include "ChaCha.h"
#include "IntUtils.h"
#include "MacFromName.h"
#include "MemUtils.h"
#include "ParallelUtils.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

#if defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_STREAM

using Utility::IntUtils;
using Utility::MemUtils;
using Utility::ParallelUtils;

struct ChaCha512::ChaCha512State
{
	// counter
	std::array<uint, 2> C;
	// state
	std::array<uint, 14> S;

	ChaCha512State()
	{
		Reset();
	}

	void Reset()
	{
		// 128 bits of counter
		C[0] = 0;
		C[1] = 0;
		MemUtils::Clear(C, 0, C.size() * sizeof(uint));
		MemUtils::Clear(S, 0, S.size() * sizeof(uint));
	}
};

const std::string ChaCha512::CLASS_NAME("ChaCha512");
const std::vector<byte> ChaCha512::CSHAKE_CUST = { 0x43, 0x53, 0x58, 0x35, 0x31, 0x32 };
const std::vector<byte> ChaCha512::SIGMA_INFO = { 0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x36, 0x34, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B };

//~~~Constructor~~~//

ChaCha512::ChaCha512(StreamAuthenticators AuthenticatorType)
	:
	m_authenticatorType(AuthenticatorType),
	m_cipherState(new ChaCha512State),
	m_isAuthenticated(AuthenticatorType != StreamAuthenticators::None),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, 0, INFO_SIZE) },
	m_macAuthenticator(m_authenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_macCounter(0),
	m_macKey(nullptr),
	m_macTag(0),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

ChaCha512::~ChaCha512()
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
		if (m_macKey != nullptr)
		{
			m_macKey.reset(nullptr);
		}
		if (m_macAuthenticator != nullptr)
		{
			m_macAuthenticator.reset(nullptr);
		}

		IntUtils::ClearVector(m_legalKeySizes);
		IntUtils::ClearVector(m_macTag);
	}
}

//~~~Accessors~~~//

const size_t ChaCha512::BlockSize()
{
	return BLOCK_SIZE;
}

const size_t ChaCha512::DistributionCodeMax()
{
	return INFO_SIZE;
}

const StreamCiphers ChaCha512::Enumeral()
{
	return StreamCiphers::ChaCha512;
}

const bool ChaCha512::IsAuthenticator()
{
	return m_isAuthenticated;
}

const bool ChaCha512::IsInitialized()
{
	return m_isInitialized;
}

const bool ChaCha512::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &ChaCha512::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string ChaCha512::Name()
{
	std::string tmp = CLASS_NAME;

#if defined(CEX_CHACHA512_STRONG)
	tmp += "P80";
#else
	tmp += "P40";
#endif

	switch (m_authenticatorType)
	{
		case StreamAuthenticators::HMACSHA256:
		{
			tmp += "-HMACSHA256";
			break;
		}
		case StreamAuthenticators::HMACSHA512:
		{
			tmp += "-HMACSHA512";
			break;
		}
		case StreamAuthenticators::KMAC256:
		{
			tmp += "-KMAC256";
			break;
		}
		case StreamAuthenticators::KMAC512:
		{
			tmp += "-KMAC512";
			break;
		}
		default:
		{
			tmp += "-KMAC1024";
			break;
		}
	}

	return tmp;
}

const size_t ChaCha512::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ChaCha512::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> &ChaCha512::Tag()
{
	return m_macTag;
}

const size_t ChaCha512::TagSize()
{
	return m_macAuthenticator != nullptr ? m_macAuthenticator->MacSize() : 0;
}

//~~~Public Functions~~~//

void ChaCha512::Authenticator(StreamAuthenticators AuthenticatorType)
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

void ChaCha512::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (KeyParams.Key().size() != KEY_SIZE)
	{
		throw CryptoSymmetricCipherException("ChaCha512:Initialize", "The key must be 64 bytes!");
	}
	if (KeyParams.Nonce().size() != 0)
	{
		throw CryptoSymmetricCipherException("ChaCha512:Initialize", "The nonce is not required with ChaCha512!");
	}
	if (KeyParams.Info().size() > 0 && KeyParams.Info().size() != INFO_SIZE)
	{
		throw CryptoSymmetricCipherException("ChaCha512:Initialize", "The distribution code must be no larger than DistributionCodeMax!");
	}

	// reset the counter and mac
	Reset();

	std::vector<byte> code(INFO_SIZE);

	if (KeyParams.Info().size() != 0)
	{
		// custom code
		MemUtils::Copy(KeyParams.Info(), 0, code, 0, KeyParams.Info().size());
	}
	else
	{
		// standard
		MemUtils::Copy(SIGMA_INFO, 0, code, 0, SIGMA_INFO.size());
	}

	if (m_authenticatorType == StreamAuthenticators::None)
	{
		// add key and nonce to state
		Expand(KeyParams.Key(), code);
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

		// expand round keys
		Expand(ck, code);

		// generate the mac key
		std::vector<byte> mk(m_macAuthenticator->LegalKeySizes()[1].KeySize());
		gen.Generate(mk);
		m_macKey.reset(new SymmetricSecureKey(mk));
		m_macAuthenticator->Initialize(*m_macKey.get());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ChaCha512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricCipherException("ChaCha512:ParallelMaxDegree", "Degree setting is invalid!");
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void ChaCha512::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException("ChaCha512:Finalize", "The cipher has not been initialized!");
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricCipherException("ChaCha512:Finalize", "The cipher has not been configured for authentication!");
	}

	// update the authenticator
	m_macAuthenticator->Update(Input, Offset, Length);
}

void ChaCha512::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	Process(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Functions~~~//

void ChaCha512::Expand(const std::vector<byte> &Key, const std::vector<byte> &Code)
{
#if defined(CEX_IS_LITTLE_ENDIAN)
	MemUtils::Copy(Key, 0, m_cipherState->S, 0, STATE_SIZE * sizeof(uint));
	MemUtils::Copy(Key, STATE_SIZE * sizeof(uint), m_cipherState->C, 0, NONCE_SIZE * sizeof(uint));
#else
	m_cipherState->S[0] = IntUtils::LeBytesTo32(Key, 0);
	m_cipherState->S[1] = IntUtils::LeBytesTo32(Key, 4);
	m_cipherState->S[2] = IntUtils::LeBytesTo32(Key, 8);
	m_cipherState->S[3] = IntUtils::LeBytesTo32(Key, 12);
	m_cipherState->S[4] = IntUtils::LeBytesTo32(Key, 16);
	m_cipherState->S[5] = IntUtils::LeBytesTo32(Key, 20);
	m_cipherState->S[6] = IntUtils::LeBytesTo32(Key, 24);
	m_cipherState->S[7] = IntUtils::LeBytesTo32(Key, 28);
	m_cipherState->S[8] = IntUtils::LeBytesTo32(Key, 32);
	m_cipherState->S[9] = IntUtils::LeBytesTo32(Key, 36);
	m_cipherState->S[10] = IntUtils::LeBytesTo32(Key, 40);
	m_cipherState->S[11] = IntUtils::LeBytesTo32(Key, 44);
	m_cipherState->S[12] = IntUtils::LeBytesTo32(Key, 48);
	m_cipherState->S[13] = IntUtils::LeBytesTo32(Key, 52);
	m_cipherState->C[0] = IntUtils::LeBytesTo32(Key, 56);
	m_cipherState->C[1] = IntUtils::LeBytesTo32(Key, 60);
#endif

	m_cipherState->S[4] += IntUtils::LeBytesTo32(Code, 0);
	m_cipherState->S[5] += IntUtils::LeBytesTo32(Code, 4);
	m_cipherState->S[6] += IntUtils::LeBytesTo32(Code, 8);
	m_cipherState->S[7] += IntUtils::LeBytesTo32(Code, 12);
}

void ChaCha512::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException("ChaCha512:Finalize", "The cipher has not been initialized!");
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricCipherException("ChaCha512:Finalize", "The cipher has not been configured for authentication!");
	}
	if (Length > m_macAuthenticator->MacSize())
	{
		throw CryptoSymmetricCipherException("ChaCha512:Finalize", "The MAC code specified is longer than the maximum length!");
	}

	// generate the mac code
	std::vector<byte> code(m_macAuthenticator->MacSize());
	m_macAuthenticator->Finalize(code, 0);
	MemUtils::Copy(code, 0, Output, OutOffset, code.size() < Length ? code.size() : Length);

	// customization string is CSX512+counter
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

void ChaCha512::Generate(std::vector<byte> &Output, const size_t OutOffset, std::array<uint, 2> &Counter, const size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(__AVX512__)

	const size_t AVX512BLK = 16 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<uint, 32> ctrBlk;

		// process 8 blocks (uses avx if available)
		while (ctr != SEGALN)
		{
			MemUtils::Copy(Counter, 0, ctrBlk, 0, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 16, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 1, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 17, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 2, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 18, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 3, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 19, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 4, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 20, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 5, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 21, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 6, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 22, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 7, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 23, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 8, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 24, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 9, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 25, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 10, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 26, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 11, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 27, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 12, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 28, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 13, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 29, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 14, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 30, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 15, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 31, 4);
			IntUtils::LeIncrementW(Counter);
			ChaCha::PermuteP16x512H(Output, OutOffset + ctr, ctrBlk, m_cipherState->S, ROUND_COUNT);
			ctr += AVX512BLK;
		}
	}

#elif defined(__AVX2__)

	const size_t AVX2BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<uint, 16> ctrBlk;

		// process 8 blocks (uses avx if available)
		while (ctr != SEGALN)
		{
			MemUtils::Copy(Counter, 0, ctrBlk, 0, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 8, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 1, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 9, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 2, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 10, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 3, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 11, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 4, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 12, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 5, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 13, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 6, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 14, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 7, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 15, 4);
			IntUtils::LeIncrementW(Counter);
			ChaCha::PermuteP8x512H(Output, OutOffset + ctr, ctrBlk, m_cipherState->S, ROUND_COUNT);
			ctr += AVX2BLK;
		}
	}

#elif defined(__AVX__)

	const size_t AVXBLK = 4 * BLOCK_SIZE;

	if (Length >= AVXBLK)
	{
		const size_t SEGALN = Length - (Length % AVXBLK);
		std::array<uint, 8> ctrBlk;

		// process 4 blocks (uses sse intrinsics if available)
		while (ctr != SEGALN)
		{
			MemUtils::Copy(Counter, 0, ctrBlk, 0, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 4, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 1, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 5, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 2, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 6, 4);
			IntUtils::LeIncrementW(Counter);
			MemUtils::Copy(Counter, 0, ctrBlk, 3, 4);
			MemUtils::Copy(Counter, 1, ctrBlk, 7, 4);
			IntUtils::LeIncrementW(Counter);
			ChaCha::PermuteP4x512H(Output, OutOffset + ctr, ctrBlk, m_cipherState->S, ROUND_COUNT);
			ctr += AVXBLK;
		}
	}
#endif

	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	while (ctr != ALNLEN)
	{
		ChaCha::PermuteP512C(Output, OutOffset + ctr, Counter, m_cipherState->S, ROUND_COUNT);
		IntUtils::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<byte> otp(BLOCK_SIZE, 0);
		ChaCha::PermuteP512C(otp, 0, Counter, m_cipherState->S, ROUND_COUNT);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemUtils::Copy(otp, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
		IntUtils::LeIncrementW(Counter);
	}
}

void ChaCha512::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t PRCLEN = (Length >= Input.size() - InOffset) && Length >= Output.size() - OutOffset ? IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) : Length;

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(Output, OutOffset, m_cipherState->C, PRCLEN);
		// output is input xor random
		const size_t ALNLEN = PRCLEN - (PRCLEN % BLOCK_SIZE);

		if (ALNLEN != 0)
		{
			MemUtils::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
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

		ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			std::array<uint, 2> thdCtr;
			// offset counter by chunk size / block size
			IntUtils::LeIncreaseW(m_cipherState->C, thdCtr, CTRLEN * i);
			// create random at offset position
			this->Generate(Output, OutOffset + (i * CNKLEN), thdCtr, CNKLEN);
			// xor with input at offset
			MemUtils::XOR(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemUtils::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(uint));
			}
		});

		// copy last counter to class variable
		MemUtils::Copy(tmpCtr, 0, m_cipherState->C, 0, NONCE_SIZE * sizeof(uint));

		// last block processing
		if (RNDLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN % RNDLEN;
			Generate(Output, RNDLEN, m_cipherState->C, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[i + OutOffset + RNDLEN] ^= static_cast<byte>(Input[i + InOffset + RNDLEN]);
			}
		}
	}

	if (m_isAuthenticated)
	{
		m_macCounter += Length;

		if (m_isEncryption)
		{
			m_macAuthenticator->Update(Output, OutOffset, Length);
			m_macAuthenticator->Update(IntUtils::Le64ToBytes<std::vector<byte>>(m_cipherState->C[0]), 0, sizeof(uint));
			m_macAuthenticator->Update(IntUtils::Le64ToBytes<std::vector<byte>>(m_cipherState->C[1]), 0, sizeof(uint));

			Finalize(m_macTag, 0, m_macTag.size());
			MemUtils::Copy(m_macTag, 0, Output, OutOffset + Length, m_macTag.size());
		}
		else
		{
			m_macAuthenticator->Update(Input, InOffset, Length);
			m_macAuthenticator->Update(IntUtils::Le64ToBytes<std::vector<byte>>(m_cipherState->C[0]), 0, sizeof(uint));
			m_macAuthenticator->Update(IntUtils::Le64ToBytes<std::vector<byte>>(m_cipherState->C[1]), 0, sizeof(uint));

			Finalize(m_macTag, 0, m_macTag.size());

			if (!IntUtils::Compare(Input, InOffset + Length, m_macTag, 0, m_macTag.size()))
			{
				throw CryptoAuthenticationFailure("ChaCha512:Process", "The authentication tag does not match!");
			}
		}
	}
}

void ChaCha512::Reset()
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
