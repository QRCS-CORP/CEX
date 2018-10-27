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

//~~~Constructor~~~//

ChaCha512::ChaCha512(StreamAuthenticators Authenticator)
	:
	m_authenticatorType(Authenticator),
	m_cipherState(new ChaCha512State),
	m_distributionCode(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, SALT_SIZE, INFO_SIZE) },
	m_legalRounds(ROUND_COUNT),
	m_macAuthenticator(m_authenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(Authenticator)),
	m_macCounter(0),
	m_macKey(0),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

ChaCha512::~ChaCha512()
{
	if (!m_isDestroyed)
	{
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

		IntUtils::ClearVector(m_distributionCode);
		IntUtils::ClearVector(m_legalKeySizes);
		IntUtils::ClearVector(m_legalRounds);
		IntUtils::ClearVector(m_macKey);
	}
}

//~~~Accessors~~~//

const size_t ChaCha512::BlockSize()
{
	return BLOCK_SIZE;
}

const std::vector<byte> &ChaCha512::DistributionCode()
{
	return m_distributionCode;
}

const size_t ChaCha512::DistributionCodeMax()
{
	return INFO_SIZE;
}

const StreamCiphers ChaCha512::Enumeral()
{
	return StreamCiphers::ChaCha512;
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

const std::vector<size_t> &ChaCha512::LegalRounds()
{
	return m_legalRounds;
}

const std::string ChaCha512::Name()
{
#if defined(CEX_CHACHA512_STRONG)
	return CLASS_NAME + "P80";
#else
	return CLASS_NAME + "P40";
#endif
}

const size_t ChaCha512::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ChaCha512::ParallelProfile()
{
	return m_parallelProfile;
}

const size_t ChaCha512::Rounds()
{
	return ROUND_COUNT;
}

const size_t ChaCha512::TagSize()
{
	return m_macAuthenticator != nullptr ? m_macAuthenticator->MacSize() : 0;
}

//~~~Public Functions~~~//

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

	// generate the mac code
	std::vector<byte> code(m_macAuthenticator->MacSize());
	m_macAuthenticator->Finalize(code, 0);
	MemUtils::Copy(code, 0, Output, OutOffset, code.size() < Length ? code.size() : Length);

	// customization string is CSX512+counter
	std::vector<byte> cst(CSHAKE_CUST.size() + sizeof(ulong));
	MemUtils::Copy(CSHAKE_CUST, 0, cst, 0, CSHAKE_CUST.size());
	IntUtils::Le64ToBytes(m_macCounter, cst, CSHAKE_CUST.size());

	// extract the new mac key
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(m_macKey, cst);
	gen.Generate(m_macKey);

	// re-initialize the authenticator
	Key::Symmetric::SymmetricKey sk(m_macKey);
	m_macAuthenticator->Initialize(sk);
}

void ChaCha512::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (KeyParams.Key().size() != KEY_SIZE)
	{
		throw CryptoSymmetricCipherException("ChaCha256:Initialize", "Key must be 32 bytes!");
	}
	if (KeyParams.Info().size() > INFO_SIZE)
	{
		throw CryptoSymmetricCipherException("ChaCha256:Initialize", "The distribution code must be no larger than DistributionCodeMax!");
	}
	if (KeyParams.Nonce().size() != 0 && KeyParams.Nonce().size() < SALT_SIZE)
	{
		throw CryptoSymmetricCipherException("ChaCha256:Initialize", "The nonce should be either zero or at least 16 bytes!");
	}

	// reset the counter and mac
	m_cipherState->Reset();

	if (KeyParams.Info().size() != 0)
	{
		// custom code
		MemUtils::Copy(KeyParams.Info(), 0, m_distributionCode, 0, (KeyParams.Info().size() > m_distributionCode.size()) ? m_distributionCode.size() : KeyParams.Info().size());
	}

	if (m_authenticatorType == StreamAuthenticators::None)
	{
		// add key and nonce to state
		Expand(KeyParams.Key());
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
		Kdf::SHAKE kdf(Enumeration::ShakeModes::SHAKE256);
		kdf.Initialize(KeyParams.Key(), cst);

		// generate the new cipher key
		std::vector<byte> ck(KEY_SIZE);
		kdf.Generate(ck);

		// expand round keys
		Expand(ck);

		// generate the mac seed
		m_macKey.resize(m_macAuthenticator->LegalKeySizes()[1].KeySize());
		kdf.Generate(m_macKey);
		Key::Symmetric::SymmetricKey sk(m_macKey);
		m_macAuthenticator->Initialize(sk);
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ChaCha512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
	{
		throw CryptoSymmetricCipherException("ChaCha512:ParallelMaxDegree", "Parallel degree can not be zero!");
	}
	if (Degree % 2 != 0)
	{
		throw CryptoSymmetricCipherException("ChaCha512:ParallelMaxDegree", "Parallel degree must be an even number!");
	}
	if (Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricCipherException("ChaCha512:ParallelMaxDegree", "Parallel degree can not exceed processor count!");
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void ChaCha512::Reset()
{
	m_macCounter = 0;
	m_isInitialized = false;
	m_cipherState->Reset();
}

void ChaCha512::TransformBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Process(Input, 0, Output, 0, BLOCK_SIZE);
}

void ChaCha512::TransformBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Process(Input, InOffset, Output, OutOffset, BLOCK_SIZE);
}

void ChaCha512::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	Process(Input, InOffset, Output, OutOffset, Length);
}

//~~~Private Functions~~~//

void ChaCha512::Expand(const std::vector<byte> &Key)
{
	MemUtils::Copy(Key, 0, m_cipherState->S, 0, STATE_SIZE * sizeof(uint));
	MemUtils::Copy(Key, STATE_SIZE * sizeof(uint), m_cipherState->C, 0, NONCE_SIZE * sizeof(uint));

	if (m_distributionCode.size() == INFO_SIZE)
	{
		m_cipherState->S[4] += IntUtils::LeBytesTo32(m_distributionCode, 0);
		m_cipherState->S[5] += IntUtils::LeBytesTo32(m_distributionCode, 4);
		m_cipherState->S[6] += IntUtils::LeBytesTo32(m_distributionCode, 8);
		m_cipherState->S[7] += IntUtils::LeBytesTo32(m_distributionCode, 12);
	}
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

	if (m_authenticatorType != StreamAuthenticators::None && !m_isEncryption)
	{
		m_macAuthenticator->Update(Input, InOffset, Length);
		m_macCounter += Length;
	}

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(Output, OutOffset, m_cipherState->C, PRCLEN);
		// output is input xor random
		const size_t ALNLEN = PRCLEN - (PRCLEN % BLOCK_SIZE);

		if (ALNLEN != 0)
		{
			MemUtils::XorBlock(Input, InOffset, Output, OutOffset, ALNLEN);
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
			MemUtils::XorBlock(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
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

	if (m_authenticatorType != StreamAuthenticators::None && m_isEncryption)
	{
		m_macAuthenticator->Update(Output, OutOffset, Length);
		m_macCounter += Length;
	}
}

NAMESPACE_STREAMEND
