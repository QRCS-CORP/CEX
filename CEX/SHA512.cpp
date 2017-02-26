#include "SHA512.h"
#include "ArrayUtils.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "SHA512Compress.h"
#include "SymmetricKey.h"

NAMESPACE_DIGEST

using Utility::IntUtils;


//~~~Constructor~~~//

SHA512::SHA512(bool Parallel)
	:
	m_hasAvx(false),
	m_iPad(0),
	m_isDestroyed(false),
	m_isHmac(false),
	m_isInitialized(false),
	m_isParallel(Parallel),
	m_leafSize(BLOCK_SIZE),
	m_minParallel(MIN_PRLBLOCK),
	m_msgBuffer(Parallel ? MIN_PRLBLOCK : BLOCK_SIZE, 0),
	m_msgLength(0),
	m_oPad(0),
	m_parallelBlockSize(PRL_BRANCHSIZE * PRL_DEGREE),
	m_State(Parallel ? PRL_DEGREE * ITL_LANESIZE : 1),
	m_treeDestroy(true)
{
	if (m_isParallel)
	{

		DetectCpu();
		// defaults to tree depth(1), parallel degree(4), and subtree(8) branch size
		m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 1, (uint8_t)BLOCK_SIZE, (uint8_t)PRL_DEGREE, (uint8_t)ITL_LANESIZE };
	}
	else
	{
		// fixed values for sequential mode
		m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 0, (uint8_t)BLOCK_SIZE, 0, 0 };
	}

	Initialize(m_State);
}

SHA512::SHA512(SHA2Params &Params)
	:
	m_iPad(0),
	m_isDestroyed(false),
	m_isHmac(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_leafSize(BLOCK_SIZE),
	m_minParallel(Params.ParallelDegree() * ITL_LANESIZE * BLOCK_SIZE),
	m_msgBuffer(Params.ParallelDegree() > 0 ? Params.ParallelDegree() * ITL_LANESIZE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelBlockSize(0),
	m_oPad(0),
	m_State(Params.ParallelDegree() > 0 ? Params.ParallelDegree() * ITL_LANESIZE : 1),
	m_treeDestroy(false),
	m_treeParams(Params)
{
	m_isParallel = Params.ParallelDegree() > 1;

	if (m_isParallel)
	{
		if (Params.LeafLength() != 0 && (Params.LeafLength() < BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE != 0))
			throw CryptoDigestException("SHA512:Ctor", "The LeafLength parameter is invalid! Must be evenly divisible by digest block size.");
		if (Params.ParallelDegree() < 2 || Params.ParallelDegree() % 2 != 0)
			throw CryptoDigestException("SHA512:Ctor", "The ParallelDegree parameter is invalid! Must be an even number greater than 1.");
		if (Params.TreeDepth() > 2)
			throw CryptoDigestException("SHA512:Ctor", "The maximum tree depth is 2; valid range is 0, 1, and 2.");
		if (Params.SubTreeLength() % 2 != 0 || Params.SubTreeLength() < 2 || Params.SubTreeLength() > m_minParallel / BLOCK_SIZE)
			throw CryptoDigestException("SHA512:Ctor", "SubTreeLength must be divisible by two, and no more than minimum parallel divide by block size.");

		DetectCpu();
		m_treeParams = { (uint8_t)DIGEST_SIZE, 0, (uint8_t)(Params.TreeDepth() == 2 ? 2 : 1), (uint8_t)BLOCK_SIZE, Params.ParallelDegree(), Params.SubTreeLength() };
	}
	else
	{
		m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 0, (uint8_t)BLOCK_SIZE, 0, 0 };
	}

	Initialize(m_State);
}

SHA512::~SHA512()
{
	Destroy();
}

//~~~Public Functions~~~//

void SHA512::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (Input.size() < m_minParallel)
		m_isParallel = false;

	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void SHA512::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_hasAvx = false;
		m_isHmac = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_leafSize = 0;
		m_minParallel = 0;
		m_msgLength = 0;
		m_parallelBlockSize = 0;
		m_treeDestroy = false;

		try
		{
			for (size_t i = 0; i < m_State.size(); ++i)
				m_State[i].Reset();

			if (m_treeDestroy)
				m_treeParams.Reset();

			Utility::ArrayUtils::ClearVector(m_iPad);
			Utility::ArrayUtils::ClearVector(m_oPad);
			Utility::ArrayUtils::ClearVector(m_msgBuffer);
			Utility::ArrayUtils::ClearVector(m_State);
		}
		catch (std::exception& ex)
		{
			throw CryptoDigestException("SHA512:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t SHA512::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	if (Output.size() - OutOffset < DigestSize())
		throw CryptoDigestException("SHA512:Finalize", "The Output buffer is too short!");

	// rtm: too small for parallel
	if (!m_isHmac && m_isParallel && m_State[0].T[0] == 0)
	{
		m_isParallel = false;
		size_t len = m_msgLength;
		m_msgLength = 0;
		Update(m_msgBuffer, 0, len);
	}

	if (m_isParallel && !m_isHmac)
	{
		std::vector<byte> leaf(BLOCK_SIZE);

		//  depth 2: hash into intermediate branch states
		if (m_treeParams.TreeDepth() == 2)
		{
			// create the temp state buffers
			std::vector<SHA512State> branchState(m_State.size() / m_treeParams.SubTreeLength());
			Initialize(branchState);

			// compress the leaves into subtree state hashes
			for (size_t i = 0, j = 0; i < m_State.size(); i += 2)
			{
				// no empty block processing
				if (m_State[i].T[0] != 0)
				{
					// copy state as input message block
					memcpy(&leaf[0], &m_State[i].H[0], DIGEST_SIZE);
					memcpy(&leaf[DIGEST_SIZE], &m_State[i + 1].H[0], DIGEST_SIZE);
					SHA512Compress::Compress128(leaf, 0, branchState, j);

					// finalize at subtree boundary
					if (i != 0 && i % m_treeParams.SubTreeLength() == 0)
					{
						// increment node state counter
						m_treeParams.NodeOffset() += 1;
						memcpy(&leaf[0], &m_treeParams.ToBytes()[0], m_treeParams.GetHeaderSize());
						// process the params as final state
						HashFinal(leaf, 0, m_treeParams.GetHeaderSize(), branchState, j++);
					}
				}
			}

			// compress the subtree hashes into root hash
			for (size_t i = 0; i < branchState.size(); i += 2)
			{
				if (branchState[i].T[0] != 0)
				{
					// copy subtree hashes
					memcpy(&leaf[0], &branchState[i].H[0], DIGEST_SIZE);
					memcpy(&leaf[DIGEST_SIZE], &branchState[i + 1].H[0], DIGEST_SIZE);
					// subtree branch hashes are compressed into root state
					SHA512Compress::Compress128(leaf, 0, m_State, 0);
				}
			}
		}
		else
		{
			// depth 1: process state blocks as contiguous input
			for (size_t i = 0; i < m_State.size(); i += 2)
			{
				// skip empty state
				if (m_State[i].T[0] != 0)
				{
					// copy hashes as input blocks
					memcpy(&leaf[0], &m_State[i].H[0], DIGEST_SIZE);
					memcpy(&leaf[DIGEST_SIZE], &m_State[i + 1].H[0], DIGEST_SIZE);
					// compress into root state
					SHA512Compress::Compress128(leaf, 0, m_State, 0);
				}
			}
		}
	}

	// Note: I considered mac on each state in parallel mode, but I'm not sure I see the benefit.
	// If mac is secure, once on last state should be enough(?) this may change at some point..
	if (m_isHmac)
		MacFinal(m_msgBuffer, m_msgLength, m_State, 0);
	else
		HashFinal(m_msgBuffer, 0, m_msgLength, m_State, 0);

	StateToBytes(Output, OutOffset, m_State, 0);
	Reset();

	return DIGEST_SIZE;
}

size_t SHA512::Generate(ISymmetricKey &MacKey, std::vector<uint8_t> &Output)
{
	if (Output.size() > 255 * DIGEST_SIZE)
		throw CryptoDigestException("SHA512:Generate", "Maximum output size is 255 times the digest return size!");

	size_t prcLen = DIGEST_SIZE;
	std::vector<uint8_t> state(DIGEST_SIZE);
	std::vector<byte> prk;

	Extract(MacKey.Key(), MacKey.Nonce(), prk);
	LoadMacKey(Key::Symmetric::SymmetricKey(prk));
	Expand(MacKey.Info(), 0, state);

	if (prcLen < Output.size())
	{
		memcpy(&Output[0], &state[0], DIGEST_SIZE);
		int32_t rmd = (int32_t)(Output.size() - prcLen);

		while (rmd > 0)
		{
			Expand(MacKey.Info(), prcLen, state);

			if (rmd > (int32_t)DIGEST_SIZE)
			{
				memcpy(&Output[prcLen], &state[0], DIGEST_SIZE);
				prcLen += DIGEST_SIZE;
				rmd -= (int32_t)DIGEST_SIZE;
			}
			else
			{
				rmd = (int32_t)(Output.size() - prcLen);
				memcpy(&Output[prcLen], &state[0], rmd);
				rmd = 0;
			}
		}
	}
	else
	{
		memcpy(&Output[0], &state[0], Output.size());
	}

	Reset();
	m_isHmac = false;

	return Output.size();
}

void SHA512::LoadMacKey(ISymmetricKey &MacKey)
{
	if (MacKey.Key().size() < 4)
		throw CryptoDigestException("SHA512:LoadMacKey", "The minimum key size is 4 bytes, key length equal to digest output size is recommended!");

	m_isHmac = true;
	m_treeParams.KeyLength() = (byte)MacKey.Key().size();
	Reset();

	size_t klen = MacKey.Key().size() + MacKey.Nonce().size() + MacKey.Info().size();
	std::vector<byte> key(klen, 0);
	memcpy(&key[0], &MacKey.Key()[0], MacKey.Key().size());

	if (MacKey.Nonce().size() != 0)
		memcpy(&key[MacKey.Key().size()], &MacKey.Nonce()[0], MacKey.Nonce().size());
	if (MacKey.Info().size() != 0)
		memcpy(&key[MacKey.Key().size() + MacKey.Nonce().size()], &MacKey.Info()[0], MacKey.Info().size());

	if (m_iPad.size() != BLOCK_SIZE)
		m_iPad.resize(BLOCK_SIZE, 0x36);
	else
		memset(&m_iPad[0], (byte)0x36, m_iPad.size());

	if (m_oPad.size() != BLOCK_SIZE)
		m_oPad.resize(BLOCK_SIZE, 0x5C);
	else
		memset(&m_oPad[0], (byte)0x5C, m_oPad.size());

	if (klen > BLOCK_SIZE)
	{
		Update(key, 0, key.size());
		key.resize(DIGEST_SIZE);
		HashFinal(m_msgBuffer, 0, m_msgLength, m_State, 0);
		StateToBytes(key, 0, m_State, 0);
		Reset();
	}

	for (size_t i = 0; i < key.size(); ++i)
		m_iPad[i] ^= key[i];
	for (size_t i = 0; i < key.size(); ++i)
		m_oPad[i] ^= key[i];

	ResetMac();
}

void SHA512::Reset()
{
	m_msgLength = 0;
	memset(&m_msgBuffer[0], 0, m_msgBuffer.size());

	Initialize(m_State);
}

void SHA512::Update(byte Input)
{
	std::vector<uint8_t> inp(1, Input);
	Update(inp, 0, 1);
}

void SHA512::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (Input.size() - InOffset < Length)
		throw CryptoDigestException("SHA512:Update", "The Input buffer is too short!");
	if (Length == 0)
		return;

	if (m_isParallel)
	{
		size_t stateOffset = m_State.size() / m_treeParams.ParallelDegree();

		if (m_msgLength != 0 && Length + m_msgLength >= m_msgBuffer.size())
		{
			// fill buffer
			size_t rmd = m_msgBuffer.size() - m_msgLength;
			if (rmd != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

			// empty the message buffer
			Utility::ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset, stateOffset](size_t i)
			{
				ProcessBlock(m_msgBuffer, i * ITL_BLKSIZE, m_State, i * stateOffset);
			});

			m_msgLength = 0;
			Length -= rmd;
			InOffset += rmd;
		}

		if (Length >= m_minParallel)
		{
			// calculate working set size
			size_t prcLen = Length - (Length % m_minParallel);

			// process large blocks
			//for (size_t i = 0; i < m_treeParams.ParallelDegree(); ++i)
			Utility::ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset, prcLen, stateOffset](size_t i)
			{
				ProcessLeaf(Input, InOffset + (i * ITL_BLKSIZE), m_State, i * stateOffset, prcLen);
			});

			Length -= prcLen;
			InOffset += prcLen;
		}
	}
	else
	{
		if (m_msgLength != 0 && m_msgLength + Length >= BLOCK_SIZE)
		{
			size_t rmd = BLOCK_SIZE - m_msgLength;
			if (rmd != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

			ProcessBlock(m_msgBuffer, 0, m_State, 0);
			m_msgLength = 0;
			InOffset += rmd;
			Length -= rmd;
		}

		// loop until last block
		while (Length > BLOCK_SIZE)
		{
			ProcessBlock(Input, InOffset, m_State, 0);
			InOffset += BLOCK_SIZE;
			Length -= BLOCK_SIZE;
		}
	}

	// store unaligned bytes
	if (Length != 0)
	{
		memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], Length);
		m_msgLength += Length;
	}
}

//~~~Private Functions~~~//

void SHA512::DetectCpu()
{
	Common::CpuDetect detect;
	m_hasAvx = detect.AVX2();
}

void SHA512::Extract(const std::vector<byte> &Key, const std::vector<byte> &Salt, std::vector<byte> &Output)
{
	if (Output.size() != DIGEST_SIZE)
		Output.resize(DIGEST_SIZE);

	LoadMacKey(Key::Symmetric::SymmetricKey(Key));

	if (Salt.size() == 0)
	{
		std::vector<byte> zeros(DIGEST_SIZE, 0);
		LoadMacKey(Key::Symmetric::SymmetricKey(zeros));
	}
	else
	{
		LoadMacKey(Key::Symmetric::SymmetricKey(Salt));
	}

	Update(Key, 0, Key.size());
	Finalize(Output, 0);
	ResetMac();
}

void SHA512::Expand(const std::vector<byte> &Input, size_t Count, std::vector<byte> &Output)
{
	const size_t N = Count / DIGEST_SIZE + 1;

	if (Count != 0)
		Update(Output, 0, DIGEST_SIZE);
	if (Input.size() > 0)
		Update(Input, 0, Input.size());

	Update((byte)N);
	Finalize(Output, 0);
	ResetMac();
}

void SHA512::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<SHA512State> &State, size_t StateOffset)
{
	State[StateOffset].Increase(Length);
	ulong bitLen = (State[StateOffset].T[0] << 3);

	if (Length == BLOCK_SIZE)
	{
		SHA512Compress::Compress128(Input, InOffset, State, StateOffset);
		Length = 0;
	}

	Input[InOffset + Length] = (byte)128;
	++Length;

	// padding
	if (Length < BLOCK_SIZE)
		memset(&Input[InOffset + Length], 0, BLOCK_SIZE - Length);

	if (Length > 112)
	{
		SHA512Compress::Compress128(Input, InOffset, State, StateOffset);
		memset(&Input[InOffset], 0, BLOCK_SIZE);
	}

	// finalize state with counter and last compression
	IntUtils::Be64ToBytes(State[StateOffset].T[1], Input, InOffset + 112);
	IntUtils::Be64ToBytes(bitLen, Input, InOffset + 120);
	SHA512Compress::Compress128(Input, InOffset, State, StateOffset);
}

void SHA512::Initialize(std::vector<SHA512State> &State)
{
	LoadState(State, 0);

	if (State.size() > 1)
	{
		for (size_t i = 1; i < State.size(); ++i)
		{
			memcpy(&State[i].H[0], &State[0].H[0], State[0].H.size() * sizeof(ulong));
			State[i].T[0] = 0;
			State[i].T[1] = 0;
		}
	}

	m_isInitialized = true;
}

void SHA512::LoadState(std::vector<SHA512State> &State, size_t StateOffset)
{
	State[StateOffset].T[0] = 0;
	State[StateOffset].T[1] = 0;
	State[StateOffset].H[0] = 0x6a09e667f3bcc908;
	State[StateOffset].H[1] = 0xbb67ae8584caa73b;
	State[StateOffset].H[2] = 0x3c6ef372fe94f82b;
	State[StateOffset].H[3] = 0xa54ff53a5f1d36f1;
	State[StateOffset].H[4] = 0x510e527fade682d1;
	State[StateOffset].H[5] = 0x9b05688c2b3e6c1f;
	State[StateOffset].H[6] = 0x1f83d9abfb41bd6b;
	State[StateOffset].H[7] = 0x5be0cd19137e2179;
}

void SHA512::MacFinal(std::vector<byte> &Input, const size_t Length, std::vector<SHA512State> &State, size_t StateOffset)
{
	HashFinal(Input, 0, Length, State, StateOffset);
	StateToBytes(Input, 0, State, StateOffset);
	LoadState(State, StateOffset);
	SHA512Compress::Compress128(m_oPad, 0, State, StateOffset);
	HashFinal(Input, 0, DIGEST_SIZE, State, StateOffset);
}

void SHA512::ProcessBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<SHA512State> &State, size_t StateOffset)
{
	if (m_isParallel)
	{
		if (m_hasAvx)
		{
			SHA512Compress::Compress512(Input, InOffset, State, StateOffset);
		}
		else
		{
			// 4 lanes in reverse order for future simd compatability
			SHA512Compress::Compress128(Input, InOffset, State, StateOffset + 3);
			SHA512Compress::Compress128(Input, InOffset + BLOCK_SIZE, State, StateOffset + 2);
			SHA512Compress::Compress128(Input, InOffset + BLOCK_SIZE * 2, State, StateOffset + 1);
			SHA512Compress::Compress128(Input, InOffset + BLOCK_SIZE * 3, State, StateOffset);
		}
	}
	else
	{
		SHA512Compress::Compress128(Input, InOffset, State, StateOffset);
	}
}

void SHA512::ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<SHA512State> &State, size_t StateOffset, uint64_t Length)
{
	do
	{
		ProcessBlock(Input, InOffset, State, StateOffset);
		InOffset += m_minParallel;
		Length -= m_minParallel;
	} while (Length > 0);
}

void SHA512::ResetMac()
{
	LoadState(m_State, 0);
	SHA512Compress::Compress128(m_iPad, 0, m_State, 0);
}

void SHA512::StateToBytes(std::vector<byte> &Output, const size_t OutOffset, std::vector<SHA512State> &State, size_t StateOffset)
{
#if defined(IS_BIG_ENDIAN)
	memcpy(&Output[OutOffset], &State[StateOffset].H[0], State[StateOffset].H.size() * sizeof(ulong));
#else
	IntUtils::Be64ToBytes(m_State[StateOffset].H[0], Output, OutOffset);
	IntUtils::Be64ToBytes(m_State[StateOffset].H[1], Output, OutOffset + 8);
	IntUtils::Be64ToBytes(m_State[StateOffset].H[2], Output, OutOffset + 16);
	IntUtils::Be64ToBytes(m_State[StateOffset].H[3], Output, OutOffset + 24);
	IntUtils::Be64ToBytes(m_State[StateOffset].H[4], Output, OutOffset + 32);
	IntUtils::Be64ToBytes(m_State[StateOffset].H[5], Output, OutOffset + 40);
	IntUtils::Be64ToBytes(m_State[StateOffset].H[6], Output, OutOffset + 48);
	IntUtils::Be64ToBytes(m_State[StateOffset].H[7], Output, OutOffset + 56);
#endif
}

NAMESPACE_DIGESTEND