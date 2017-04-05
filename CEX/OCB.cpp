#include "OCB.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CMAC.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "SymmetricKey.h"

NAMESPACE_MODE

using Utility::ArrayUtils;
using Utility::IntUtils;

//~~~Constructor~~~//

OCB::OCB(BlockCiphers CipherType)
	:
	m_aadData(BLOCK_SIZE),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_blockCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_checkSum(BLOCK_SIZE),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_hashCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_hashList(0),
	m_isEncryption(false),
	m_isFinalized(false),
	m_legalKeySizes(0),
	m_listAsterisk(BLOCK_SIZE),
	m_listDollar(BLOCK_SIZE),
	m_macSize(BLOCK_SIZE),
	m_mainBlockCount(0),
	m_mainOffset(BLOCK_SIZE),
	m_mainOffset0(BLOCK_SIZE),
	m_mainStretch(BLOCK_SIZE + (BLOCK_SIZE / 2)),
	m_msgTag(BLOCK_SIZE),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize() + PREFETCH_HASH, true),
	m_topInput(0)
{
	Scope();
}

OCB::OCB(IBlockCipher* Cipher)
	:
	m_aadData(BLOCK_SIZE),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_blockCipher(Cipher != 0 ? Cipher : throw CryptoCipherModeException("OCB:CTor", "The Cipher can not be null!")),
	m_checkSum(BLOCK_SIZE),
	m_cipherType(m_blockCipher->Enumeral()),
	m_destroyEngine(false),
	m_hashCipher(Helper::BlockCipherFromName::GetInstance(m_cipherType)),
	m_hashList(0),
	m_isEncryption(false),
	m_isFinalized(false),
	m_legalKeySizes(0),
	m_listAsterisk(BLOCK_SIZE),
	m_listDollar(BLOCK_SIZE),
	m_macSize(BLOCK_SIZE),
	m_mainBlockCount(0),
	m_mainOffset(BLOCK_SIZE),
	m_mainOffset0(BLOCK_SIZE),
	m_mainStretch(2 * BLOCK_SIZE),
	m_msgTag(BLOCK_SIZE),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize() + PREFETCH_HASH, true),
	m_topInput(BLOCK_SIZE + (BLOCK_SIZE / 2))
{
	if (m_blockCipher->BlockSize() != BLOCK_SIZE)
		throw CryptoCipherModeException("OCB:CTor", "The Cipher block-size must be 128 bit!");

	Scope();
}

OCB::~OCB()
{
	Destroy();
}

//~~~Public Functions~~~//

void OCB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	DecryptBlock(Input, 0, Output, 0);
}

void OCB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	memcpy(&Output[OutOffset], &Input[InOffset], BLOCK_SIZE);
	std::vector<byte> hash(BLOCK_SIZE);
	GetLSub(Ntz(++m_mainBlockCount), hash);
	IntUtils::XORBLK(hash, 0, m_mainOffset, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	IntUtils::XORBLK(m_mainOffset, 0, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	m_blockCipher->Transform(Output, OutOffset, Output, OutOffset);
	IntUtils::XORBLK(m_mainOffset, 0, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	IntUtils::XORBLK(Output, OutOffset, m_checkSum, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
}

void OCB::Destroy()
{
	m_aadLoaded = false;
	m_aadPreserve = false;
	m_cipherType = BlockCiphers::None;
	m_isDestroyed = false;
	m_isFinalized = false;
	m_isEncryption = false;
	m_isInitialized = false;
	m_macSize = 0;
	m_mainBlockCount = 0;
	m_parallelProfile.Reset();

	try
	{
		ArrayUtils::ClearVector(m_aadData);
		ArrayUtils::ClearVector(m_checkSum);
		ArrayUtils::ClearVector(m_hashList);
		ArrayUtils::ClearVector(m_legalKeySizes);
		ArrayUtils::ClearVector(m_listAsterisk);
		ArrayUtils::ClearVector(m_listDollar);
		ArrayUtils::ClearVector(m_mainOffset);
		ArrayUtils::ClearVector(m_mainOffset0);
		ArrayUtils::ClearVector(m_mainStretch);
		ArrayUtils::ClearVector(m_msgTag);
		ArrayUtils::ClearVector(m_ocbNonce);
		ArrayUtils::ClearVector(m_ocbVector);
		ArrayUtils::ClearVector(m_topInput);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_blockCipher != 0)
				m_blockCipher->Destroy();
			if (m_hashCipher != 0)
				m_hashCipher->Destroy();
		}
	}
	catch (std::exception& ex)
	{
		throw CryptoCipherModeException("EAX:Destroy", "Could not clear all variables!", std::string(ex.what()));
	}
}

void OCB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void OCB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	memcpy(&Output[OutOffset], &Input[InOffset], BLOCK_SIZE);
	IntUtils::XORBLK(Output, OutOffset, m_checkSum, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	std::vector<byte> hash(BLOCK_SIZE);
	GetLSub(Ntz(++m_mainBlockCount), hash);
	IntUtils::XORBLK(hash, 0, m_mainOffset, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	IntUtils::XORBLK(m_mainOffset, 0, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	m_blockCipher->Transform(Output, OutOffset, Output, OutOffset);
	IntUtils::XORBLK(m_mainOffset, 0, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());
}

void OCB::Finalize(std::vector<byte> &Output, const size_t Offset, const size_t Length)
{
	if (Length > BLOCK_SIZE || Length < MIN_TAGSIZE)
		throw CryptoCipherModeException("OCB:Finalize", "The output length must be between 12 and 16 bytes!");

	CalculateMac();
	memcpy(&Output[Offset], &m_msgTag[0], Length);
}

void OCB::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	Scope();

	if (KeyParams.Key().size() == 0)
	{
		if (KeyParams.Nonce() == m_ocbVector)
			throw CryptoSymmetricCipherException("OCB:Initialize", "The nonce can not be zeroised or reused!");
		if (!m_blockCipher->IsInitialized())
			throw CryptoSymmetricCipherException("OCB:Initialize", "First initialization requires a key and nonce!");
	}
	else
	{
		if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
			throw CryptoSymmetricCipherException("OCB:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");

		m_hashCipher->Initialize(true, KeyParams);
		m_blockCipher->Initialize(Encryption, KeyParams);
	}

	if (KeyParams.Nonce().size() > MAX_NONCESIZE || KeyParams.Nonce().size() < MIN_NONCESIZE)
		throw CryptoSymmetricCipherException("OCB:Initialize", "Requires a nonce of at least 12, and no longer than 15 bytes!");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		throw CryptoSymmetricCipherException("OCB:Initialize", "The parallel block size is out of bounds!");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("OCB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	m_isEncryption = Encryption;
	m_ocbNonce = KeyParams.Nonce();
	m_ocbVector = m_ocbNonce;
	m_hashCipher->Transform(m_listAsterisk, 0, m_listAsterisk, 0);
	DoubleBlock(m_listAsterisk, m_listDollar);
	std::vector<byte> hash(BLOCK_SIZE);
	DoubleBlock(m_listDollar, hash);
	m_hashList.push_back(hash);
	GenerateOffsets(m_ocbVector);

	if (m_isFinalized)
	{
		memset(&m_msgTag[0], (byte)0, m_msgTag.size());
		m_isFinalized = false;
	}

	m_isInitialized = true;
}

void OCB::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
		throw CryptoSymmetricCipherException("OCB:SetAssociatedData", "The cipher has not been initialized!");
	if (m_aadLoaded)
		throw CryptoSymmetricCipherException("OCB:SetAssociatedData", "The associated data can not be added after processing has begun!");

	size_t blkCnt = 0;
	size_t blkLen = Length;
	size_t blkOff = Offset;
	std::vector<byte> offsetHash(BLOCK_SIZE);

	while (blkLen >= BLOCK_SIZE)
	{
		std::vector<byte> offset(BLOCK_SIZE);
		GetLSub(Ntz(++blkCnt), offset);
		std::vector<byte> tmp(BLOCK_SIZE);
		memcpy(&tmp[0], &Input[blkOff], BLOCK_SIZE);
		IntUtils::XORBLK(offset, 0, offsetHash, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
		IntUtils::XORBLK(offsetHash, 0, tmp, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
		m_hashCipher->Transform(tmp, 0, tmp, 0);
		IntUtils::XORBLK(tmp, 0, m_aadData, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
		blkOff += BLOCK_SIZE;
		blkLen -= BLOCK_SIZE;
	}

	if (blkLen != 0)
	{
		std::vector<byte> tmp(BLOCK_SIZE);
		memcpy(&tmp[0], &Input[blkOff], blkLen);
		ExtendBlock(tmp, blkLen);
		IntUtils::XORBLK(m_listAsterisk, 0, offsetHash, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
		IntUtils::XORBLK(offsetHash, 0, tmp, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
		m_hashCipher->Transform(tmp, 0, tmp, 0);
		IntUtils::XORBLK(tmp, 0, m_aadData, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	}

	m_aadLoaded = true;
}

size_t OCB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	const size_t PRCSZE = IntUtils::Min(Output.size(), Input.size());
	Transform(Input, 0, Output, 0, PRCSZE);
	return PRCSZE;
}

size_t OCB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_parallelProfile.IsParallel() && (IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_parallelProfile.ParallelBlockSize()))
	{
		Transform(Input, InOffset, Output, OutOffset, m_parallelProfile.ParallelBlockSize());
		return m_parallelProfile.ParallelBlockSize();
	}
	else
	{
		if (m_isEncryption)
			EncryptBlock(Input, InOffset, Output, OutOffset);
		else
			DecryptBlock(Input, InOffset, Output, OutOffset);

		return BLOCK_SIZE;
	}
}

void OCB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (m_parallelProfile.IsParallel() && Length >= m_parallelProfile.ParallelBlockSize())
	{
		if (m_isEncryption)
			ParallelEncrypt(Input, InOffset, Output, OutOffset, Length);
		else
			ParallelDecrypt(Input, InOffset, Output, OutOffset, Length);
	}
	else
	{
		const size_t BLKCNT = Length / BLOCK_SIZE;
		if (m_isEncryption)
		{
			for (size_t i = 0; i < BLKCNT; ++i)
				EncryptBlock(Input, InOffset + i * BLOCK_SIZE, Output, OutOffset + i * BLOCK_SIZE);
		}
		else
		{
			for (size_t i = 0; i < BLKCNT; ++i)
				DecryptBlock(Input, InOffset + (i * BLOCK_SIZE), Output, OutOffset + (i * BLOCK_SIZE));
		}

		if (Length % BLOCK_SIZE != 0)
		{
			const size_t BLKOFF = (BLKCNT * BLOCK_SIZE);
			ProcessPartial(Input, InOffset + BLKOFF, Output, OutOffset + BLKOFF, Length - BLKOFF);
		}
	}
}

bool OCB::Verify(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (m_isEncryption)
		throw CryptoCipherModeException("OCB:Verify", "The cipher mode has not been initialized for decryption!");
	if (!m_isInitialized && !m_isFinalized)
		throw CryptoCipherModeException("OCB:Verify", "The cipher mode has not been initialized!");
	if (Length < MIN_TAGSIZE || Length > m_macSize)
		throw CryptoCipherModeException("OCB:Verify", "The length must be minimum of 12 and maximum of MAC code size!");

	if (!m_isFinalized)
		CalculateMac();

	return ArrayUtils::Compare(m_msgTag, 0, Input, Offset, Length);
}

//~~~Private Functions~~~//

void OCB::CalculateMac()
{
	IntUtils::XORBLK(m_mainOffset, 0, m_checkSum, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	IntUtils::XORBLK(m_listDollar, 0, m_checkSum, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	m_hashCipher->Transform(m_checkSum, 0, m_checkSum, 0);
	IntUtils::XORBLK(m_aadData, 0, m_checkSum, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	memcpy(&m_msgTag[0], &m_checkSum[0], m_macSize);
	Reset();

	if (m_autoIncrement)
	{
		ArrayUtils::IncrementBE8(m_ocbNonce);
		std::vector<byte> zero(0);
		Initialize(m_isEncryption, Key::Symmetric::SymmetricKey(zero, m_ocbNonce));
	}

	m_isFinalized = true;
}

void OCB::DoubleBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	uint carry = ArrayUtils::ShiftLeft(Input, Output);
	uint x = (1 - carry) << 3;
	byte n = (x == 0) ? 0x87 : (byte)((ulong)0x87 >> x);

	Output[MAX_NONCESIZE] ^= n;
}

void OCB::ExtendBlock(std::vector<byte> &Output, size_t Position)
{
	Output[Position] = (byte)0x80;
	++Position;
	if (Position < BLOCK_SIZE)
		memset(&Output[Position], (byte)0, Output.size() - Position);
}

void OCB::GenerateOffsets(const std::vector<byte> &Nonce)
{
	std::vector<byte> tmpNonce(BLOCK_SIZE);
	memcpy(&tmpNonce[BLOCK_SIZE - Nonce.size()], &Nonce[0], Nonce.size());
	tmpNonce[0] = (byte)(m_macSize << 4);
	tmpNonce[MAX_NONCESIZE - Nonce.size()] |= 1;
	uint bottom = tmpNonce[MAX_NONCESIZE] & 0x3F;
	tmpNonce[MAX_NONCESIZE] &= 0xC0;

	// when used with incrementing nonces, the cipher is only applied once every 64 inits
	if (tmpNonce != m_topInput)
	{
		std::vector<byte> kTop(BLOCK_SIZE);
		m_topInput = tmpNonce;
		m_hashCipher->Transform(m_topInput, 0, kTop, 0);
		memcpy(&m_mainStretch[0], &kTop[0], BLOCK_SIZE);

		for (size_t i = 0; i < 8; ++i)
			m_mainStretch[BLOCK_SIZE + i] = (byte)(kTop[i] ^ kTop[i + 1]);
	}

	const size_t BTMSZE = bottom % 8;
	size_t btmLen = bottom / 8;

	if (BTMSZE == 0)
	{
		memcpy(&m_mainOffset0[0], &m_mainStretch[btmLen], BLOCK_SIZE);
	}
	else
	{
		for (size_t i = 0; i < BLOCK_SIZE; ++i)
		{
			ulong b1 = m_mainStretch[btmLen];
			ulong b2 = m_mainStretch[++btmLen];

			m_mainOffset0[i] = (byte)((b1 << BTMSZE) | (b2 >> (8 - BTMSZE)));
		}
	}

	memcpy(&m_mainOffset[0], &m_mainOffset0[0], BLOCK_SIZE);
}

void OCB::GetLSub(size_t N, std::vector<byte> &LSub)
{
	size_t hashCtr = m_hashList.size();
	while (N >= hashCtr)
	{
		DoubleBlock(m_hashList[m_hashList.size() - 1], LSub);
		m_hashList.push_back(LSub);
		++hashCtr;
	}

	memcpy(&LSub[0], &m_hashList[N][0], BLOCK_SIZE);
}

uint OCB::Ntz(ulong X)
{
	uint zCnt = 0;

	while (!(X & 1)) 
	{
		X >>= 1;
		++zCnt;
	}

	return zCnt;
}

void OCB::ProcessSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t SSEBLK = 4 * BLOCK_SIZE;
	const size_t AVXBLK = 8 * BLOCK_SIZE;

	if (m_parallelProfile.HasSimd256() && Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		const size_t SUBBLK = PBKALN / AVXBLK;

		IntUtils::XORBLK(Input, InOffset, Output, OutOffset, PBKALN, m_parallelProfile.SimdProfile());
		for (size_t i = 0; i < SUBBLK; ++i)
			m_blockCipher->Transform128(Output, OutOffset + (i * AVXBLK), Output, OutOffset + (i * AVXBLK));
		IntUtils::XORBLK(Input, InOffset, Output, OutOffset, PBKALN, m_parallelProfile.SimdProfile());
	}
	else if (m_parallelProfile.HasSimd128() && Length >= SSEBLK)
	{
		const size_t PBKALN = Length - (Length % SSEBLK);
		const size_t SUBBLK = PBKALN / SSEBLK;
		IntUtils::XORBLK(Input, InOffset, Output, OutOffset, PBKALN, m_parallelProfile.SimdProfile());
		for (size_t i = 0; i < SUBBLK; ++i)
			m_blockCipher->Transform64(Output, OutOffset + (i * SSEBLK), Output, OutOffset + (i * SSEBLK));
		IntUtils::XORBLK(Input, InOffset, Output, OutOffset, PBKALN, m_parallelProfile.SimdProfile());
	}
	else
	{
		const size_t PBKALN = Length - (Length % BLOCK_SIZE);
		const size_t SUBBLK = PBKALN / BLOCK_SIZE;
		IntUtils::XORBLK(Input, InOffset, Output, OutOffset, PBKALN, m_parallelProfile.SimdProfile());
		for (size_t i = 0; i < SUBBLK; ++i)
			m_blockCipher->Transform(Output, OutOffset + (i * BLOCK_SIZE), Output, OutOffset + (i * BLOCK_SIZE));
		IntUtils::XORBLK(Input, InOffset, Output, OutOffset, PBKALN, m_parallelProfile.SimdProfile());
	}
}

void OCB::ParallelDecrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t BLKCNT = Length / BLOCK_SIZE;
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	const size_t OUTOFF = OutOffset;

	// copy data into working output
	memcpy(&Output[OutOffset], &Input[InOffset], ALNLEN);

	// create the offset chain
	std::vector<byte> offsetChain(ALNLEN);
	std::vector<byte> hash(BLOCK_SIZE);

	// TODO: parallelize this with smaller chains?
	for (size_t i = 0; i < BLKCNT; ++i)
	{
		GetLSub(Ntz(++m_mainBlockCount), hash);
		IntUtils::XORBLK(hash, 0, m_mainOffset, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
		memcpy(&offsetChain[(i * BLOCK_SIZE)], &m_mainOffset[0], BLOCK_SIZE);
	}

	// parallel offsets
	const size_t PRLSZE = m_parallelProfile.ParallelBlockSize();
	const size_t CNKSZE = PRLSZE / m_parallelProfile.ParallelMaxDegree();
	size_t chainPos = 0;

	while (Length >= PRLSZE)
	{
		Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Output, OutOffset, &offsetChain, chainPos, CNKSZE](size_t i)
		{
			this->ProcessSegment(offsetChain, chainPos + (i * CNKSZE), Output, OutOffset + (i * CNKSZE), CNKSZE);
		});

		Length -= PRLSZE;
		OutOffset += PRLSZE;
		chainPos += PRLSZE;
	}

	if (Length != 0)
	{
		while (Length >= BLOCK_SIZE)
		{
			IntUtils::XORBLK(offsetChain, chainPos, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());
			m_blockCipher->Transform(Output, OutOffset, Output, OutOffset);
			IntUtils::XORBLK(offsetChain, chainPos, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());

			Length -= BLOCK_SIZE;
			OutOffset += BLOCK_SIZE;
			chainPos += BLOCK_SIZE;
		}

		if (Length != 0)
			ProcessPartial(Input, InOffset + ALNLEN, Output, OutOffset, Length);
	}

	// update the checksum
	for (size_t i = 0; i < BLKCNT; ++i)
		IntUtils::XORBLK(Output, OUTOFF + (i * BLOCK_SIZE), m_checkSum, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
}

void OCB::ParallelEncrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t BLKCNT = Length / BLOCK_SIZE;
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);

	// copy data into working output
	memcpy(&Output[OutOffset], &Input[InOffset], ALNLEN);

	// pre-fold the checksum
	for (size_t i = 0; i < BLKCNT; ++i)
		IntUtils::XORBLK(Output, OutOffset + (i * BLOCK_SIZE), m_checkSum, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());

	// create the offset chain
	std::vector<byte> offsetChain(ALNLEN);
	std::vector<byte> hash(BLOCK_SIZE);

	// TODO: parallelize this with smaller chains?
	for (size_t i = 0; i < BLKCNT; ++i)
	{
		GetLSub(Ntz(++m_mainBlockCount), hash);
		IntUtils::XORBLK(hash, 0, m_mainOffset, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
		memcpy(&offsetChain[(i * BLOCK_SIZE)], &m_mainOffset[0], BLOCK_SIZE);
	}

	// parallel offsets
	const size_t PRLSZE = m_parallelProfile.ParallelBlockSize();
	const size_t CNKSZE = PRLSZE / m_parallelProfile.ParallelMaxDegree();
	size_t chainPos = 0;

	while (Length >= PRLSZE)
	{
		Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Output, OutOffset, &offsetChain, chainPos, CNKSZE](size_t i)
		{
			this->ProcessSegment(offsetChain, chainPos + (i * CNKSZE), Output, OutOffset + (i * CNKSZE), CNKSZE);
		});

		Length -= PRLSZE;
		OutOffset += PRLSZE;
		chainPos += PRLSZE;
	}

	if (Length != 0)
	{
		while (Length >= BLOCK_SIZE)
		{
			IntUtils::XORBLK(offsetChain, chainPos, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());
			m_blockCipher->Transform(Output, OutOffset, Output, OutOffset);
			IntUtils::XORBLK(offsetChain, chainPos, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());

			Length -= BLOCK_SIZE;
			OutOffset += BLOCK_SIZE;
			chainPos += BLOCK_SIZE;
		}

		if (Length != 0)
			ProcessPartial(Input, InOffset + ALNLEN, Output, OutOffset, Length);
	}
}

void OCB::ProcessPartial(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, size_t Length)
{
	if (m_isEncryption)
	{
		memcpy(&Output[OutOffset], &Input[InOffset], Length);
		ExtendBlock(Output, OutOffset + Length);

		IntUtils::XORPRT(Output, OutOffset, m_checkSum, 0, Length + 1);
		IntUtils::XORBLK(m_listAsterisk, 0, m_mainOffset, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());

		std::vector<byte> pad(BLOCK_SIZE);
		m_hashCipher->Transform(m_mainOffset, 0, pad, 0);
		IntUtils::XORBLK(pad, 0, Output, OutOffset, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	}
	else
	{
		memcpy(&Output[OutOffset], &Input[InOffset], Length);
		IntUtils::XORBLK(m_listAsterisk, 0, m_mainOffset, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());

		std::vector<byte> pad(BLOCK_SIZE);
		m_hashCipher->Transform(m_mainOffset, 0, pad, 0);
		IntUtils::XORPRT(pad, 0, Output, OutOffset, Length);

		std::vector<byte> tmp(BLOCK_SIZE);
		memcpy(&tmp[0], &Output[OutOffset], Length);
		ExtendBlock(tmp, Length);
		IntUtils::XORBLK(tmp, 0, m_checkSum, 0, BLOCK_SIZE, m_parallelProfile.SimdProfile());
	}
}

void OCB::Reset()
{
	if (!m_aadPreserve)
	{
		m_aadLoaded = false;
		memset(&m_aadData[0], (byte)0, m_aadData.size());
	}

	m_mainBlockCount = 0;
	memset(&m_checkSum[0], (byte)0, m_checkSum.size());
	memset(&m_listAsterisk[0], (byte)0, m_listAsterisk.size());
	memset(&m_listDollar[0], (byte)0, m_listDollar.size());
	memset(&m_mainOffset[0], (byte)0, m_mainOffset.size());
	memset(&m_mainOffset0[0], (byte)0, m_mainOffset0.size());
	memset(&m_mainStretch[0], (byte)0, m_mainStretch.size());
	memset(&m_ocbVector[0], (byte)0, m_ocbVector.size());
	memset(&m_topInput[0], (byte)0, m_topInput.size());
	m_hashList.clear();

	m_isInitialized = false;
}

void OCB::Scope()
{
	if (m_legalKeySizes.size() == 0)
	{
		const size_t KEYCNT = m_blockCipher->LegalKeySizes().size();
		m_legalKeySizes.resize(KEYCNT);

		for (size_t i = 0; i < KEYCNT; ++i)
			m_legalKeySizes[i] = SymmetricKeySize(m_blockCipher->LegalKeySizes()[i].KeySize(), MAX_NONCESIZE, 0);

		m_hashList.clear();
		m_hashList.reserve(PREFETCH_HASH);
	}

	if (!m_parallelProfile.IsDefault())
		m_parallelProfile.Calculate();
}

NAMESPACE_MODEEND
