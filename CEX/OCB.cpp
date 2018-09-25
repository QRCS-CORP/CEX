#include "OCB.h"
#include "BlockCipherFromName.h"
#include "CMAC.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "SymmetricKey.h"

NAMESPACE_MODE

const std::string OCB::CLASS_NAME("OCB");

//~~~Constructor~~~//

OCB::OCB(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType)
	:
	m_aadData(BLOCK_SIZE),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_autoIncrement(false),
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType, CipherExtensionType) :
		throw CryptoCipherModeException("OCB:CTor", "The Cipher type can not be none!")),
	m_checkSum(BLOCK_SIZE),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_hashCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_hashList(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isFinalized(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_listAsterisk(BLOCK_SIZE),
	m_listDollar(BLOCK_SIZE),
	m_mainBlockCount(0),
	m_mainOffset(BLOCK_SIZE),
	m_mainOffset0(BLOCK_SIZE),
	m_mainStretch(BLOCK_SIZE + (BLOCK_SIZE / 2)),
	m_msgTag(BLOCK_SIZE),
	m_ocbNonce(0),
	m_ocbVector(0),
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
	m_autoIncrement(false),
	m_blockCipher(Cipher != nullptr ? Cipher :
		throw CryptoCipherModeException("OCB:CTor", "The Cipher can not be null!")),
	m_checkSum(BLOCK_SIZE),
	m_cipherType(m_blockCipher->Enumeral()),
	m_destroyEngine(false),
	m_hashCipher(Helper::BlockCipherFromName::GetInstance(m_cipherType)),
	m_hashList(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isFinalized(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_listAsterisk(BLOCK_SIZE),
	m_listDollar(BLOCK_SIZE),
	m_mainBlockCount(0),
	m_mainOffset(BLOCK_SIZE),
	m_mainOffset0(BLOCK_SIZE),
	m_mainStretch(2 * BLOCK_SIZE),
	m_msgTag(BLOCK_SIZE),
	m_ocbNonce(0),
	m_ocbVector(0),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize() + PREFETCH_HASH, true),
	m_topInput(BLOCK_SIZE + (BLOCK_SIZE / 2))
{
	Scope();
}

OCB::~OCB()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_aadLoaded = false;
		m_aadPreserve = false;
		m_autoIncrement = false;
		m_cipherType = BlockCiphers::None;
		m_isFinalized = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_mainBlockCount = 0;
		m_parallelProfile.Reset();

		Utility::IntUtils::ClearVector(m_aadData);
		Utility::IntUtils::ClearVector(m_checkSum);
		Utility::IntUtils::ClearVector(m_hashList);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_listAsterisk);
		Utility::IntUtils::ClearVector(m_listDollar);
		Utility::IntUtils::ClearVector(m_mainOffset);
		Utility::IntUtils::ClearVector(m_mainOffset0);
		Utility::IntUtils::ClearVector(m_mainStretch);
		Utility::IntUtils::ClearVector(m_msgTag);
		Utility::IntUtils::ClearVector(m_ocbNonce);
		Utility::IntUtils::ClearVector(m_ocbVector);
		Utility::IntUtils::ClearVector(m_topInput);

		if (m_hashCipher != nullptr)
		{
			m_hashCipher.reset(nullptr);
		}

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_blockCipher != nullptr)
			{
				m_blockCipher.reset(nullptr);
			}
		}
		else
		{
			if (m_blockCipher != nullptr)
			{
				m_blockCipher.release();
			}
		}
	}
}

//~~~Accessors~~~//

bool &OCB::AutoIncrement()
{
	return m_autoIncrement;
}

const size_t OCB::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers OCB::CipherType()
{
	return m_cipherType;
}

IBlockCipher* OCB::Engine()
{
	return m_blockCipher.get();
}

const CipherModes OCB::Enumeral()
{
	return CipherModes::OCB;
}

const bool OCB::IsEncryption()
{
	return m_isEncryption;
}

const bool OCB::IsInitialized()
{
	return m_isInitialized;
}

const bool OCB::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &OCB::LegalKeySizes()
{
	return m_legalKeySizes;
}

const size_t OCB::MaxTagSize()
{
	return MAX_TAGSIZE;
}

const size_t OCB::MinTagSize()
{
	return MIN_TAGSIZE;
}

const std::string OCB::Name()
{
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

const size_t OCB::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &OCB::ParallelProfile()
{
	return m_parallelProfile;
}

bool &OCB::PreserveAD()
{
	return m_aadPreserve;
}

const std::vector<byte> OCB::Tag()
{
	CexAssert(m_isFinalized, "The cipher mode has not been finalized");

	return m_msgTag;
}

//~~~Public Functions~~~//

void OCB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void OCB::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void OCB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void OCB::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void OCB::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized");
	CexAssert(Length >= MIN_TAGSIZE || Length <= BLOCK_SIZE, "The cipher mode has not been initialized");

	CalculateMac();
	Utility::MemUtils::Copy(m_msgTag, 0, Output, OutOffset, Length);
}

void OCB::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	Scope();
	Reset();

	if (KeyParams.Key().size() == 0)
	{
		if (KeyParams.Nonce() == m_ocbVector)
		{
			throw CryptoSymmetricCipherException("OCB:Initialize", "The nonce can not be zeroised or reused!");
		}
		if (!m_blockCipher->IsInitialized())
		{
			throw CryptoSymmetricCipherException("OCB:Initialize", "First initialization requires a key and nonce!");
		}
	}
	else
	{
		if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		{
			throw CryptoSymmetricCipherException("OCB:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
		}

		m_hashCipher->Initialize(true, KeyParams);
		m_blockCipher->Initialize(Encryption, KeyParams);
	}

	if (KeyParams.Nonce().size() > MAX_NONCESIZE || KeyParams.Nonce().size() < MIN_NONCESIZE)
	{
		throw CryptoSymmetricCipherException("OCB:Initialize", "Requires a nonce of at least 12, and no longer than 15 bytes!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
	{
		throw CryptoSymmetricCipherException("OCB:Initialize", "The parallel block size is out of bounds!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
	{
		throw CryptoSymmetricCipherException("OCB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
	}

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
		Utility::MemUtils::Clear(m_msgTag, 0, m_msgTag.size());
		m_isFinalized = false;
	}

	m_isInitialized = true;
}

void OCB::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
}

void OCB::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(!m_aadLoaded, "The associated data has already been set");

	size_t blkCnt = 0;
	size_t blkLen = Length;
	size_t blkOff = Offset;
	std::vector<byte> offsetHash(BLOCK_SIZE);

	while (blkLen >= BLOCK_SIZE)
	{
		std::vector<byte> offset(BLOCK_SIZE);
		GetLSub(Ntz(++blkCnt), offset);

		std::vector<byte> tmp(BLOCK_SIZE);
		Utility::MemUtils::COPY128(Input, blkOff, tmp, 0);
		Utility::MemUtils::XorBlock(offset, 0, offsetHash, 0, BLOCK_SIZE);
		Utility::MemUtils::XorBlock(offsetHash, 0, tmp, 0, BLOCK_SIZE);

		m_hashCipher->Transform(tmp, 0, tmp, 0);
		Utility::MemUtils::XorBlock(tmp, 0, m_aadData, 0, BLOCK_SIZE);

		blkOff += BLOCK_SIZE;
		blkLen -= BLOCK_SIZE;
	}

	if (blkLen != 0)
	{
		std::vector<byte> tmp(BLOCK_SIZE);
		Utility::MemUtils::Copy(Input, blkOff, tmp, 0, blkLen);
		ExtendBlock(tmp, blkLen);

		Utility::MemUtils::XorBlock(m_listAsterisk, 0, offsetHash, 0, BLOCK_SIZE);
		Utility::MemUtils::XorBlock(offsetHash, 0, tmp, 0, BLOCK_SIZE);

		m_hashCipher->Transform(tmp, 0, tmp, 0);
		Utility::MemUtils::XorBlock(tmp, 0, m_aadData, 0, BLOCK_SIZE);
	}

	m_aadLoaded = true;
}

void OCB::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (m_parallelProfile.IsParallel() && Length >= m_parallelProfile.ParallelBlockSize())
	{
		if (m_isEncryption)
		{
			ParallelEncrypt(Input, InOffset, Output, OutOffset, Length);
		}
		else
		{
			ParallelDecrypt(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		const size_t BLKCNT = Length / BLOCK_SIZE;
		if (m_isEncryption)
		{
			for (size_t i = 0; i < BLKCNT; ++i)
			{
				EncryptBlock(Input, InOffset + i * BLOCK_SIZE, Output, OutOffset + i * BLOCK_SIZE);
			}
		}
		else
		{
			for (size_t i = 0; i < BLKCNT; ++i)
			{
				DecryptBlock(Input, InOffset + (i * BLOCK_SIZE), Output, OutOffset + (i * BLOCK_SIZE));
			}
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
	CexAssert(!m_isEncryption, "the cipher mode has not been initialized for decryption");
	CexAssert(Length >= MIN_TAGSIZE || Length <= BLOCK_SIZE, "the length must be minimum of 12 and maximum of MAC code size");
	CexAssert(!(!m_isInitialized && !m_isFinalized), "the cipher mode has not been initialized for decryption");

	if (!m_isFinalized)
	{
		CalculateMac();
	}

	return Utility::IntUtils::Compare(m_msgTag, 0, Input, Offset, Length);
}

//~~~Private Functions~~~//

void OCB::CalculateMac()
{
	Utility::MemUtils::XOR128(m_mainOffset, 0, m_checkSum, 0);
	Utility::MemUtils::XOR128(m_listDollar, 0, m_checkSum, 0);

	m_hashCipher->Transform(m_checkSum, 0, m_checkSum, 0);

	Utility::MemUtils::XOR128(m_aadData, 0, m_checkSum, 0);
	Utility::MemUtils::COPY128(m_checkSum, 0, m_msgTag, 0);

	Reset();

	if (m_autoIncrement)
	{
		Utility::IntUtils::BeIncrement8(m_ocbNonce);
		std::vector<byte> zero(0);
		Initialize(m_isEncryption, Key::Symmetric::SymmetricKey(zero, m_ocbNonce));
	}

	m_isFinalized = true;
}

void OCB::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Utility::MemUtils::COPY128(Input, InOffset, Output, OutOffset);
	std::vector<byte> hash(BLOCK_SIZE);
	GetLSub(Ntz(++m_mainBlockCount), hash);

	Utility::MemUtils::XorBlock(hash, 0, m_mainOffset, 0, BLOCK_SIZE);
	Utility::MemUtils::XorBlock(m_mainOffset, 0, Output, OutOffset, BLOCK_SIZE);

	m_blockCipher->Transform(Output, OutOffset, Output, OutOffset);
	Utility::MemUtils::XorBlock(m_mainOffset, 0, Output, OutOffset, BLOCK_SIZE);
	Utility::MemUtils::XorBlock(Output, OutOffset, m_checkSum, 0, BLOCK_SIZE);
}

void OCB::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Utility::MemUtils::COPY128(Input, InOffset, Output, OutOffset);
	Utility::MemUtils::XorBlock(Output, OutOffset, m_checkSum, 0, BLOCK_SIZE);
	std::vector<byte> hash(BLOCK_SIZE);
	GetLSub(Ntz(++m_mainBlockCount), hash);

	Utility::MemUtils::XorBlock(hash, 0, m_mainOffset, 0, BLOCK_SIZE);
	Utility::MemUtils::XorBlock(m_mainOffset, 0, Output, OutOffset, BLOCK_SIZE);

	m_blockCipher->Transform(Output, OutOffset, Output, OutOffset);
	Utility::MemUtils::XorBlock(m_mainOffset, 0, Output, OutOffset, BLOCK_SIZE);
}

void OCB::DoubleBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	uint carry = Utility::IntUtils::ShiftLeft(Input, Output);
	uint x = (1 - carry) << 3;
	byte n = (x == 0) ? 0x87 : static_cast<byte>(static_cast<ulong>(0x87) >> x);

	Output[MAX_NONCESIZE] ^= n;
}

void OCB::ExtendBlock(std::vector<byte> &Output, size_t Position)
{
	Output[Position] = 0x80;
	++Position;

	if (Position < BLOCK_SIZE)
	{
		Utility::MemUtils::Clear(Output, Position, Output.size() - Position);
	}
}

void OCB::GenerateOffsets(const std::vector<byte> &Nonce)
{
	std::vector<byte> tmpNonce(BLOCK_SIZE);
	Utility::MemUtils::Copy(Nonce, 0, tmpNonce, BLOCK_SIZE - Nonce.size(), Nonce.size());
	tmpNonce[0] = static_cast<byte>(tmpNonce.size() << 4);
	tmpNonce[MAX_NONCESIZE - Nonce.size()] |= 1;
	uint bottom = tmpNonce[MAX_NONCESIZE] & 0x3F;
	tmpNonce[MAX_NONCESIZE] &= 0xC0;

	// when used with incrementing nonces, the cipher is only applied once every 64 inits
	if (tmpNonce != m_topInput)
	{
		std::vector<byte> kTop(BLOCK_SIZE);
		m_topInput = tmpNonce;
		m_hashCipher->Transform(m_topInput, 0, kTop, 0);
		Utility::MemUtils::COPY128(kTop, 0, m_mainStretch, 0);

		for (size_t i = 0; i < 8; ++i)
		{
			m_mainStretch[BLOCK_SIZE + i] = static_cast<byte>(kTop[i] ^ kTop[i + 1]);
		}
	}

	const size_t BTMLEN = bottom % 8;
	size_t btmLen = bottom / 8;

	if (BTMLEN == 0)
	{
		Utility::MemUtils::COPY128(m_mainStretch, btmLen, m_mainOffset0, 0);
	}
	else
	{
		for (size_t i = 0; i < BLOCK_SIZE; ++i)
		{
			ulong b1 = m_mainStretch[btmLen];
			++btmLen;
			ulong b2 = m_mainStretch[btmLen];
			m_mainOffset0[i] = static_cast<byte>((b1 << BTMLEN) | (b2 >> (8 - BTMLEN)));
		}
	}

	Utility::MemUtils::COPY128(m_mainOffset0, 0, m_mainOffset, 0);
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

	Utility::MemUtils::COPY128(m_hashList[N], 0, LSub, 0);
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
#if defined(__AVX512__)
	const size_t AVX512BLK = 16 * BLOCK_SIZE;
	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		const size_t SUBBLK = PBKALN / AVX512BLK;

		Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, PBKALN);

		for (size_t i = 0; i < SUBBLK; ++i)
		{
			m_blockCipher->Transform2048(Output, OutOffset + (i * AVX512BLK), Output, OutOffset + (i * AVX512BLK));
		}

		Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, PBKALN);
	}
#elif defined(__AVX2__)
	const size_t AVX2BLK = 8 * BLOCK_SIZE;
	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		const size_t SUBBLK = PBKALN / AVX2BLK;

		Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, PBKALN);

		for (size_t i = 0; i < SUBBLK; ++i)
		{
			m_blockCipher->Transform1024(Output, OutOffset + (i * AVX2BLK), Output, OutOffset + (i * AVX2BLK));
		}

		Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, PBKALN);
	}
#elif defined(__AVX__)
	const size_t AVXBLK = 4 * BLOCK_SIZE;
	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		const size_t SUBBLK = PBKALN / AVXBLK;
		Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, PBKALN);

		for (size_t i = 0; i < SUBBLK; ++i)
		{
			m_blockCipher->Transform512(Output, OutOffset + (i * AVXBLK), Output, OutOffset + (i * AVXBLK));
		}

		Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, PBKALN);
	}
#else
	const size_t PBKALN = Length - (Length % BLOCK_SIZE);
	const size_t SUBBLK = PBKALN / BLOCK_SIZE;
	Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, PBKALN);

	for (size_t i = 0; i < SUBBLK; ++i)
	{
		m_blockCipher->Transform(Output, OutOffset + (i * BLOCK_SIZE), Output, OutOffset + (i * BLOCK_SIZE));
	}

	Utility::MemUtils::XorBlock(Input, InOffset, Output, OutOffset, PBKALN);
#endif
}

void OCB::ParallelDecrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t BLKCNT = Length / BLOCK_SIZE;
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	const size_t OUTOFF = OutOffset;

	// copy data into working output
	Utility::MemUtils::Copy(Input, InOffset, Output, OutOffset, ALNLEN);
	// create the offset chain
	std::vector<byte> offsetChain(ALNLEN);
	std::vector<byte> hash(BLOCK_SIZE);

	for (size_t i = 0; i < BLKCNT; ++i)
	{
		GetLSub(Ntz(++m_mainBlockCount), hash);
		Utility::MemUtils::XorBlock(hash, 0, m_mainOffset, 0, BLOCK_SIZE);
		Utility::MemUtils::COPY128(m_mainOffset, 0, offsetChain, i * BLOCK_SIZE);
	}

	// parallel offsets
	const size_t PRLLEN = m_parallelProfile.ParallelBlockSize();
	const size_t CNKLEN = PRLLEN / m_parallelProfile.ParallelMaxDegree();
	size_t chainPos = 0;

	while (Length >= PRLLEN)
	{
		Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Output, OutOffset, &offsetChain, chainPos, CNKLEN](size_t i)
		{
			this->ProcessSegment(offsetChain, chainPos + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
		});

		Length -= PRLLEN;
		OutOffset += PRLLEN;
		chainPos += PRLLEN;
	}

	if (Length != 0)
	{
		while (Length >= BLOCK_SIZE)
		{
			Utility::MemUtils::XorBlock(offsetChain, chainPos, Output, OutOffset, BLOCK_SIZE);
			m_blockCipher->Transform(Output, OutOffset, Output, OutOffset);
			Utility::MemUtils::XorBlock(offsetChain, chainPos, Output, OutOffset, BLOCK_SIZE);

			Length -= BLOCK_SIZE;
			OutOffset += BLOCK_SIZE;
			chainPos += BLOCK_SIZE;
		}

		if (Length != 0)
		{
			ProcessPartial(Input, InOffset + ALNLEN, Output, OutOffset, Length);
		}
	}

	// update the checksum
	for (size_t i = 0; i < BLKCNT; ++i)
	{
		Utility::MemUtils::XorBlock(Output, OUTOFF + (i * BLOCK_SIZE), m_checkSum, 0, BLOCK_SIZE);
	}
}

void OCB::ParallelEncrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t BLKCNT = Length / BLOCK_SIZE;
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);

	// copy data into working output
	Utility::MemUtils::Copy(Input, InOffset, Output, OutOffset, ALNLEN);

	// pre-fold the checksum
	for (size_t i = 0; i < BLKCNT; ++i)
	{
		Utility::MemUtils::XOR128(Output, OutOffset + (i * BLOCK_SIZE), m_checkSum, 0);
	}

	// create the offset chain
	std::vector<byte> offsetChain(ALNLEN);
	std::vector<byte> hash(BLOCK_SIZE);

	for (size_t i = 0; i < BLKCNT; ++i)
	{
		GetLSub(Ntz(++m_mainBlockCount), hash);
		Utility::MemUtils::XOR128(hash, 0, m_mainOffset, 0);
		Utility::MemUtils::COPY128(m_mainOffset, 0, offsetChain, i * BLOCK_SIZE);
	}

	// parallel offsets
	const size_t PRLLEN = m_parallelProfile.ParallelBlockSize();
	const size_t CNKLEN = PRLLEN / m_parallelProfile.ParallelMaxDegree();
	size_t chainPos = 0;

	while (Length >= PRLLEN)
	{
		Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Output, OutOffset, &offsetChain, chainPos, CNKLEN](size_t i)
		{
			this->ProcessSegment(offsetChain, chainPos + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
		});

		Length -= PRLLEN;
		OutOffset += PRLLEN;
		chainPos += PRLLEN;
	}

	if (Length != 0)
	{
		while (Length >= BLOCK_SIZE)
		{
			Utility::MemUtils::XOR128(offsetChain, chainPos, Output, OutOffset);
			m_blockCipher->Transform(Output, OutOffset, Output, OutOffset);
			Utility::MemUtils::XOR128(offsetChain, chainPos, Output, OutOffset);

			Length -= BLOCK_SIZE;
			OutOffset += BLOCK_SIZE;
			chainPos += BLOCK_SIZE;
		}

		if (Length != 0)
		{
			ProcessPartial(Input, InOffset + ALNLEN, Output, OutOffset, Length);
		}
	}
}

void OCB::ProcessPartial(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, size_t Length)
{
	if (m_isEncryption)
	{
		Utility::MemUtils::Copy(Input, InOffset, Output, OutOffset, Length);
		ExtendBlock(Output, OutOffset + Length);

		Utility::MemUtils::XorBlock(Output, OutOffset, m_checkSum, 0, Length + 1);
		Utility::MemUtils::XOR128(m_listAsterisk, 0, m_mainOffset, 0);

		std::vector<byte> pad(BLOCK_SIZE);
		m_hashCipher->Transform(m_mainOffset, 0, pad, 0);
		Utility::MemUtils::XOR128(pad, 0, Output, OutOffset);
	}
	else
	{
		Utility::MemUtils::Copy(Input, InOffset, Output, OutOffset, Length);
		Utility::MemUtils::XOR128(m_listAsterisk, 0, m_mainOffset, 0);

		std::vector<byte> pad(BLOCK_SIZE);
		m_hashCipher->Transform(m_mainOffset, 0, pad, 0);
		Utility::MemUtils::XorBlock(pad, 0, Output, OutOffset, Length);

		std::vector<byte> tmp(BLOCK_SIZE);
		Utility::MemUtils::Copy(Output, OutOffset, tmp, 0, Length);
		ExtendBlock(tmp, Length);
		Utility::MemUtils::XOR128(tmp, 0, m_checkSum, 0);
	}
}

void OCB::Reset()
{
	if (!m_aadPreserve)
	{
		m_aadLoaded = false;
		Utility::MemUtils::Clear(m_aadData, 0, m_aadData.size());
	}

	m_mainBlockCount = 0;
	Utility::MemUtils::Clear(m_checkSum, 0, m_checkSum.size());
	Utility::MemUtils::Clear(m_listAsterisk, 0, m_listAsterisk.size());
	Utility::MemUtils::Clear(m_listDollar, 0, m_listDollar.size());
	Utility::MemUtils::Clear(m_mainOffset, 0, m_mainOffset.size());
	Utility::MemUtils::Clear(m_mainOffset0, 0, m_mainOffset0.size());
	Utility::MemUtils::Clear(m_mainStretch, 0, m_mainStretch.size());
	Utility::MemUtils::Clear(m_ocbVector, 0, m_ocbVector.size());
	Utility::MemUtils::Clear(m_topInput, 0, m_topInput.size());
	m_hashList.clear();
	m_isInitialized = false;
}

void OCB::Scope()
{
	std::vector<SymmetricKeySize> keySizes = m_blockCipher->LegalKeySizes();
	m_legalKeySizes.resize(keySizes.size());

	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
	{
		m_legalKeySizes[i] = SymmetricKeySize(keySizes[i].KeySize(), MAX_NONCESIZE, keySizes[i].NonceSize());
	}

	m_hashList.clear();
	m_hashList.reserve(PREFETCH_HASH);

	if (!m_parallelProfile.IsDefault())
	{
		m_parallelProfile.Calculate();
	}
}

NAMESPACE_MODEEND
