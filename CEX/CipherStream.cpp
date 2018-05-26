#include "CipherStream.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "PaddingFromName.h"
#include "StreamCipherFromName.h"

NAMESPACE_PROCESSING

//~~~Constructor~~~//

CipherStream::CipherStream(BlockCiphers CipherType, Digests KdfEngine, int RoundCount, CipherModes ModeType, PaddingModes PaddingType)
	:
	m_cipherEngine(ModeType != CipherModes::None && CipherType != BlockCiphers::None ? GetCipherMode(ModeType, CipherType, 16, RoundCount, KdfEngine) :
		throw CryptoProcessingException("CipherStream:CTor", "The cipher type or mode is invalid!")),
	m_cipherPadding(ModeType != CipherModes::CTR && ModeType != CipherModes::ICM ? GetPaddingMode(PaddingType) : nullptr),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isCounterMode(ModeType == CipherModes::CTR || ModeType == CipherModes::ICM),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_isStreamCipher(false),
	m_legalKeySizes(0),
	m_streamCipher(nullptr)
{
	Scope();
}

CipherStream::CipherStream(StreamCiphers CipherType, size_t RoundCount)
	:
	m_cipherPadding(nullptr),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isCounterMode(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_isStreamCipher(true),
	m_legalKeySizes(0),
	m_streamCipher(CipherType != StreamCiphers::None ? GetStreamCipher(CipherType, RoundCount) :
		throw CryptoProcessingException("CipherStream:CTor", "The stream cipher is not recognized!"))
{
	if (RoundCount < 10 || RoundCount > 30 || RoundCount % 2 != 0)
	{
		throw CryptoProcessingException("CipherStream:CTor", "Invalid rounds count; must be an even number between 10 and 30!");
	}

	Scope();
}

CipherStream::CipherStream(CipherDescription* Header)
	:
	m_cipherEngine(GetCipherMode(Header->CipherType(), Header->EngineType(), static_cast<int>(Header->BlockSize()), static_cast<int>(Header->RoundCount()), Header->KdfEngine())),
	m_cipherPadding(Header->CipherType() != CipherModes::CTR && Header->CipherType() != CipherModes::ICM && Header->PaddingType() != PaddingModes::None ? GetPaddingMode(Header->PaddingType()) : nullptr),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isCounterMode(Header->CipherType() == CipherModes::CTR || Header->CipherType() == CipherModes::ICM),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_legalKeySizes(0),
	m_streamCipher(nullptr)
{
	m_isStreamCipher = false;
	Scope();
}

CipherStream::CipherStream(ICipherMode* Cipher, IPadding* Padding)
	:
	m_cipherEngine(Cipher != nullptr ? Cipher :
		throw CryptoProcessingException("CipherStream:CTor", "The Cipher can not be null!")),
	m_cipherPadding(Padding),
	m_destroyEngine(false),
	m_isBufferedIO(false),
	m_isCounterMode(Cipher->Enumeral() == CipherModes::CTR || Cipher->Enumeral() == CipherModes::ICM),
	m_isDestroyed(false),
	m_isEncryption(Cipher->IsEncryption()),
	m_isInitialized(false),
	m_isStreamCipher(false),
	m_isParallel(false),
	m_legalKeySizes(0),
	m_streamCipher(nullptr)
{
	Scope();
}

CipherStream::CipherStream(IStreamCipher* Cipher)
	:
	m_cipherEngine(nullptr),
	m_cipherPadding(nullptr),
	m_destroyEngine(false),
	m_isBufferedIO(false),
	m_isCounterMode(false),
	m_isDestroyed(false),
	m_isEncryption(true),
	m_isInitialized(false),
	m_isParallel(false),
	m_isStreamCipher(true),
	m_legalKeySizes(0),
	m_streamCipher(Cipher != nullptr ? Cipher : 
		throw CryptoProcessingException("CipherStream:CTor", "The Cipher can not be null!"))
{
	Scope();
}

CipherStream::~CipherStream()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isCounterMode = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_isStreamCipher = false;
		Utility::IntUtils::ClearVector(m_legalKeySizes);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_cipherEngine != nullptr)
			{
				m_cipherEngine.reset(nullptr);
			}
			if (m_cipherPadding != nullptr)
			{
				m_cipherPadding.reset(nullptr);
			}
			if (m_streamCipher != nullptr)
			{
				m_streamCipher.reset(nullptr);
			}
		}
		else
		{
			if (m_cipherEngine != nullptr)
			{
				m_cipherEngine.release();
			}
			if (m_cipherPadding != nullptr)
			{
				m_cipherPadding.release();
			}
			if (m_streamCipher != nullptr)
			{
				m_streamCipher.release();
			}
		}
	}
}

//~~~Accessors~~~//

bool CipherStream::IsParallel() 
{
	if (m_isStreamCipher)
	{
		return m_streamCipher->IsParallel();
	}
	else
	{
		return m_cipherEngine->IsParallel();
	}
}

const std::vector<SymmetricKeySize> CipherStream::LegalKeySizes() 
{ 
	return m_legalKeySizes; 
}

size_t CipherStream::ParallelBlockSize() 
{ 
	if (m_isStreamCipher)
	{
		return m_streamCipher->ParallelBlockSize();
	}
	else
	{
		return m_cipherEngine->ParallelBlockSize();
	}
}

ParallelOptions &CipherStream::ParallelProfile()
{
	if (m_isStreamCipher)
	{
		return m_streamCipher->ParallelProfile();
	}
	else
	{
		return m_cipherEngine->ParallelProfile();
	}
}

//~~~Public Functions~~~//

void CipherStream::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
	{
		throw CryptoProcessingException("CipherStream:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	}

	try
	{
		if (!m_isStreamCipher)
		{
			m_cipherEngine->ParallelProfile().IsParallel() = m_isParallel;
			m_cipherEngine->Initialize(Encryption, KeyParams);
		}
		else
		{
			m_streamCipher->ParallelProfile().IsParallel() = m_isParallel;
			m_streamCipher->Initialize(KeyParams);
		}

		m_isEncryption = Encryption;
		m_isInitialized = true;
	}
	catch(std::exception& ex)
	{
		throw CryptoProcessingException("CipherStream:Initialize", "The key could not be loaded, check the key and iv sizes!", std::string(ex.what()));
	}
}

void CipherStream::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_cipherEngine->ParallelProfile().ProcessorCount(), "parallel degree can not exceed processor count");

	if (!m_isStreamCipher)
	{
		m_cipherEngine->ParallelProfile().SetMaxDegree(Degree);
	}
	else
	{
		m_streamCipher->ParallelProfile().SetMaxDegree(Degree);
	}
}

void CipherStream::Write(IByteStream* InStream, IByteStream* OutStream)
{
	CexAssert(m_isInitialized, "the cipher has not been initialized");
	CexAssert(InStream->Length() - InStream->Position() > 0, "the Input stream is too short");
	CexAssert(InStream->CanRead(), "the Input stream is set to write only!");
	CexAssert(OutStream->CanRead() || OutStream->CanWrite(), "the Output stream is to read only!");

	if (!m_isStreamCipher)
	{
		BlockTransform(InStream, OutStream);
	}
	else
	{
		StreamTransform(InStream, OutStream);
	}

	if (OutStream->Position() != OutStream->Length())
	{
		OutStream->SetLength(OutStream->Position());
	}
}

void CipherStream::Write(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CexAssert(m_isInitialized, "the cipher has not been initialized");
	CexAssert(Input.size() - InOffset > 0, "the input array is too short");
	CexAssert(Input.size() - InOffset <= Output.size() - OutOffset, "the output array is too short!");

	if (!m_isStreamCipher)
	{
		BlockTransform(Input, InOffset, Output, OutOffset);
	}
	else
	{
		StreamTransform(Input, InOffset, Output, OutOffset);
	}
}

//~~~Private Functions~~~//

void CipherStream::BlockTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t INPLEN = Input.size() - InOffset;
	size_t prcLen = 0;

	if (m_isParallel)
	{
		const size_t PRLBLK = m_cipherEngine->ParallelBlockSize();
		if (INPLEN > PRLBLK)
		{
			const size_t PRCLEN = (INPLEN % PRLBLK != 0 || m_isCounterMode || m_isEncryption) ? (INPLEN / PRLBLK) * PRLBLK : ((INPLEN / PRLBLK) * PRLBLK) - PRLBLK;

			while (prcLen != PRCLEN)
			{
				m_cipherEngine->Transform(Input, InOffset, Output, OutOffset, PRLBLK);
				InOffset += PRLBLK;
				OutOffset += PRLBLK;
				prcLen += PRLBLK;
				CalculateProgress(INPLEN, InOffset);
			}
		}
	}

	const size_t BLKLEN = m_cipherEngine->BlockSize();
	const size_t ALNLEN = (m_isCounterMode || m_isEncryption) ? (INPLEN / BLKLEN) * BLKLEN : (INPLEN < BLKLEN) ? 0 : ((INPLEN / BLKLEN) * BLKLEN) - BLKLEN;

	if (INPLEN > BLKLEN)
	{
		while (prcLen != ALNLEN)
		{
			m_cipherEngine->Transform(Input, InOffset, Output, OutOffset, BLKLEN);
			InOffset += BLKLEN;
			OutOffset += BLKLEN;
			prcLen += BLKLEN;
			CalculateProgress(INPLEN, InOffset);
		}
	}

	// partial
	if (ALNLEN != INPLEN)
	{
		if (m_isCounterMode)
		{
			const size_t FNLLEN = INPLEN - ALNLEN;
			std::vector<byte> inpBuffer(BLKLEN);
			Utility::MemUtils::Copy(Input, InOffset, inpBuffer, 0, FNLLEN);
			std::vector<byte> outBuffer(BLKLEN);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0, FNLLEN);
			Utility::MemUtils::Copy(outBuffer, 0, Output, OutOffset, FNLLEN);
			prcLen += FNLLEN;
		}
		else if (m_isEncryption)
		{
			const size_t FNLLEN = INPLEN - ALNLEN;
			std::vector<byte> inpBuffer(BLKLEN);
			Utility::MemUtils::Copy(Input, InOffset, inpBuffer, 0, FNLLEN);
			if (FNLLEN != BLKLEN)
			{
				m_cipherPadding->AddPadding(inpBuffer, FNLLEN);
			}
			prcLen += BLKLEN;

			if (Output.size() != prcLen)
			{
				Output.resize(prcLen);
			}

			m_cipherEngine->EncryptBlock(inpBuffer, 0, Output, OutOffset);
		}
		else
		{
			std::vector<byte> outBuffer(BLKLEN);
			m_cipherEngine->DecryptBlock(Input, InOffset, outBuffer, 0);
			const size_t PADLEN = m_cipherPadding->GetPaddingLength(outBuffer, 0);
			const size_t FNLLEN = (PADLEN == 0) ? BLKLEN : BLKLEN - PADLEN;
			Utility::MemUtils::Copy(outBuffer, 0, Output, OutOffset, FNLLEN);
			prcLen += FNLLEN;

			if (Output.size() != prcLen)
			{
				Output.resize(prcLen);
			}
		}
	}

	CalculateProgress(INPLEN, InOffset);
}

void CipherStream::BlockTransform(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t INPLEN = InStream->Length() - InStream->Position();
	size_t prcLen = 0;
	size_t prcRead = 0;
	std::vector<byte> inpBuffer(0);
	std::vector<byte> outBuffer(0);

	if (m_isParallel)
	{
		const size_t PRLBLK = m_cipherEngine->ParallelBlockSize();
		if (INPLEN > PRLBLK)
		{
			const size_t PRCLEN = (INPLEN % PRLBLK != 0 || m_isCounterMode || m_isEncryption) ? (INPLEN / PRLBLK) * PRLBLK : ((INPLEN / PRLBLK) * PRLBLK) - PRLBLK;
			inpBuffer.resize(PRLBLK);
			outBuffer.resize(PRLBLK);

			while (prcLen != PRCLEN)
			{
				prcRead = InStream->Read(inpBuffer, 0, PRLBLK);
				m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
				OutStream->Write(outBuffer, 0, prcRead);
				prcLen += prcRead;
				CalculateProgress(INPLEN, OutStream->Position());
			}
		}
	}

	const size_t BLKLEN = m_cipherEngine->BlockSize();
	const size_t ALNLEN = (m_isCounterMode || m_isEncryption) ? (INPLEN / BLKLEN) * BLKLEN : (INPLEN < BLKLEN) ? 0 : ((INPLEN / BLKLEN) * BLKLEN) - BLKLEN;
	inpBuffer.resize(BLKLEN);
	outBuffer.resize(BLKLEN);

	if (INPLEN > BLKLEN)
	{
		while (prcLen != ALNLEN)
		{
			prcRead = InStream->Read(inpBuffer, 0, BLKLEN);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
			OutStream->Write(outBuffer, 0, prcRead);
			prcLen += prcRead;
			CalculateProgress(INPLEN, OutStream->Position());
		}
	}

	// partial
	if (ALNLEN != INPLEN)
	{
		if (m_isCounterMode)
		{
			const size_t FNLLEN = INPLEN - ALNLEN;
			Utility::MemUtils::Clear(outBuffer, 0, outBuffer.size());
			Utility::MemUtils::Clear(inpBuffer, 0, inpBuffer.size());
			prcRead = InStream->Read(inpBuffer, 0, FNLLEN);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
			OutStream->Write(outBuffer, 0, prcRead);
		}
		else if (m_isEncryption)
		{
			const size_t FNLLEN = INPLEN - ALNLEN;
			prcRead = InStream->Read(inpBuffer, 0, FNLLEN);
			if (FNLLEN != BLKLEN)
			{
				m_cipherPadding->AddPadding(inpBuffer, prcRead);
			}
			m_cipherEngine->EncryptBlock(inpBuffer, 0, outBuffer, 0);
			OutStream->Write(outBuffer, 0, BLKLEN);
		}
		else
		{
			InStream->Read(inpBuffer, 0, BLKLEN);
			m_cipherEngine->DecryptBlock(inpBuffer, 0, outBuffer, 0);
			const size_t PADLEN = m_cipherPadding->GetPaddingLength(outBuffer, 0);
			const size_t FNLLEN = (PADLEN == 0) ? BLKLEN : BLKLEN - PADLEN;
			OutStream->Write(outBuffer, 0, FNLLEN);
		}
	}

	CalculateProgress(INPLEN, OutStream->Position());
}

void CipherStream::StreamTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t INPLEN = Input.size() - InOffset;
	size_t prcLen = 0;

	if (m_isParallel)
	{
		const size_t PRLBLK = m_streamCipher->ParallelBlockSize();
		if (INPLEN > PRLBLK)
		{
			const size_t PRCLEN = (INPLEN / PRLBLK) * PRLBLK;

			while (prcLen != PRCLEN)
			{
				m_streamCipher->Transform(Input, InOffset, Output, OutOffset, PRLBLK);
				InOffset += PRLBLK;
				OutOffset += PRLBLK;
				prcLen += PRLBLK;
				CalculateProgress(INPLEN, InOffset);
			}
		}
	}

	const size_t BLKLEN = m_streamCipher->BlockSize();
	const size_t ALNLEN = (INPLEN / BLKLEN) * BLKLEN;

	if (INPLEN > BLKLEN)
	{
		while (prcLen != ALNLEN)
		{
			m_streamCipher->Transform(Input, InOffset, Output, OutOffset, BLKLEN);
			InOffset += BLKLEN;
			OutOffset += BLKLEN;
			prcLen += BLKLEN;
			CalculateProgress(INPLEN, InOffset);
		}
	}

	// partial
	if (ALNLEN != INPLEN)
	{
		const size_t FNLLEN = INPLEN - ALNLEN;
		m_streamCipher->Transform(Input, InOffset, Output, OutOffset, FNLLEN);
		prcLen += FNLLEN;
	}

	CalculateProgress(INPLEN, prcLen);
}

void CipherStream::StreamTransform(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t INPLEN = InStream->Length() - InStream->Position();
	size_t prcLen = 0;
	size_t prcRead = 0;
	std::vector<byte> inpBuffer(0);
	std::vector<byte> outBuffer(0);

	if (m_isParallel)
	{
		const size_t PRLBLK = m_streamCipher->ParallelBlockSize();
		if (INPLEN > PRLBLK)
		{
			const size_t PRCLEN = (INPLEN / PRLBLK) * PRLBLK;
			inpBuffer.resize(PRLBLK);
			outBuffer.resize(PRLBLK);

			while (prcLen != PRCLEN)
			{
				prcRead = InStream->Read(inpBuffer, 0, PRLBLK);
				m_streamCipher->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
				OutStream->Write(outBuffer, 0, prcRead);
				prcLen += prcRead;
				CalculateProgress(INPLEN, OutStream->Position());
			}
		}
	}

	const size_t BLKLEN = m_streamCipher->BlockSize();
	const size_t ALNLEN = (INPLEN / BLKLEN) * BLKLEN;
	inpBuffer.resize(BLKLEN);
	outBuffer.resize(BLKLEN);

	if (INPLEN > BLKLEN)
	{
		while (prcLen != ALNLEN)
		{
			prcRead = InStream->Read(inpBuffer, 0, BLKLEN);
			m_streamCipher->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
			OutStream->Write(outBuffer, 0, prcRead);
			prcLen += prcRead;
			CalculateProgress(INPLEN, OutStream->Position());
		}
	}

	if (ALNLEN != INPLEN)
	{
		const size_t FNLLEN = INPLEN - ALNLEN;
		inpBuffer.resize(FNLLEN);
		prcRead = InStream->Read(inpBuffer, 0, FNLLEN);
		outBuffer.resize(prcRead);
		m_streamCipher->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
		OutStream->Write(outBuffer, 0, prcRead);
	}

	CalculateProgress(INPLEN, OutStream->Position());
}

void CipherStream::CalculateProgress(size_t Length, size_t Processed)
{
	if (Length >= Processed)
	{
		double progress = 100.0 * (static_cast<double>(Processed) / Length);
		if (progress > 100.0)
		{
			progress = 100.0;
		}

		if (m_isParallel)
		{
			ProgressPercent(static_cast<int>(progress));
		}
		else
		{
			size_t block = Length / 100;
			if (block == 0)
			{
				ProgressPercent(static_cast<int>(progress));
			}
			else if (Processed % block == 0)
			{
				ProgressPercent(static_cast<int>(progress));
			}
		}
	}
}

ICipherMode* CipherStream::GetCipherMode(CipherModes ModeType, BlockCiphers CipherType, int BlockSize, int RoundCount, Digests KdfEngine)
{
	try
	{
		return Helper::CipherModeFromName::GetInstance(ModeType, CipherType);
	}
	catch(std::exception& ex)
	{
		throw CryptoProcessingException("CipherStream:GetCipherMode", "The cipher mode could not be instantiated!", std::string(ex.what()));
	}
}

IPadding* CipherStream::GetPaddingMode(PaddingModes PaddingType)
{
	try
	{
		return Helper::PaddingFromName::GetInstance(PaddingType);
	}
	catch(std::exception& ex)
	{
		throw CryptoProcessingException("CipherStream:GetPaddingMode", "The padding could not be instantiated!", std::string(ex.what()));
	}
}

IStreamCipher* CipherStream::GetStreamCipher(StreamCiphers CipherType, size_t RoundCount)
{
	try
	{
		return Helper::StreamCipherFromName::GetInstance(CipherType, RoundCount);
	}
	catch(std::exception& ex)
	{
		throw CryptoProcessingException("CipherStream:GetStreamEngine", "The cipher could not be instantiated!", std::string(ex.what()));
	}
}

void CipherStream::Scope()
{
	if (m_isStreamCipher)
	{
		m_isParallel = m_streamCipher->IsParallel();
		m_legalKeySizes = m_streamCipher->LegalKeySizes();
	}
	else
	{
		m_isParallel = m_cipherEngine->IsParallel();
		m_legalKeySizes = m_cipherEngine->LegalKeySizes();
	}
}

NAMESPACE_PROCESSINGEND
