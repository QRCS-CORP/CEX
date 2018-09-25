#include "CipherStream.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "IntUtils.h"
#include "PaddingFromName.h"
#include "StreamCipherFromName.h"

NAMESPACE_PROCESSING

//~~~Constructor~~~//

CipherStream::CipherStream(CipherDescription* Description)
	:
	m_cipherEngine(Description->CipherModeType() != CipherModes::None && Description->CipherType() != BlockCiphers::None ? GetCipherMode(Description->CipherType(), Description->CipherExtensionType(), Description->CipherModeType()) :
		throw CryptoProcessingException("CipherStream:CTor", "The cipher type or mode is invalid!")),
	m_cipherPadding(Description->CipherModeType() == CipherModes::CBC || Description->CipherModeType() == CipherModes::CFB || Description->CipherModeType() == CipherModes::OCB ? GetPaddingMode(Description->PaddingType()) : nullptr),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isCounterMode(Description->CipherModeType() == CipherModes::CTR || Description->CipherModeType() == CipherModes::ICM),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_legalKeySizes(0)
{
	Scope();
}

CipherStream::CipherStream(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, CipherModes CipherModeType, PaddingModes PaddingType)
	:
	m_cipherEngine(CipherModeType != CipherModes::None && CipherType != BlockCiphers::None ? GetCipherMode(CipherType, CipherExtensionType, CipherModeType) :
		throw CryptoProcessingException("CipherStream:CTor", "The cipher type or mode is invalid!")),
	m_cipherPadding(CipherModeType == CipherModes::CBC || CipherModeType == CipherModes::CFB || CipherModeType == CipherModes::OCB ? GetPaddingMode(PaddingType) : nullptr),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isCounterMode(CipherModeType == CipherModes::CTR || CipherModeType == CipherModes::ICM),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_legalKeySizes(0)
{
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
	m_isParallel(false),
	m_legalKeySizes(0)
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
		}
	}
}

//~~~Accessors~~~//

bool CipherStream::IsParallel() 
{
	return m_cipherEngine->IsParallel();
}

const std::vector<SymmetricKeySize> CipherStream::LegalKeySizes() 
{ 
	return m_legalKeySizes; 
}

size_t CipherStream::ParallelBlockSize() 
{ 
	return m_cipherEngine->ParallelBlockSize();
}

ParallelOptions &CipherStream::ParallelProfile()
{
	return m_cipherEngine->ParallelProfile();
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
		m_cipherEngine->ParallelProfile().IsParallel() = m_isParallel;
		m_cipherEngine->Initialize(Encryption, KeyParams);

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

	m_cipherEngine->ParallelProfile().SetMaxDegree(Degree);
}

void CipherStream::Write(IByteStream* InStream, IByteStream* OutStream)
{
	CexAssert(m_isInitialized, "the cipher has not been initialized");
	CexAssert(InStream->Length() - InStream->Position() > 0, "the Input stream is too short");
	CexAssert(InStream->CanRead(), "the Input stream is set to write only!");
	CexAssert(OutStream->CanRead() || OutStream->CanWrite(), "the Output stream is to read only!");

	BlockTransform(InStream, OutStream);

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

	BlockTransform(Input, InOffset, Output, OutOffset);
}

//~~~Private Functions~~~//

void CipherStream::BlockTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t INPLEN = Input.size() - InOffset;
	size_t prcLen;

	prcLen = 0;

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
	size_t prcLen;
	size_t prcRead;
	std::vector<byte> inpBuffer(0);
	std::vector<byte> outBuffer(0);

	prcLen = 0;
	prcRead = 0;

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

ICipherMode* CipherStream::GetCipherMode(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, CipherModes CipherModeType)
{
	try
	{
		return Helper::CipherModeFromName::GetInstance(CipherType, CipherExtensionType, CipherModeType);
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

void CipherStream::Scope()
{
	m_isParallel = m_cipherEngine->IsParallel();
	m_legalKeySizes = m_cipherEngine->LegalKeySizes();
}

NAMESPACE_PROCESSINGEND
