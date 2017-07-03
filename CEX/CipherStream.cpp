#include "CipherStream.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "MemUtils.h"
#include "PaddingFromName.h"
#include "ParallelUtils.h"
#include "StreamCipherFromName.h"

NAMESPACE_PROCESSING

//~~~Properties~~~//

bool CipherStream::IsParallel() 
{
	if (m_isStreamCipher)
		return m_streamCipher->IsParallel();
	else
		return m_cipherEngine->IsParallel();
}

const std::vector<SymmetricKeySize> CipherStream::LegalKeySizes() 
{ 
	return m_legalKeySizes; 
}

size_t CipherStream::ParallelBlockSize() 
{ 
	if (m_isStreamCipher)
		return m_streamCipher->ParallelBlockSize();
	else
		return m_cipherEngine->ParallelBlockSize();
}

ParallelOptions &CipherStream::ParallelProfile()
{
	if (m_isStreamCipher)
		return m_streamCipher->ParallelProfile();
	else
		return m_cipherEngine->ParallelProfile();
}

//~~~Constructor~~~//

CipherStream::CipherStream(BlockCiphers CipherType, Digests KdfEngine, int RoundCount, CipherModes ModeType, PaddingModes PaddingType)
	:
	m_blockCipher(0),
	m_cipherPadding(0),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_isStreamCipher(false),
	m_legalKeySizes(0),
	m_streamCipher(0)
{
	m_cipherEngine = GetCipherMode(ModeType, CipherType, 16, RoundCount, KdfEngine);
	Scope();

	if (!m_isCounterMode)
		m_cipherPadding = GetPaddingMode(PaddingType);

}

CipherStream::CipherStream(StreamCiphers CipherType, size_t RoundCount)
	:
	m_blockCipher(0),
	m_cipherPadding(0),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_isStreamCipher(true),
	m_legalKeySizes(0),
	m_streamCipher(0)
{
	if (CipherType != StreamCiphers::ChaCha20 && CipherType != StreamCiphers::Salsa20)
		throw CryptoProcessingException("CipherStream:CTor", "The stream cipher is not recognized!");
	if (RoundCount < 10 || RoundCount > 30 || RoundCount % 2 != 0)
		throw CryptoProcessingException("CipherStream:CTor", "Invalid rounds count; must be an even number between 10 and 30!");

	m_streamCipher = GetStreamCipher(CipherType, RoundCount);
	Scope();
}

CipherStream::CipherStream(CipherDescription* Header)
	:
	m_blockCipher(0),
	m_cipherPadding(0),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isParallel(false),
	m_legalKeySizes(0),
	m_streamCipher(0)
{
	if (Header == 0)
		throw CryptoProcessingException("CipherStream:CTor", "The key Header is invalid!");

	m_isStreamCipher = false;
	m_cipherEngine = GetCipherMode(Header->CipherType(), Header->EngineType(), (int)Header->BlockSize(), (int)Header->RoundCount(), Header->KdfEngine());

	if (!m_isCounterMode && Header->PaddingType() != PaddingModes::None)
		m_cipherPadding = GetPaddingMode(Header->PaddingType());

	Scope();
}

CipherStream::CipherStream(ICipherMode* Cipher, IPadding* Padding)
	:
	m_blockCipher(0),
	m_cipherEngine(Cipher),
	m_cipherPadding(Padding),
	m_destroyEngine(false),
	m_isBufferedIO(false),
	m_isDestroyed(false),
	m_isEncryption(Cipher->IsEncryption()),
	m_isInitialized(false),
	m_isStreamCipher(false),
	m_isParallel(false),
	m_legalKeySizes(0),
	m_streamCipher(0)
{
	if (m_cipherEngine->IsInitialized())
		throw CryptoProcessingException("CipherStream:CTor", "The cipher must be initialized through the local Initialize() method!");
	if (m_cipherPadding == 0 && m_cipherEngine->Enumeral() != CipherModes::CTR)
		m_cipherPadding = GetPaddingMode(PaddingModes::X923);

	Scope();
}

CipherStream::CipherStream(IStreamCipher* Cipher)
	:
	m_blockCipher(0),
	m_cipherPadding(0),
	m_destroyEngine(false),
	m_isBufferedIO(false),
	m_isDestroyed(false),
	m_isEncryption(),
	m_isInitialized(false),
	m_isParallel(false),
	m_isStreamCipher(true),
	m_streamCipher(Cipher)
{
	if (Cipher == 0)
		throw CryptoProcessingException("CipherStream:CTor", "The Cipher can not be null!");
	if (Cipher->IsInitialized())
		throw CryptoProcessingException("The cipher must be initialized through the local Initialize() method!");

	Scope();
}

CipherStream::~CipherStream()
{
	Destroy();
}

//~~~Public Functions~~~//

void CipherStream::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isCounterMode = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_isStreamCipher = false;

		if (m_destroyEngine)
		{
			try
			{
				if (m_blockCipher != 0)
					delete m_blockCipher;
				if (m_cipherEngine != 0)
					delete m_cipherEngine;
				if (m_streamCipher != 0)
					delete m_streamCipher;
				if (m_cipherPadding != 0)
					delete m_cipherPadding;

				m_isDestroyed = true;
			}
			catch(std::exception& ex) 
			{
				throw CryptoProcessingException("CipherStream:Destroy", "The engines were not heap allocated!", std::string(ex.what()));
			}
		}

	}
}

void CipherStream::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		throw CryptoProcessingException("CipherStream:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");

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
	if (!m_isStreamCipher)
		m_cipherEngine->ParallelProfile().SetMaxDegree(Degree);
	else
		m_streamCipher->ParallelProfile().SetMaxDegree(Degree);
}

void CipherStream::Write(IByteStream* InStream, IByteStream* OutStream)
{
	CEXASSERT(m_isInitialized, "the cipher has not been initialized");
	CEXASSERT(InStream->Length() - InStream->Position() > 0, "the Input stream is too short");
	CEXASSERT(InStream->CanRead(), "the Input stream is set to write only!");
	CEXASSERT(OutStream->CanRead() || OutStream->CanWrite(), "the Output stream is to read only!");

	if (!m_isStreamCipher)
		BlockTransform(InStream, OutStream);
	else
		StreamTransform(InStream, OutStream);

	if (OutStream->Position() != OutStream->Length())
		OutStream->SetLength(OutStream->Position());
}

void CipherStream::Write(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "the cipher has not been initialized");
	CEXASSERT(Input.size() - InOffset > 0, "the input array is too short");
	CEXASSERT(Input.size() - InOffset <= Output.size() - OutOffset, "the output array is too short!");

	if (!m_isStreamCipher)
		BlockTransform(Input, InOffset, Output, OutOffset);
	else
		StreamTransform(Input, InOffset, Output, OutOffset);
}

//~~~Private Functions~~~//

void CipherStream::BlockTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t INPSZE = Input.size() - InOffset;
	size_t prcLen = 0;

	if (m_isParallel)
	{
		const size_t PRLBLK = m_cipherEngine->ParallelBlockSize();
		if (INPSZE > PRLBLK)
		{
			const size_t PRCSZE = (INPSZE % PRLBLK != 0 || m_isCounterMode || m_isEncryption) ? (INPSZE / PRLBLK) * PRLBLK : ((INPSZE / PRLBLK) * PRLBLK) - PRLBLK;

			while (prcLen != PRCSZE)
			{
				m_cipherEngine->Transform(Input, InOffset, Output, OutOffset, PRLBLK);
				InOffset += PRLBLK;
				OutOffset += PRLBLK;
				prcLen += PRLBLK;
				CalculateProgress(INPSZE, InOffset);
			}
		}
	}

	const size_t BLKSZE = m_cipherEngine->BlockSize();
	const size_t ALNSZE = (m_isCounterMode || m_isEncryption) ? (INPSZE / BLKSZE) * BLKSZE : (INPSZE < BLKSZE) ? 0 : ((INPSZE / BLKSZE) * BLKSZE) - BLKSZE;

	if (INPSZE > BLKSZE)
	{
		while (prcLen != ALNSZE)
		{
			m_cipherEngine->Transform(Input, InOffset, Output, OutOffset, BLKSZE);
			InOffset += BLKSZE;
			OutOffset += BLKSZE;
			prcLen += BLKSZE;
			CalculateProgress(INPSZE, InOffset);
		}
	}

	// partial
	if (ALNSZE != INPSZE)
	{
		if (m_isCounterMode)
		{
			const size_t FNLSZE = INPSZE - ALNSZE;
			std::vector<byte> inpBuffer(BLKSZE);
			Utility::MemUtils::Copy<byte>(Input, InOffset, inpBuffer, 0, FNLSZE);
			std::vector<byte> outBuffer(BLKSZE);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0, FNLSZE);
			Utility::MemUtils::Copy<byte>(outBuffer, 0, Output, OutOffset, FNLSZE);
			prcLen += FNLSZE;
		}
		else if (m_isEncryption)
		{
			const size_t FNLSZE = INPSZE - ALNSZE;
			std::vector<byte> inpBuffer(BLKSZE);
			Utility::MemUtils::Copy<byte>(Input, InOffset, inpBuffer, 0, FNLSZE);
			if (FNLSZE != BLKSZE)
				m_cipherPadding->AddPadding(inpBuffer, FNLSZE);
			prcLen += BLKSZE;

			if (Output.size() != prcLen)
				Output.resize(prcLen);

			m_cipherEngine->EncryptBlock(inpBuffer, 0, Output, OutOffset);
		}
		else
		{
			std::vector<byte> outBuffer(BLKSZE);
			m_cipherEngine->DecryptBlock(Input, InOffset, outBuffer, 0);
			const size_t PADLEN = m_cipherPadding->GetPaddingLength(outBuffer, 0);
			const size_t FNLSZE = (PADLEN == 0) ? BLKSZE : BLKSZE - PADLEN;
			Utility::MemUtils::Copy<byte>(outBuffer, 0, Output, OutOffset, FNLSZE);
			prcLen += FNLSZE;

			if (Output.size() != prcLen)
				Output.resize(prcLen);
		}
	}

	CalculateProgress(INPSZE, InOffset);
}

void CipherStream::BlockTransform(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t INPSZE = InStream->Length() - InStream->Position();
	size_t prcLen = 0;
	size_t prcRead = 0;
	std::vector<byte> inpBuffer(0);
	std::vector<byte> outBuffer(0);

	if (m_isParallel)
	{
		const size_t PRLBLK = m_cipherEngine->ParallelBlockSize();
		if (INPSZE > PRLBLK)
		{
			const size_t PRCSZE = (INPSZE % PRLBLK != 0 || m_isCounterMode || m_isEncryption) ? (INPSZE / PRLBLK) * PRLBLK : ((INPSZE / PRLBLK) * PRLBLK) - PRLBLK;
			inpBuffer.resize(PRLBLK);
			outBuffer.resize(PRLBLK);

			while (prcLen != PRCSZE)
			{
				prcRead = InStream->Read(inpBuffer, 0, PRLBLK);
				m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
				OutStream->Write(outBuffer, 0, prcRead);
				prcLen += prcRead;
				CalculateProgress(INPSZE, OutStream->Position());
			}
		}
	}

	const size_t BLKSZE = m_cipherEngine->BlockSize();
	const size_t ALNSZE = (m_isCounterMode || m_isEncryption) ? (INPSZE / BLKSZE) * BLKSZE : (INPSZE < BLKSZE) ? 0 : ((INPSZE / BLKSZE) * BLKSZE) - BLKSZE;
	inpBuffer.resize(BLKSZE);
	outBuffer.resize(BLKSZE);

	if (INPSZE > BLKSZE)
	{
		while (prcLen != ALNSZE)
		{
			prcRead = InStream->Read(inpBuffer, 0, BLKSZE);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
			OutStream->Write(outBuffer, 0, prcRead);
			prcLen += prcRead;
			CalculateProgress(INPSZE, OutStream->Position());
		}
	}

	// partial
	if (ALNSZE != INPSZE)
	{
		if (m_isCounterMode)
		{
			const size_t FNLSZE = INPSZE - ALNSZE;
			Utility::MemUtils::Clear<byte>(outBuffer, 0, outBuffer.size());
			Utility::MemUtils::Clear<byte>(inpBuffer, 0, inpBuffer.size());
			prcRead = InStream->Read(inpBuffer, 0, FNLSZE);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
			OutStream->Write(outBuffer, 0, prcRead);
		}
		else if (m_isEncryption)
		{
			const size_t FNLSZE = INPSZE - ALNSZE;
			prcRead = InStream->Read(inpBuffer, 0, FNLSZE);
			if (FNLSZE != BLKSZE)
				m_cipherPadding->AddPadding(inpBuffer, prcRead);
			m_cipherEngine->EncryptBlock(inpBuffer, 0, outBuffer, 0);
			OutStream->Write(outBuffer, 0, BLKSZE);
		}
		else
		{
			InStream->Read(inpBuffer, 0, BLKSZE);
			m_cipherEngine->DecryptBlock(inpBuffer, 0, outBuffer, 0);
			const size_t PADLEN = m_cipherPadding->GetPaddingLength(outBuffer, 0);
			const size_t FNLSZE = (PADLEN == 0) ? BLKSZE : BLKSZE - PADLEN;
			OutStream->Write(outBuffer, 0, FNLSZE);
		}
	}

	CalculateProgress(INPSZE, OutStream->Position());
}

void CipherStream::StreamTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t INPSZE = Input.size() - InOffset;
	size_t prcLen = 0;

	if (m_isParallel)
	{
		const size_t PRLBLK = m_streamCipher->ParallelBlockSize();
		if (INPSZE > PRLBLK)
		{
			const size_t PRCSZE = (INPSZE / PRLBLK) * PRLBLK;

			while (prcLen != PRCSZE)
			{
				m_streamCipher->Transform(Input, InOffset, Output, OutOffset, PRLBLK);
				InOffset += PRLBLK;
				OutOffset += PRLBLK;
				prcLen += PRLBLK;
				CalculateProgress(INPSZE, InOffset);
			}
		}
	}

	const size_t BLKSZE = m_streamCipher->BlockSize();
	const size_t ALNSZE = (INPSZE / BLKSZE) * BLKSZE;

	if (INPSZE > BLKSZE)
	{
		while (prcLen != ALNSZE)
		{
			m_streamCipher->Transform(Input, InOffset, Output, OutOffset, BLKSZE);
			InOffset += BLKSZE;
			OutOffset += BLKSZE;
			prcLen += BLKSZE;
			CalculateProgress(INPSZE, InOffset);
		}
	}

	// partial
	if (ALNSZE != INPSZE)
	{
		const size_t FNLSZE = INPSZE - ALNSZE;
		m_streamCipher->Transform(Input, InOffset, Output, OutOffset, FNLSZE);
		prcLen += FNLSZE;
	}

	CalculateProgress(INPSZE, prcLen);
}

void CipherStream::StreamTransform(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t INPSZE = InStream->Length() - InStream->Position();
	size_t prcLen = 0;
	size_t prcRead = 0;
	std::vector<byte> inpBuffer(0);
	std::vector<byte> outBuffer(0);

	if (m_isParallel)
	{
		const size_t PRLBLK = m_streamCipher->ParallelBlockSize();
		if (INPSZE > PRLBLK)
		{
			const size_t PRCSZE = (INPSZE / PRLBLK) * PRLBLK;
			inpBuffer.resize(PRLBLK);
			outBuffer.resize(PRLBLK);

			while (prcLen != PRCSZE)
			{
				prcRead = InStream->Read(inpBuffer, 0, PRLBLK);
				m_streamCipher->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
				OutStream->Write(outBuffer, 0, prcRead);
				prcLen += prcRead;
				CalculateProgress(INPSZE, OutStream->Position());
			}
		}
	}

	const size_t BLKSZE = m_streamCipher->BlockSize();
	const size_t ALNSZE = (INPSZE / BLKSZE) * BLKSZE;
	inpBuffer.resize(BLKSZE);
	outBuffer.resize(BLKSZE);

	if (INPSZE > BLKSZE)
	{
		while (prcLen != ALNSZE)
		{
			prcRead = InStream->Read(inpBuffer, 0, BLKSZE);
			m_streamCipher->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
			OutStream->Write(outBuffer, 0, prcRead);
			prcLen += prcRead;
			CalculateProgress(INPSZE, OutStream->Position());
		}
	}

	if (ALNSZE != INPSZE)
	{
		const size_t FNLSZE = INPSZE - ALNSZE;
		inpBuffer.resize(FNLSZE);
		prcRead = InStream->Read(inpBuffer, 0, FNLSZE);
		outBuffer.resize(prcRead);
		m_streamCipher->Transform(inpBuffer, 0, outBuffer, 0, prcRead);
		OutStream->Write(outBuffer, 0, prcRead);
	}

	CalculateProgress(INPSZE, OutStream->Position());
}

void CipherStream::CalculateProgress(size_t Length, size_t Processed)
{
	if (Length >= Processed)
	{
		double progress = 100.0 * ((double)Processed / Length);
		if (progress > 100.0)
			progress = 100.0;

		if (m_isParallel)
		{
			ProgressPercent((int)progress);
		}
		else
		{
			size_t block = Length / 100;
			if (block == 0)
				ProgressPercent((int)progress);
			else if (Processed % block == 0)
				ProgressPercent((int)progress);
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
		m_isCounterMode = false;
		m_isParallel = m_streamCipher->IsParallel();
		m_legalKeySizes = m_streamCipher->LegalKeySizes();
	}
	else
	{
		m_isCounterMode = (m_cipherEngine->Enumeral() == CipherModes::CTR || m_cipherEngine->Enumeral() == CipherModes::ICM);
		m_isParallel = m_cipherEngine->IsParallel();
		m_legalKeySizes = m_cipherEngine->LegalKeySizes();
	}
}

NAMESPACE_PROCESSINGEND