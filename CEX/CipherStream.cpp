#include "CipherStream.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "PaddingFromName.h"
#include "ParallelUtils.h"
#include "StreamCipherFromName.h"

NAMESPACE_PROCESSING

//~~~Constructor~~~//

CipherStream::CipherStream(BlockCiphers CipherType, Digests KdfEngine, int RoundCount, CipherModes ModeType, PaddingModes PaddingType)
	:
	m_blockCipher(0),
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isStreamCipher(false),
	m_legalKeySizes(0),
	m_parallelBlockSize(0),
	m_parallelMinimumSize(0),
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
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isStreamCipher(true),
	m_legalKeySizes(0),
	m_parallelBlockSize(0),
	m_parallelMinimumSize(0),
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
	m_destroyEngine(true),
	m_isBufferedIO(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_parallelBlockSize(0),
	m_parallelMinimumSize(0),
	m_streamCipher(0)
{
	if (Header == 0)
		throw CryptoProcessingException("CipherStream:CTor", "The key Header is invalid!");

	if (Header->EngineType() == SymmetricEngines::ChaCha20 || Header->EngineType() == SymmetricEngines::Salsa)
	{
		m_isStreamCipher = true;
		m_streamCipher = GetStreamCipher((StreamCiphers)Header->EngineType(), (int)Header->RoundCount());
	}
	else
	{
		m_isStreamCipher = false;
		m_cipherEngine = GetCipherMode(Header->CipherType(), (BlockCiphers)Header->EngineType(), (int)Header->BlockSize(), (int)Header->RoundCount(), Header->KdfEngine());

		if (!m_isCounterMode && Header->PaddingType() != PaddingModes::None)
			m_cipherPadding = GetPaddingMode(Header->PaddingType());
	}

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
	m_legalKeySizes(0),
	m_parallelBlockSize(0),
	m_parallelMinimumSize(0),
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
	m_isStreamCipher(true),
	m_parallelBlockSize(0),
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
		m_blockSize = 0;
		m_isCounterMode = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_isStreamCipher = false;
		m_parallelBlockSize = 0;

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
			}
			catch(std::exception& ex) 
			{
				throw CryptoProcessingException("CipherStream:Destroy", "The engines were not heap allocated!", std::string(ex.what()));
			}
		}

		m_isDestroyed = true;
	}
}

void CipherStream::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	try
	{
		if (!m_isStreamCipher)
			m_cipherEngine->Initialize(Encryption, KeyParams);
		else
			m_streamCipher->Initialize(KeyParams);
	}
	catch(std::exception& ex)
	{
		throw CryptoProcessingException("CipherStream:Initialize", "The key could not be loaded, check the key and iv sizes!", std::string(ex.what()));
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CipherStream::Write(IByteStream* InStream, IByteStream* OutStream)
{
	if (!m_isInitialized)
		throw CryptoProcessingException("CipherStream:Write", "The cipher has not been initialized; call the Initialize() function first!");
	if (InStream->Length() - InStream->Position() < 1)
		throw CryptoProcessingException("CipherStream:Write", "The Input stream is too short!");
	if (!InStream->CanRead())
		throw CryptoProcessingException("CipherStream:Write", "The Input stream is set to write only!");
	if (!OutStream->CanRead() || !OutStream->CanWrite())
		throw CryptoProcessingException("CipherStream:Write", "The Output stream is to read only! Must be read and write capable.");

	ParametersCheck();

	if (!m_isStreamCipher)
		BlockTransform(InStream, OutStream);
	else
		StreamTransform(InStream, OutStream);

	if (OutStream->Position() != OutStream->Length())
		OutStream->SetLength(OutStream->Position());
}

void CipherStream::Write(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	if (!m_isInitialized)
		throw CryptoProcessingException("CipherStream:Write", "The cipher has not been initialized; call the Initialize() function first!");
	if (Input.size() - InOffset < 1)
		throw CryptoProcessingException("CipherStream:Write", "The Input array is too short!");
	if (Input.size() - InOffset > Output.size() - OutOffset)
		throw CryptoProcessingException("CipherStream:Write", "The Output array is too short!");

	ParametersCheck();

	if (!m_isStreamCipher)
		BlockTransform(Input, InOffset, Output, OutOffset);
	else
		StreamTransform(Input, InOffset, Output, OutOffset);
}

//~~~Private Functions~~~//

void CipherStream::BlockTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t INPSZE = Input.size() - InOffset;
	size_t alnSze = 0;
	size_t blkSze = 0;
	size_t count = 0;

	if (m_isParallel && INPSZE >= m_cipherEngine->ParallelBlockSize())
	{
		blkSze = m_parallelBlockSize;
		alnSze = (INPSZE / m_parallelBlockSize) * m_parallelBlockSize;

		while (count != alnSze)
		{
			m_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
			InOffset += blkSze;
			OutOffset += blkSze;
			count += blkSze;
			CalculateProgress(INPSZE, count);
		}

		m_cipherEngine->ParallelProfile().IsParallel() = false;
	}
	else
	{
		m_cipherEngine->ParallelProfile().IsParallel() = false;
	}

	blkSze = m_blockSize;
	alnSze = (!m_isCounterMode && !m_isEncryption) ? (INPSZE < blkSze) ? 0 : INPSZE - blkSze : ((INPSZE / blkSze) * blkSze);

	while (count != alnSze)
	{
		m_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSze;
		OutOffset += blkSze;
		count += blkSze;
		CalculateProgress(INPSZE, count);
	}

	// partial
	if (alnSze != INPSZE)
	{
		if (m_isCounterMode)
		{
			size_t fnlSze = INPSZE - alnSze;
			std::vector<byte> inpBuffer(blkSze);
			memcpy(&inpBuffer[0], &Input[InOffset], fnlSze);
			std::vector<byte> outBuffer(blkSze);

			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
			memcpy(&Output[OutOffset], &outBuffer[0], fnlSze);
			count += fnlSze;
		}
		else if (m_isEncryption)
		{
			size_t fnlSze = INPSZE - alnSze;
			std::vector<byte> inpBuffer(blkSze);
			memcpy(&inpBuffer[0], &Input[InOffset], fnlSze);
			m_cipherPadding->AddPadding(inpBuffer, fnlSze);
			count += blkSze;
			if (Output.size() != count)
				Output.resize(count);

			m_cipherEngine->Transform(inpBuffer, 0, Output, OutOffset);
		}
		else
		{
			std::vector<byte> outBuffer(blkSze);
			m_cipherEngine->Transform(Input, InOffset, outBuffer, 0);
			size_t fnlSze = blkSze - m_cipherPadding->GetPaddingLength(outBuffer, 0);
			memcpy(&Output[OutOffset], &outBuffer[0], fnlSze);
			count += fnlSze;
			if (Output.size() != count)
				Output.resize(count);
		}
	}

	CalculateProgress(INPSZE, count);
}

void CipherStream::BlockTransform(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t INPSZE = InStream->Length() - InStream->Position();
	size_t alnSze = 0;
	size_t blkSze = 0;
	size_t count = 0;
	std::vector<byte> inpBuffer(0);
	std::vector<byte> outBuffer(0);

	if (m_isParallel && INPSZE >= m_cipherEngine->ParallelBlockSize())
	{
		blkSze = m_parallelBlockSize;
		alnSze = (INPSZE / m_parallelBlockSize) * m_parallelBlockSize;
		inpBuffer.resize(blkSze);
		outBuffer.resize(blkSze);

		while (count != alnSze)
		{
			InStream->Read(inpBuffer, 0, blkSze);
			m_cipherEngine->Transform(inpBuffer, outBuffer);
			OutStream->Write(outBuffer, 0, blkSze);
			count += blkSze;
			CalculateProgress(INPSZE, OutStream->Position());
		}

		m_cipherEngine->ParallelProfile().IsParallel() = false;
	}
	else
	{
		m_cipherEngine->ParallelProfile().IsParallel() = false;
	}

	blkSze = m_blockSize;
	alnSze = (!m_isCounterMode && !m_isEncryption) ? (INPSZE < blkSze) ? 0 : INPSZE - blkSze : ((INPSZE / blkSze) * blkSze);
	inpBuffer.resize(blkSze);
	outBuffer.resize(blkSze);

	while (count != alnSze)
	{
		InStream->Read(inpBuffer, 0, blkSze);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSze);
		count += blkSze;
		CalculateProgress(INPSZE, OutStream->Position());
	}

	// partial
	if (alnSze != INPSZE)
	{
		if (m_isCounterMode)
		{
			size_t fnlSze = INPSZE - alnSze;
			memset(&outBuffer[0], 0, outBuffer.size());
			memset(&inpBuffer[0], 0, inpBuffer.size());
			InStream->Read(inpBuffer, 0, fnlSze);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
			OutStream->Write(outBuffer, 0, fnlSze);
		}
		else if (m_isEncryption)
		{
			size_t fnlSze = INPSZE - alnSze;
			InStream->Read(inpBuffer, 0, fnlSze);
			m_cipherPadding->AddPadding(inpBuffer, fnlSze);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
			OutStream->Write(outBuffer, 0, blkSze);
		}
		else
		{
			InStream->Read(inpBuffer, 0, blkSze);
			m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
			size_t fnlSze = blkSze - m_cipherPadding->GetPaddingLength(outBuffer, 0);
			OutStream->Write(outBuffer, 0, fnlSze);
		}
	}

	CalculateProgress(INPSZE, OutStream->Position());
}

void CipherStream::StreamTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t INPSZE = Input.size() - InOffset;
	size_t alnSze = 0;
	size_t blkSze = 0;
	size_t count = 0;

	if (m_isParallel && INPSZE >= m_streamCipher->ParallelBlockSize())
	{
		blkSze = m_parallelBlockSize;
		alnSze = (INPSZE / m_parallelBlockSize) * m_parallelBlockSize;

		while (count != alnSze)
		{
			m_streamCipher->Transform(Input, InOffset, Output, OutOffset);
			InOffset += blkSze;
			OutOffset += blkSze;
			count += blkSze;
			CalculateProgress(INPSZE, count);
		}

		m_streamCipher->ParallelProfile().IsParallel() = false;
	}
	else
	{
		m_streamCipher->ParallelProfile().IsParallel() = false;
	}

	blkSze = m_blockSize;
	alnSze = (INPSZE / blkSze) * blkSze;

	while (count != alnSze)
	{
		m_streamCipher->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSze;
		OutOffset += blkSze;
		count += blkSze;
		CalculateProgress(INPSZE, count);
	}

	// partial
	if (alnSze != INPSZE)
	{
		size_t cnkSize = INPSZE - alnSze;
		std::vector<byte> inpBuffer(cnkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(cnkSize);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(INPSZE, count);
}

void CipherStream::StreamTransform(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t INPSZE = InStream->Length() - InStream->Position();
	size_t alnSze = 0;
	size_t blkSze = 0;
	size_t count = 0;
	std::vector<byte> inpBuffer(0);
	std::vector<byte> outBuffer(0);

	if (m_isParallel && INPSZE >= m_streamCipher->ParallelBlockSize())
	{
		blkSze = m_parallelBlockSize;
		alnSze = (INPSZE / m_parallelBlockSize) * m_parallelBlockSize;
		inpBuffer.resize(blkSze);
		outBuffer.resize(blkSze);

		while (count != alnSze)
		{
			InStream->Read(inpBuffer, 0, blkSze);
			m_streamCipher->Transform(inpBuffer, outBuffer);
			OutStream->Write(outBuffer, 0, blkSze);
			count += blkSze;
			CalculateProgress(INPSZE, OutStream->Position());
		}

		m_streamCipher->ParallelProfile().IsParallel() = false;
	}
	else
	{
		m_streamCipher->ParallelProfile().IsParallel() = false;
	}

	blkSze = m_blockSize;
	alnSze = (INPSZE / blkSze) * blkSze;
	inpBuffer.resize(blkSze);
	outBuffer.resize(blkSze);

	while (count != alnSze)
	{
		InStream->Read(inpBuffer, 0, blkSze);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSze);
		count += blkSze;
		CalculateProgress(INPSZE, OutStream->Position());
	}

	if (alnSze != INPSZE)
	{
		size_t cnkSize = INPSZE - alnSze;
		inpBuffer.resize(cnkSize);
		InStream->Read(inpBuffer, 0, cnkSize);
		outBuffer.resize(cnkSize);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, cnkSize);
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
			size_t chunk = Length / 100;
			if (chunk == 0)
				ProgressPercent((int)progress);
			else if (Processed % chunk == 0)
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

void CipherStream::ParametersCheck()
{
	if (m_isStreamCipher)
	{
		if (m_parallelBlockSize != 0)
		{
			if (m_parallelBlockSize < m_streamCipher->ParallelProfile().ParallelMinimumSize())
				m_parallelBlockSize = m_streamCipher->ParallelProfile().ParallelMinimumSize();
			else if (m_parallelBlockSize != m_streamCipher->ParallelBlockSize())
				m_parallelBlockSize -= (m_parallelBlockSize % m_streamCipher->ParallelProfile().ParallelMinimumSize());
		}

		m_streamCipher->ParallelProfile().IsParallel() = m_isParallel && m_streamCipher->ParallelProfile().ProcessorCount() > 1;
		m_streamCipher->ParallelProfile().ParallelBlockSize() = m_parallelBlockSize;
	}
	else
	{
		if (m_parallelBlockSize != 0)
		{
			if (m_parallelBlockSize < m_cipherEngine->ParallelProfile().ParallelMinimumSize())
				m_parallelBlockSize = m_cipherEngine->ParallelProfile().ParallelMinimumSize();
			else if (m_parallelBlockSize != m_cipherEngine->ParallelBlockSize())
				m_parallelBlockSize -= (m_parallelBlockSize % m_cipherEngine->ParallelProfile().ParallelMinimumSize());
		}

		m_cipherEngine->ParallelProfile().IsParallel() = m_isParallel && m_cipherEngine->ParallelProfile().ProcessorCount() > 1;
		m_cipherEngine->ParallelProfile().ParallelBlockSize() = m_parallelBlockSize;
	}
}

void CipherStream::Scope()
{
	if (m_isStreamCipher)
	{
		m_blockSize = m_streamCipher->BlockSize();
		m_isCounterMode = false;
		m_isParallel = m_streamCipher->IsParallel();
		m_parallelBlockSize = m_streamCipher->ParallelBlockSize();
		m_parallelMinimumSize = m_streamCipher->ParallelProfile().ParallelMinimumSize();

		for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
			m_legalKeySizes.push_back(SymmetricKeySize(m_streamCipher->LegalKeySizes()[i].KeySize(), m_streamCipher->LegalKeySizes()[i].NonceSize(), 0));
	}
	else
	{
		m_blockSize = m_cipherEngine->BlockSize();
		m_isCounterMode = (m_cipherEngine->Enumeral() == CipherModes::CTR || m_cipherEngine->Enumeral() == CipherModes::ICM);
		m_isParallel = m_cipherEngine->IsParallel();
		m_parallelBlockSize = m_cipherEngine->ParallelBlockSize();
		m_parallelMinimumSize = m_cipherEngine->ParallelProfile().ParallelMinimumSize();

		size_t dstMax = m_cipherEngine->Engine()->KdfEngine() != Digests::None ? m_cipherEngine->Engine()->DistributionCodeMax() : 0;
		for (size_t i = 0; i < m_cipherEngine->LegalKeySizes().size(); ++i)
			m_legalKeySizes.push_back(SymmetricKeySize(m_cipherEngine->LegalKeySizes()[i].KeySize(), m_cipherEngine->BlockSize(), dstMax));
	}
}

NAMESPACE_PROCESSINGEND