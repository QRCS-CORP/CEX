#include "CipherStream.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "PaddingFromName.h"
#include "ParallelUtils.h"
#include "StreamCipherFromName.h"

NAMESPACE_PROCESSING

using CEX::Helper::BlockCipherFromName;
using CEX::Helper::CipherModeFromName;
using CEX::Helper::PaddingFromName;
using CEX::Utility::ParallelUtils;
using CEX::Helper::StreamCipherFromName;

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
		m_processorCount = 0;
		BlockProfiles m_parallelBlockProfile = BlockProfiles::ProgressProfile;

		if (m_destroyEngine)
		{
			if (m_cipherEngine != 0)
				m_cipherEngine->Destroy();
			if (m_blockCipher != 0)
				m_blockCipher->Destroy();
			if (m_streamCipher != 0)
				m_streamCipher->Destroy();

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
			catch (...) 
			{
#if defined(CPPEXCEPTIONS_ENABLED)
				throw CryptoProcessingException("CipherStream:Destroy", "The engines were not heap allocated!");
#endif
			}
		}

		m_isDestroyed = true;
	}
}

void CipherStream::Initialize(bool Encryption, KeyParams &KeyParam)
{
	try
	{
		if (!m_isStreamCipher)
			m_cipherEngine->Initialize(Encryption, KeyParam);
		else
			m_streamCipher->Initialize(KeyParam);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoProcessingException("CipherStream:Initialize", "The key could not be loaded, check the key and iv sizes!");
#endif
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void CipherStream::Write(IByteStream* InStream, IByteStream* OutStream)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (!m_isInitialized)
		throw CryptoProcessingException("CipherStream:Write", "The cipher has not been initialized; call the Initialize() function first!");
	if (InStream->Length() - InStream->Position() < 1)
		throw CryptoProcessingException("CipherStream:Write", "The Input stream is too short!");
#endif

	// parallel min check and calc block size
	size_t dlen = InStream->Length() - InStream->Position();
	CalculateBlockSize(dlen);

	if (m_isEncryption && dlen % m_blockSize != 0)
	{
		size_t alen = (dlen - (dlen % m_blockSize)) + m_blockSize;
		OutStream->SetLength(alen);
	}
	else
	{
		OutStream->SetLength(dlen);
	}

	if (!m_isStreamCipher)
	{
		if (m_isParallel && IsParallelMin(dlen))
		{
			if (m_isCounterMode)
			{
				ParallelCTR(InStream, OutStream);
			}
			else
			{
				if (m_isEncryption)
					BlockEncrypt(InStream, OutStream);
				else
					ParallelDecrypt(InStream, OutStream);
			}
		}
		else
		{
			if (m_isCounterMode)
			{
				BlockCTR(InStream, OutStream);
			}
			else
			{
				if (m_isEncryption)
					BlockEncrypt(InStream, OutStream);
				else
					BlockDecrypt(InStream, OutStream);
			}
		}
	}
	else
	{
		if (m_isParallel && IsParallelMin(dlen))
			ParallelStream(InStream, OutStream);
		else
			ProcessStream(InStream, OutStream);
	}

	OutStream->SetLength(OutStream->Position());
}

void CipherStream::Write(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (!m_isInitialized)
		throw CryptoProcessingException("CipherStream:Write", "The cipher has not been initialized; call the Initialize() function first!");
	if (Input.size() - InOffset < 1)
		throw CryptoProcessingException("CipherStream:Write", "The Input array is too short!");
	if (Input.size() - InOffset > Output.size() - OutOffset)
		throw CryptoProcessingException("CipherStream:Write", "The Output array is too short!");
#endif

	// parallel min check and calc block size
	size_t dlen = Input.size() - InOffset;
	CalculateBlockSize(dlen);

	if (!m_isStreamCipher)
	{
		if (m_isParallel && IsParallelMin(dlen))
		{
			if (m_isCounterMode)
			{
				ParallelCTR(Input, InOffset, Output, OutOffset);
			}
			else
			{
				if (m_isEncryption)
					BlockEncrypt(Input, InOffset, Output, OutOffset);
				else
					ParallelDecrypt(Input, InOffset, Output, OutOffset);
			}
		}
		else
		{
			if (m_isCounterMode)
			{
				BlockCTR(Input, InOffset, Output, OutOffset);
			}
			else
			{
				if (m_isEncryption)
					BlockEncrypt(Input, InOffset, Output, OutOffset);
				else
					BlockDecrypt(Input, InOffset, Output, OutOffset);
			}
		}
	}
	else
	{
		if (m_isParallel && IsParallelMin(dlen))
			ParallelStream(Input, InOffset, Output, OutOffset);
		else
			ProcessStream(Input, InOffset, Output, OutOffset);
	}
}

//~~~Protected Methods~~~//

void CipherStream::CalculateBlockSize(size_t Length)
{
	size_t cipherBlock = 0;

	if (m_isStreamCipher)
		cipherBlock = m_streamCipher->BlockSize();
	else
		cipherBlock = m_cipherEngine->BlockSize();

	// parallel min check
	if (Length < ParallelMinimumSize())
		m_parallelBlockSize = cipherBlock;

	if (m_parallelBlockProfile == BlockProfiles::ProgressProfile)
	{
		// get largest 10 base block 
		size_t dsr = 10;
		while (Length / dsr > ParallelMaximumSize())
			dsr *= 2;

		m_parallelBlockSize = Length / dsr;
	}
	else if (m_parallelBlockProfile == BlockProfiles::SpeedProfile)
	{
		if (Length < PARALLEL_DEFBLOCK)
		{
			// small block
			m_parallelBlockSize = Length;
		}
		else
		{
			// get largest 64kb base block
			size_t dsr = Length - (Length % PARALLEL_DEFBLOCK);

			if (Length > ParallelMaximumSize())
			{
				while (dsr > ParallelMaximumSize())
					dsr /= 2;

				m_parallelBlockSize = (int)dsr;
			}
			else
			{
				m_parallelBlockSize = (int)dsr;
			}
		}
	}

	if (m_isParallel && !m_isCounterMode && !m_isEncryption && !m_isStreamCipher)
	{
		if (m_parallelBlockSize % ParallelMinimumSize() > 0)
			m_parallelBlockSize -= (m_parallelBlockSize % ParallelMinimumSize());
		else
			m_parallelBlockSize -= ParallelMinimumSize();
	}
	else
	{
		if (m_parallelBlockSize % ParallelMinimumSize() != 0)
			m_parallelBlockSize -= (m_parallelBlockSize % ParallelMinimumSize());
	}

	// set the ciphers block size
	if (m_parallelBlockSize >= ParallelMinimumSize())
	{
		if (!m_isStreamCipher)
			m_cipherEngine->ParallelBlockSize() = m_parallelBlockSize;
		else
			m_streamCipher->ParallelBlockSize() = m_parallelBlockSize;
	}

	// align
	if (m_isParallel)
	{
		if (!m_isStreamCipher)
			m_parallelBlockSize -= (m_parallelBlockSize % m_cipherEngine->ParallelMinimumSize());
		else
			m_parallelBlockSize -= (m_parallelBlockSize % m_streamCipher->ParallelMinimumSize());
	}
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

void CipherStream::BlockCTR(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t blkSize = m_cipherEngine->BlockSize();
	const size_t inpSize = (InStream->Length() - InStream->Position());
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	m_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		size_t fnlSize = inpSize - alnSize;
		InStream->Read(inpBuffer, 0, fnlSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, fnlSize);
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::BlockCTR(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t blkSize = m_cipherEngine->BlockSize();
	const size_t inpSize = (Input.size() - InOffset);
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;

	m_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		m_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	// partial
	if (alnSize != inpSize)
	{
		size_t cnkSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(blkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(blkSize);
		m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, count);
}

void CipherStream::BlockDecrypt(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t blkSize = m_cipherEngine->BlockSize();
	const size_t inpSize = (InStream->Length() - InStream->Position());
	const size_t alnSize = (inpSize < blkSize) ? 0 : inpSize - blkSize;
	size_t count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	m_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		size_t cnkSize = inpSize - alnSize;
		InStream->Read(inpBuffer, 0, cnkSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		size_t fnlSize = blkSize - m_cipherPadding->GetPaddingLength(outBuffer, 0);
		OutStream->Write(outBuffer, 0, fnlSize);
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::BlockDecrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t blkSize = m_cipherEngine->BlockSize();
	const size_t inpSize = (Input.size() - InOffset);
	const size_t alnSize = (inpSize < blkSize) ? 0 : inpSize - blkSize;
	size_t count = 0;

	m_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		m_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	if (alnSize != inpSize)
	{
		// last block
		std::vector<byte> inpBuffer(blkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], blkSize);
		std::vector<byte> outBuffer(blkSize);
		m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
		size_t fnlSize = blkSize - m_cipherPadding->GetPaddingLength(outBuffer, 0);
		memcpy(&Output[OutOffset], &outBuffer[0], fnlSize);
		OutOffset += fnlSize;
		Output.resize(OutOffset);
	}

	CalculateProgress(inpSize, OutOffset);
}

void CipherStream::BlockEncrypt(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t blkSize = m_cipherEngine->BlockSize();
	const size_t inpSize = (InStream->Length() - InStream->Position());
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	m_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		size_t fnlSize = inpSize - alnSize;
		InStream->Read(inpBuffer, 0, fnlSize);
		m_cipherPadding->AddPadding(inpBuffer, fnlSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::BlockEncrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t blkSize = m_cipherEngine->BlockSize();
	const size_t inpSize = (Input.size() - InOffset);
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;

	m_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		m_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	// partial
	if (alnSize != inpSize)
	{
		size_t fnlSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(blkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], fnlSize);
		m_cipherPadding->AddPadding(inpBuffer, fnlSize);
		std::vector<byte> outBuffer(blkSize);
		m_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
		if (Output.size() != OutOffset + blkSize)
			Output.resize(OutOffset + blkSize);
		memcpy(&Output[OutOffset], &outBuffer[0], blkSize);
		count += blkSize;
	}

	CalculateProgress(inpSize, count);
}

IBlockCipher* CipherStream::GetBlockEngine(BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine)
{
	try
	{
		return BlockCipherFromName::GetInstance(EngineType, BlockSize, RoundCount, KdfEngine);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoProcessingException("CipherStream:GetBlockEngine", "The cipher could not be instantiated!");
#else
		return 0;
#endif
	}
}

ICipherMode* CipherStream::GetCipherMode(CipherModes CipherType, BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine)
{
	IBlockCipher* engine = GetBlockEngine(EngineType, BlockSize, RoundCount, KdfEngine);

	try
	{
		return CipherModeFromName::GetInstance(CipherType, engine);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoProcessingException("CipherStream:GetCipherMode", "The cipher mode could not be instantiated!");
#else
		return 0;
#endif
	}
}

IPadding* CipherStream::GetPaddingMode(PaddingModes PaddingType)
{
	try
	{
		return PaddingFromName::GetInstance(PaddingType);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoProcessingException("CipherStream:GetPaddingMode", "The padding could not be instantiated!");
#else
		return 0;
#endif
	}
}

IStreamCipher* CipherStream::GetStreamEngine(StreamCiphers EngineType, int RoundCount)
{
	try
	{
		return StreamCipherFromName::GetInstance(EngineType, RoundCount);
	}
	catch (...)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoProcessingException("CipherStream:GetStreamEngine", "The cipher could not be instantiated!");
#else
		return 0;
#endif
	}
}

void CipherStream::ParallelCTR(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t blkSize = m_parallelBlockSize;
	const size_t inpSize = (InStream->Length() - InStream->Position());
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	m_cipherEngine->IsParallel() = true;
	m_cipherEngine->ParallelBlockSize() = blkSize;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		size_t cnkSize = inpSize - alnSize;
		inpBuffer.resize(cnkSize);
		InStream->Read(inpBuffer, 0, cnkSize);
		outBuffer.resize(cnkSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, cnkSize);
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::ParallelCTR(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t blkSize = m_parallelBlockSize;
	const size_t inpSize = (Input.size() - InOffset);
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;

	m_cipherEngine->IsParallel() = true;
	m_cipherEngine->ParallelBlockSize() = blkSize;

	while (count != alnSize)
	{
		m_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	if (alnSize != inpSize)
	{
		size_t cnkSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(cnkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(cnkSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, count);
}

void CipherStream::ParallelDecrypt(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t blkSize = m_parallelBlockSize;
	const size_t inpSize = (InStream->Length() - InStream->Position());
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	m_cipherEngine->IsParallel() = true;
	m_cipherEngine->ParallelBlockSize() = blkSize;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		m_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
		BlockDecrypt(InStream, OutStream);

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::ParallelDecrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t blkSize = m_parallelBlockSize;
	const size_t inpSize = (Input.size() - InOffset);
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;

	m_cipherEngine->IsParallel() = true;
	m_cipherEngine->ParallelBlockSize() = blkSize;

	// parallel
	while (count != alnSize)
	{
		m_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	if (alnSize != inpSize)
	{
		BlockDecrypt(Input, InOffset, Output, OutOffset);
		count += (inpSize - alnSize);
	}

	CalculateProgress(inpSize, count);
}

void CipherStream::ParallelStream(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t blkSize = m_parallelBlockSize;
	const size_t inpSize = (InStream->Length() - InStream->Position());
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	m_streamCipher->IsParallel() = true;
	m_streamCipher->ParallelBlockSize() = blkSize;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		size_t cnkSize = inpSize - alnSize;
		inpBuffer.resize(cnkSize);
		InStream->Read(inpBuffer, 0, cnkSize);
		outBuffer.resize(cnkSize);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, cnkSize);
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::ParallelStream(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t blkSize = m_parallelBlockSize;
	const size_t inpSize = (Input.size() - InOffset);
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;

	m_streamCipher->IsParallel() = true;
	m_streamCipher->ParallelBlockSize() = blkSize;

	// parallel blocks
	while (count != alnSize)
	{
		m_streamCipher->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	if (alnSize != inpSize)
	{
		size_t cnkSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(cnkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(cnkSize);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, count);
}

void CipherStream::ProcessStream(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t blkSize = m_streamCipher->BlockSize();
	const size_t inpSize = (InStream->Length() - InStream->Position());
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	m_streamCipher->IsParallel() = false;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		size_t cnkSize = inpSize - alnSize;
		inpBuffer.resize(cnkSize);
		InStream->Read(inpBuffer, 0, cnkSize);
		outBuffer.resize(cnkSize);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, cnkSize);
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::ProcessStream(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t blkSize = m_streamCipher->BlockSize();
	const size_t inpSize = (Input.size() - InOffset);
	const size_t alnSize = (inpSize / blkSize) * blkSize;
	size_t count = 0;

	m_streamCipher->IsParallel() = false;

	while (count != alnSize)
	{
		m_streamCipher->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	// partial
	if (alnSize != inpSize)
	{
		size_t cnkSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(cnkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(cnkSize);
		m_streamCipher->Transform(inpBuffer, outBuffer);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, count);
}

bool CipherStream::IsParallelMin(size_t Length)
{
	return (Length >= ParallelMinimumSize());
}

void CipherStream::ParametersCheck()
{
	if (m_isStreamCipher)
	{
		m_blockSize = m_streamCipher->BlockSize();
		m_isCounterMode = false;
		m_isParallel = m_streamCipher->IsParallel();
		m_parallelBlockSize = m_streamCipher->ParallelBlockSize();
	}
	else
	{
		m_blockSize = m_cipherEngine->BlockSize();
		m_isCounterMode = m_cipherEngine->Enumeral() == CipherModes::CTR;

		if (m_cipherEngine->Enumeral() == CipherModes::CBC || m_cipherEngine->Enumeral() == CipherModes::CFB || m_isCounterMode)
		{
			m_isParallel = m_cipherEngine->IsParallel() && !(!m_isCounterMode && m_cipherEngine->IsEncryption());
			m_parallelBlockSize = m_cipherEngine->ParallelBlockSize();
		}
		else
		{
			m_isParallel = false;
			m_parallelBlockSize = m_blockSize;
		}
	}
}

void CipherStream::SetScope()
{
	m_processorCount = ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;
}

NAMESPACE_PROCESSINGEND