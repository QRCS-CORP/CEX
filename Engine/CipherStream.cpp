#include "Common.h"
#include "CipherStream.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "StreamCipherFromName.h"
#include "PaddingFromName.h"
#include "ParallelUtils.h"

NAMESPACE_PROCESSING

void CipherStream::Destroy()
{
	if (!_isDestroyed)
	{
		_blockSize = 0;
		_isCounterMode = false;
		_isEncryption = false;
		_isInitialized = false;
		_isParallel = false;
		_isStreamCipher = false;
		_parallelBlockSize = 0;
		_processorCount = 0;
		BlockProfiles _parallelBlockProfile = BlockProfiles::ProgressProfile;

		if (_destroyEngine)
		{
			if (_cipherEngine != 0)
				_cipherEngine->Destroy();
			if (_blockCipher != 0)
				_blockCipher->Destroy();
			if (_streamCipher != 0)
				_streamCipher->Destroy();

			try
			{
				if (_blockCipher != 0)
					delete _blockCipher;
				if (_cipherEngine != 0)
					delete _cipherEngine;
				if (_streamCipher != 0)
					delete _streamCipher;
				if (_cipherPadding != 0)
					delete _cipherPadding;
			}
			catch (...) 
			{
				throw CEX::Exception::CryptoProcessingException("CipherStream:Destroy", "The engines were not heap allocated!");
			}
		}

		_isDestroyed = true;
	}
}

void CipherStream::Initialize(bool Encryption, CEX::Common::KeyParams &KeyParam)
{
	try
	{
		if (!_isStreamCipher)
			_cipherEngine->Initialize(Encryption, KeyParam);
		else
			_streamCipher->Initialize(KeyParam);
	}
	catch (...)
	{
		throw CEX::Exception::CryptoProcessingException("CipherStream:Initialize", "The key could not be loaded, check the key and iv sizes!");
	}

	_isEncryption = Encryption;
	_isInitialized = true;
}

void CipherStream::Write(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream)
{
	if (!_isInitialized)
		throw CEX::Exception::CryptoProcessingException("CipherStream:Write", "The cipher has not been initialized; call the Initialize() function first!");
	if (InStream->Length() - InStream->Position() < 1)
		throw CEX::Exception::CryptoProcessingException("CipherStream:Write", "The Input stream is too short!");

	// parallel min check and calc block size
	long dlen = InStream->Length() - InStream->Position();
	CalculateBlockSize(dlen);

	if (_isEncryption && dlen % _blockSize != 0)
	{
		long alen = (dlen - (dlen % _blockSize)) + _blockSize;
		OutStream->SetLength(alen);
	}
	else
	{
		OutStream->SetLength(dlen);
	}

	if (!_isStreamCipher)
	{
		if (_isParallel && IsParallelMin(dlen))
		{
			if (_isCounterMode)
			{
				ParallelCTR(InStream, OutStream);
			}
			else
			{
				if (_isEncryption)
					BlockEncrypt(InStream, OutStream);
				else
					ParallelDecrypt(InStream, OutStream);
			}
		}
		else
		{
			if (_isCounterMode)
			{
				BlockCTR(InStream, OutStream);
			}
			else
			{
				if (_isEncryption)
					BlockEncrypt(InStream, OutStream);
				else
					BlockDecrypt(InStream, OutStream);
			}
		}
	}
	else
	{
		if (_isParallel && IsParallelMin(dlen))
			ParallelStream(InStream, OutStream);
		else
			ProcessStream(InStream, OutStream);
	}

	OutStream->SetLength(OutStream->Position());
}

void CipherStream::Write(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	if (!_isInitialized)
		throw CEX::Exception::CryptoProcessingException("CipherStream:Write", "The cipher has not been initialized; call the Initialize() function first!");
	if (Input.size() - InOffset < 1)
		throw CEX::Exception::CryptoProcessingException("CipherStream:Write", "The Input array is too short!");
	if (Input.size() - InOffset > Output.size() - OutOffset)
		throw CEX::Exception::CryptoProcessingException("CipherStream:Write", "The Output array is too short!");

	// parallel min check and calc block size
	unsigned int dlen = Input.size() - InOffset;
	CalculateBlockSize(dlen);

	if (!_isStreamCipher)
	{
		if (_isParallel && IsParallelMin(dlen))
		{
			if (_isCounterMode)
			{
				ParallelCTR(Input, InOffset, Output, OutOffset);
			}
			else
			{
				if (_isEncryption)
					BlockEncrypt(Input, InOffset, Output, OutOffset);
				else
					ParallelDecrypt(Input, InOffset, Output, OutOffset);
			}
		}
		else
		{
			if (_isCounterMode)
			{
				BlockCTR(Input, InOffset, Output, OutOffset);
			}
			else
			{
				if (_isEncryption)
					BlockEncrypt(Input, InOffset, Output, OutOffset);
				else
					BlockDecrypt(Input, InOffset, Output, OutOffset);
			}
		}
	}
	else
	{
		if (_isParallel && IsParallelMin(dlen))
			ParallelStream(Input, InOffset, Output, OutOffset);
		else
			ProcessStream(Input, InOffset, Output, OutOffset);
	}
}

// *** Protected Methods *** //

void CipherStream::CalculateBlockSize(unsigned int Length)
{
	unsigned int cipherBlock = 0;

	if (_isStreamCipher)
		cipherBlock = _streamCipher->BlockSize();
	else
		cipherBlock = _cipherEngine->BlockSize();

	// parallel min check
	if (Length < ParallelMinimumSize())
	{
		_parallelBlockSize = cipherBlock;
	}

	if (_parallelBlockProfile == BlockProfiles::ProgressProfile)
	{
		// get largest 10 base block 
		unsigned int dsr = 10;
		while (Length / dsr > ParallelMaximumSize())
			dsr *= 2;

		_parallelBlockSize = (unsigned int)(Length / dsr);
	}
	else if (_parallelBlockProfile == BlockProfiles::SpeedProfile)
	{
		if (Length < PARALLEL_DEFBLOCK)
		{
			// small block
			_parallelBlockSize = (unsigned int)Length;
		}
		else
		{
			// get largest 64kb base block
			unsigned int dsr = Length - (Length % PARALLEL_DEFBLOCK);

			if (Length > ParallelMaximumSize())
			{
				while (dsr > ParallelMaximumSize())
					dsr /= 2;

				_parallelBlockSize = (int)dsr;
			}
			else
			{
				_parallelBlockSize = (int)dsr;
			}
		}
	}

	if (_isParallel && !_isCounterMode && !_isEncryption && !_isStreamCipher)
	{
		if (_parallelBlockSize % ParallelMinimumSize() > 0)
			_parallelBlockSize -= (_parallelBlockSize % ParallelMinimumSize());
		else
			_parallelBlockSize -= ParallelMinimumSize();
	}
	else
	{
		if (_parallelBlockSize % ParallelMinimumSize() != 0)
			_parallelBlockSize -= (_parallelBlockSize % ParallelMinimumSize());
	}

	// set the ciphers block size
	if (_parallelBlockSize >= ParallelMinimumSize())
	{
		if (!_isStreamCipher)
			_cipherEngine->ParallelBlockSize() = _parallelBlockSize;
		else
			_streamCipher->ParallelBlockSize() = _parallelBlockSize;
	}
}

void CipherStream::CalculateProgress(unsigned int Length, unsigned int Processed)
{
	if (Length >= Processed)
	{
		double progress = 100.0 * ((double)Processed / Length);
		if (progress > 100.0)
			progress = 100.0;

		if (_isParallel)
		{
			ProgressPercent((int)progress);
		}
		else
		{
			long chunk = Length / 100;
			if (chunk == 0)
				ProgressPercent((int)progress);
			else if (Processed % chunk == 0)
				ProgressPercent((int)progress);
		}
	}
}

void CipherStream::BlockCTR(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream)
{
	const unsigned int blkSize = _cipherEngine->BlockSize();
	const unsigned int inpSize = (InStream->Length() - InStream->Position());
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		unsigned int fnlSize = (unsigned int)(inpSize - alnSize);
		InStream->Read(inpBuffer, 0, fnlSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, fnlSize);
		count += fnlSize;
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::BlockCTR(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	const unsigned int blkSize = _cipherEngine->BlockSize();
	const unsigned int inpSize = (Input.size() - InOffset);
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;

	_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	// partial
	if (alnSize != inpSize)
	{
		unsigned int cnkSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(blkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(blkSize);
		_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, count);
}

void CipherStream::BlockDecrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream)
{
	const unsigned int blkSize = _cipherEngine->BlockSize();
	const unsigned int inpSize = (InStream->Length() - InStream->Position());
	const unsigned int alnSize = (inpSize < blkSize) ? 0 : inpSize - blkSize;
	unsigned int count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		unsigned int cnkSize = inpSize - alnSize;
		InStream->Read(inpBuffer, 0, cnkSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		unsigned int fnlSize = blkSize - _cipherPadding->GetPaddingLength(outBuffer, 0);
		OutStream->Write(outBuffer, 0, fnlSize);
		count += fnlSize;
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::BlockDecrypt(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	const unsigned int blkSize = _cipherEngine->BlockSize();
	const unsigned int inpSize = (Input.size() - InOffset);
	const unsigned int alnSize = (inpSize < blkSize) ? 0 : inpSize - blkSize;
	unsigned int count = 0;

	_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	// last block
	std::vector<byte> inpBuffer(blkSize);
	memcpy(&inpBuffer[0], &Input[InOffset], blkSize);
	std::vector<byte> outBuffer(blkSize);
	_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
	unsigned int fnlSize = blkSize - _cipherPadding->GetPaddingLength(outBuffer, 0);
	memcpy(&Output[OutOffset], &outBuffer[0], fnlSize);
	OutOffset += fnlSize;

	if (Output.size() != OutOffset)
		Output.resize(OutOffset);

	CalculateProgress(inpSize, OutOffset);
}

void CipherStream::BlockEncrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream)
{
	const unsigned int blkSize = _cipherEngine->BlockSize();
	const unsigned int inpSize = (InStream->Length() - InStream->Position());
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		unsigned int fnlSize = inpSize - alnSize;
		InStream->Read(inpBuffer, 0, fnlSize);
		_cipherPadding->AddPadding(inpBuffer, fnlSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::BlockEncrypt(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	const unsigned int blkSize = _cipherEngine->BlockSize();
	const unsigned int inpSize = (Input.size() - InOffset);
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;

	_cipherEngine->IsParallel() = false;

	while (count != alnSize)
	{
		_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	// partial
	if (alnSize != inpSize)
	{
		unsigned int fnlSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(blkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], fnlSize);
		_cipherPadding->AddPadding(inpBuffer, fnlSize);
		std::vector<byte> outBuffer(blkSize);
		_cipherEngine->Transform(inpBuffer, 0, outBuffer, 0);
		if (Output.size() != OutOffset + blkSize)
			Output.resize(OutOffset + blkSize);
		memcpy(&Output[OutOffset], &outBuffer[0], blkSize);
		count += blkSize;
	}

	CalculateProgress(inpSize, count);
}

CEX::Cipher::Symmetric::Block::IBlockCipher* CipherStream::GetBlockEngine(CEX::Enumeration::BlockCiphers EngineType, int BlockSize, int RoundCount, CEX::Enumeration::Digests KdfEngine)
{
	try
	{
		return CEX::Helper::BlockCipherFromName::GetInstance(EngineType, BlockSize, RoundCount, KdfEngine);
	}
	catch (...)
	{
		throw CEX::Exception::CryptoProcessingException("CipherStream:GetBlockEngine", "The cipher could not be instantiated!");
	}
}

CEX::Cipher::Symmetric::Block::Mode::ICipherMode* CipherStream::GetCipherMode(CEX::Enumeration::CipherModes CipherType, CEX::Enumeration::BlockCiphers EngineType, int BlockSize, int RoundCount, CEX::Enumeration::Digests KdfEngine)
{
	CEX::Cipher::Symmetric::Block::IBlockCipher* engine = GetBlockEngine(EngineType, BlockSize, RoundCount, KdfEngine);

	try
	{
		return CEX::Helper::CipherModeFromName::GetInstance(CipherType, engine);
	}
	catch (...)
	{
		throw CEX::Exception::CryptoProcessingException("CipherStream:GetCipherMode", "The cipher mode could not be instantiated!");
	}
}

CEX::Cipher::Symmetric::Block::Padding::IPadding* CipherStream::GetPaddingMode(CEX::Enumeration::PaddingModes PaddingType)
{
	try
	{
		return CEX::Helper::PaddingFromName::GetInstance(PaddingType);
	}
	catch (...)
	{
		throw CEX::Exception::CryptoProcessingException("CipherStream:GetPaddingMode", "The padding could not be instantiated!");
	}
}

CEX::Cipher::Symmetric::Stream::IStreamCipher* CipherStream::GetStreamEngine(CEX::Enumeration::StreamCiphers EngineType, int RoundCount)
{
	try
	{
		return CEX::Helper::StreamCipherFromName::GetInstance(EngineType, RoundCount);
	}
	catch (...)
	{
		throw CEX::Exception::CryptoProcessingException("CipherStream:GetStreamEngine", "The cipher could not be instantiated!");
	}
}

bool CipherStream::IsStreamCipher(CEX::Enumeration::SymmetricEngines EngineType)
{
	return EngineType == CEX::Enumeration::SymmetricEngines::ChaCha ||
		EngineType == CEX::Enumeration::SymmetricEngines::Salsa;
}

void CipherStream::ParallelCTR(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream)
{
	const unsigned int blkSize = _parallelBlockSize;
	const unsigned int inpSize = (InStream->Length() - InStream->Position());
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	_cipherEngine->IsParallel() = true;
	_cipherEngine->ParallelBlockSize() = blkSize;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		unsigned int cnkSize = inpSize - alnSize;
		inpBuffer.resize(cnkSize);
		InStream->Read(inpBuffer, 0, cnkSize);
		outBuffer.resize(cnkSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::ParallelCTR(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	const unsigned int blkSize = _parallelBlockSize;
	const unsigned int inpSize = (Input.size() - InOffset);
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;

	_cipherEngine->IsParallel() = true;
	_cipherEngine->ParallelBlockSize() = blkSize;

	// parallel blocks
	while (count != alnSize)
	{
		_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	if (alnSize != inpSize)
	{
		unsigned int cnkSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(cnkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(cnkSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, count);
}

void CipherStream::ParallelDecrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream)
{
	const unsigned int blkSize = _parallelBlockSize;
	const unsigned int inpSize = (InStream->Length() - InStream->Position());
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	_cipherEngine->IsParallel() = true;
	_cipherEngine->ParallelBlockSize() = blkSize;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		_cipherEngine->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		BlockDecrypt(InStream, OutStream);
		count += (inpSize - alnSize);
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::ParallelDecrypt(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	const unsigned int blkSize = _parallelBlockSize;
	const unsigned int inpSize = (Input.size() - InOffset);
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;

	_cipherEngine->IsParallel() = true;
	_cipherEngine->ParallelBlockSize() = blkSize;

	// parallel
	while (count != alnSize)
	{
		_cipherEngine->Transform(Input, InOffset, Output, OutOffset);
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

void CipherStream::ParallelStream(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream)
{
	const unsigned int blkSize = _parallelBlockSize;
	const unsigned int inpSize = (InStream->Length() - InStream->Position());
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	_streamCipher->IsParallel() = true;
	_streamCipher->ParallelBlockSize() = blkSize;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		unsigned int cnkSize = inpSize - alnSize;
		inpBuffer.resize(cnkSize);
		InStream->Read(inpBuffer, 0, cnkSize);
		outBuffer.resize(cnkSize);
		_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::ParallelStream(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	const unsigned int blkSize = _parallelBlockSize;
	const unsigned int inpSize = (Input.size() - InOffset);
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;

	_streamCipher->IsParallel() = true;
	_streamCipher->ParallelBlockSize() = blkSize;

	// parallel blocks
	while (count != alnSize)
	{
		_streamCipher->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	if (alnSize != inpSize)
	{
		unsigned int cnkSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(cnkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(cnkSize);
		_streamCipher->Transform(inpBuffer, outBuffer);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, count);
}

void CipherStream::ProcessStream(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream)
{
	const unsigned int blkSize = _streamCipher->BlockSize();
	const unsigned int inpSize = (InStream->Length() - InStream->Position());
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;
	std::vector<byte> inpBuffer(blkSize);
	std::vector<byte> outBuffer(blkSize);

	_streamCipher->IsParallel() = false;

	while (count != alnSize)
	{
		InStream->Read(inpBuffer, 0, blkSize);
		_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, blkSize);
		count += blkSize;
		CalculateProgress(inpSize, OutStream->Position());
	}

	if (alnSize != inpSize)
	{
		unsigned int cnkSize = inpSize - alnSize;
		inpBuffer.resize(cnkSize);
		InStream->Read(inpBuffer, 0, cnkSize);
		outBuffer.resize(cnkSize);
		_streamCipher->Transform(inpBuffer, outBuffer);
		OutStream->Write(outBuffer, 0, cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, OutStream->Position());
}

void CipherStream::ProcessStream(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	const unsigned int blkSize = _streamCipher->BlockSize();
	const unsigned int inpSize = (Input.size() - InOffset);
	const unsigned int alnSize = (inpSize / blkSize) * blkSize;
	unsigned int count = 0;

	_streamCipher->IsParallel() = false;

	while (count != alnSize)
	{
		_streamCipher->Transform(Input, InOffset, Output, OutOffset);
		InOffset += blkSize;
		OutOffset += blkSize;
		count += blkSize;
		CalculateProgress(inpSize, count);
	}

	// partial
	if (alnSize != inpSize)
	{
		unsigned int cnkSize = inpSize - alnSize;
		std::vector<byte> inpBuffer(cnkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
		std::vector<byte> outBuffer(cnkSize);
		_streamCipher->Transform(inpBuffer, outBuffer);
		memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		count += cnkSize;
	}

	CalculateProgress(inpSize, count);
}

bool CipherStream::IsParallelMin(unsigned int Length)
{
	return (Length >= ParallelMinimumSize());
}

void CipherStream::ParametersCheck()
{
	if (_isStreamCipher)
	{
		_blockSize = _streamCipher->BlockSize();
		_isCounterMode = false;
		_isParallel = _streamCipher->IsParallel();
		_parallelBlockSize = _streamCipher->ParallelBlockSize();
	}
	else
	{
		_blockSize = _cipherEngine->BlockSize();
		_isCounterMode = _cipherEngine->Enumeral() == CEX::Enumeration::CipherModes::CTR;

		if (_cipherEngine->Enumeral() == CEX::Enumeration::CipherModes::CBC || _cipherEngine->Enumeral() == CEX::Enumeration::CipherModes::CFB || _isCounterMode)
		{
			_isParallel = _cipherEngine->IsParallel() && !(!_isCounterMode && _cipherEngine->IsEncryption());
			_parallelBlockSize = _cipherEngine->ParallelBlockSize();
		}
		else
		{
			_isParallel = false;
			_parallelBlockSize = _blockSize;
		}
	}
}

void CipherStream::SetScope()
{
	_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (_processorCount % 2 != 0)
		_processorCount--;
	if (_processorCount > 1)
		_isParallel = true;
}

NAMESPACE_PROCESSINGEND