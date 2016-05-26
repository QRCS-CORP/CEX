#include "CMAC.h"
#include "BlockCipherFromName.h"
#include "CBC.h"
#include "ISO7816.h"
#include "IntUtils.h"

NAMESPACE_MAC

void CMAC::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if ((InOffset + Length) > Input.size())
		throw CryptoMacException("CMAC:BlockUpdate", "The Input buffer is too short!");

	if (_wrkOffset == _blockSize)
	{
		_cipherMode->Transform(_wrkBuffer, 0, _msgCode, 0);
		_wrkOffset = 0;
	}

	size_t diff = _blockSize - _wrkOffset;
	if (Length > diff)
	{
		memcpy(&_wrkBuffer[_wrkOffset], &Input[InOffset], diff);
		_cipherMode->Transform(_wrkBuffer, 0, _msgCode, 0);
		_wrkOffset = 0;
		Length -= diff;
		InOffset += diff;

		while (Length > _blockSize)
		{
			_cipherMode->Transform(Input, InOffset, _msgCode, 0);
			Length -= _blockSize;
			InOffset += _blockSize;
		}
	}

	if (Length > 0)
	{
		memcpy(&_wrkBuffer[_wrkOffset], &Input[InOffset], Length);
		_wrkOffset += Length;
	}
}

void CMAC::ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!_isInitialized)
		throw CryptoMacException("CMAC:ComputeMac", "The Mac is not initialized!");

	if (Output.size() != _macSize)
		Output.resize(_macSize);

	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void CMAC::Destroy()
{
	if (!_isDestroyed)
	{
		_blockSize = 0;
		_isInitialized = false;
		CEX::Utility::IntUtils::ClearVector(_K1);
		CEX::Utility::IntUtils::ClearVector(_K2);
		CEX::Utility::IntUtils::ClearVector(_msgCode);
		CEX::Utility::IntUtils::ClearVector(_wrkBuffer);
		_macSize = 0;
		_wrkOffset = 0;
		_isDestroyed = true;
	}
}

size_t CMAC::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
	if ((Output.size() - OutOffset) < _macSize)
		throw CryptoMacException("CMAC:DoFinal", "The Output buffer is too short!");

	if (_wrkOffset != _blockSize)
	{
		CEX::Cipher::Symmetric::Block::Padding::ISO7816 pad;
		pad.AddPadding(_wrkBuffer, _wrkOffset);
		CEX::Utility::IntUtils::XORBLK(_K2, 0, _wrkBuffer, 0, _macSize);
	}
	else
	{
		CEX::Utility::IntUtils::XORBLK(_K1, 0, _wrkBuffer, 0, _macSize);
	}

	_cipherMode->Transform(_wrkBuffer, 0, _msgCode, 0);
	memcpy(&Output[OutOffset], &_msgCode[0], _macSize);
	Reset();

	return _macSize;
}

void CMAC::Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV)
{
	if (MacKey.size() == 0)
		throw CryptoMacException("CMAC:Initialize", "Key can not be null!");

	size_t ivSze = IV.size() > _blockSize ? _blockSize : IV.size();
	std::vector<byte> vec(_blockSize);
	if (ivSze != 0)
		memcpy(&vec[0], &IV[0], ivSze);

	_cipherKey.Key() = MacKey;
	_cipherKey.IV() = IV;
	_cipherMode->Initialize(true, _cipherKey);
	std::vector<byte> lu(_blockSize);
	std::vector<byte> tmpz(_blockSize, (byte)0);
	_cipherMode->Transform(tmpz, 0, lu, 0);
	_K1 = GenerateSubkey(lu);
	_K2 = GenerateSubkey(_K1);
	_cipherMode->Initialize(true, _cipherKey);
	_isInitialized = true;
}

void CMAC::Reset()
{
	_cipherMode->Initialize(true, _cipherKey);
	std::fill(_wrkBuffer.begin(), _wrkBuffer.end(), 0);
	_wrkOffset = 0;
}

void CMAC::Update(byte Input)
{
	if (_wrkOffset == _wrkBuffer.size())
	{
		_cipherMode->Transform(_wrkBuffer, 0, _msgCode, 0);
		_wrkOffset = 0;
	}

	_wrkBuffer[_wrkOffset++] = Input;
}

std::vector<byte> CMAC::GenerateSubkey(std::vector<byte> &Input)
{
	int fbit = (Input[0] & 0xFF) >> 7;
	std::vector<byte> tmpk(Input.size());

	for (size_t i = 0; i < Input.size() - 1; i++)
		tmpk[i] = (byte)((Input[i] << 1) + ((Input[i + 1] & 0xFF) >> 7));

	tmpk[Input.size() - 1] = (byte)(Input[Input.size() - 1] << 1);

	if (fbit == 1)
		tmpk[Input.size() - 1] ^= Input.size() == _blockSize ? CT87 : CT1B;

	return tmpk;
}

void CMAC::CreateCipher(CEX::Enumeration::BlockCiphers EngineType)
{
	_cipherMode = new CEX::Cipher::Symmetric::Block::Mode::CBC(CEX::Helper::BlockCipherFromName::GetInstance(EngineType));
}

void CMAC::LoadCipher(CEX::Cipher::Symmetric::Block::IBlockCipher* Cipher)
{
	_cipherMode = new CEX::Cipher::Symmetric::Block::Mode::CBC(Cipher);
}

NAMESPACE_MACEND