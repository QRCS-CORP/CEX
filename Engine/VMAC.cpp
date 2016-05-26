#include "VMAC.h"
#include "IntUtils.h"

NAMESPACE_MAC

void VMAC::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if ((InOffset + Length) > Input.size())
		throw CryptoMacException("VMAC:Ctor", "The Input buffer is too short!");

	for (size_t i = 0; i < Length; ++i)
		Update(Input[InOffset + i]);
}

void VMAC::ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!_isInitialized)
		throw CryptoMacException("VMAC:ComputeMac", "The Mac is not initialized!");

	if (Output.size() != MAC_SIZE)
		Output.resize(MAC_SIZE);

	BlockUpdate(Input, 0, (int)Input.size());
	DoFinal(Output, 0);
}

void VMAC::Destroy()
{
	if (!_isDestroyed)
	{
		_blockSize = 0;
		_isInitialized = false;
		_G = 0;
		_N = 0;
		_S = 0;
		_X1 = 0;
		_X2 = 0;
		_X3 = 0;
		_X4 = 0;
		CEX::Utility::IntUtils::ClearVector(_P);
		CEX::Utility::IntUtils::ClearVector(_T);
		CEX::Utility::IntUtils::ClearVector(_workingKey);
		CEX::Utility::IntUtils::ClearVector(_workingIV);
		_isDestroyed = true;
	}
}

size_t VMAC::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
	if (Output.size() - OutOffset < MAC_SIZE)
		throw CryptoMacException("VMAC:DoFinal", "The Output buffer is too short!");

	size_t ctr = 1;
	byte ptmp;

	// execute the post-processing phase
	while (ctr != 25)
	{
		_S = _P[(_S + _P[_N & CTFF]) & CTFF];
		_X4 = _P[(_X4 + _X3 + ctr) & CTFF];
		_X3 = _P[(_X3 + _X2 + ctr) & CTFF];
		_X2 = _P[(_X2 + _X1 + ctr) & CTFF];
		_X1 = _P[(_X1 + _S + ctr) & CTFF];
		_T[_G & CT1F] = (byte)(_T[_G & CT1F] ^ _X1);
		_T[(_G + 1) & CT1F] = (byte)(_T[(_G + 1) & CT1F] ^ _X2);
		_T[(_G + 2) & CT1F] = (byte)(_T[(_G + 2) & CT1F] ^ _X3);
		_T[(_G + 3) & CT1F] = (byte)(_T[(_G + 3) & CT1F] ^ _X4);
		_G = (byte)((_G + 4) & CT1F);

		ptmp = _P[_N & CTFF];
		_P[_N & CTFF] = _P[_S & CTFF];
		_P[_S & CTFF] = ptmp;
		_N = (byte)((_N + 1) & CTFF);

		++ctr;
	}

	// input T to the IV-phase of the VMPC KSA
	ctr = 0;
	while (ctr != 768)
	{
		_S = _P[(_S + _P[ctr & CTFF] + _T[ctr & CT1F]) & CTFF];
		ptmp = _P[ctr & CTFF];
		_P[ctr & CTFF] = _P[_S & CTFF];
		_P[_S & CTFF] = ptmp;

		++ctr;
	}

	// store 20 new outputs of the VMPC Stream Cipher input table M
	std::vector<byte> M(20);
	ctr = 0;
	while (ctr != 20)
	{
		_S = _P[(_S + _P[ctr & CTFF]) & CTFF];
		M[ctr] = _P[(_P[(_P[_S & CTFF]) & CTFF] + 1) & CTFF];
		ptmp = _P[ctr & CTFF];
		_P[ctr & CTFF] = _P[_S & CTFF];
		_P[_S & CTFF] = ptmp;

		++ctr;
	}

	memcpy(&Output[OutOffset], &M[0], M.size());
	Reset();

	return M.size();
}

void VMAC::Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV)
{
	if (MacKey.size() == 0)
		throw CryptoMacException("VMAC:Initialize", "Key can not be zero length!");
	if (IV.size() < 1 || IV.size() > 768)
		throw CryptoMacException("VMAC:Initialize", "VMAC requires 1 to 768 bytes of IV!");

	_workingIV.resize(IV.size());
	memcpy(&_workingIV[0], &IV[0], IV.size());
	_workingKey.resize(MacKey.size());
	memcpy(&_workingKey[0], &MacKey[0], MacKey.size());

	Reset();
	_isInitialized = true;
}

void VMAC::Reset()
{
	_G = _N = _S = _X1 = _X2 = _X3 = _X4 = 0;
	_T.clear();
	_T.resize(32, (byte)0);
	InitKey(_workingKey, _workingIV);
}

void VMAC::Update(byte Input)
{
	_S = _P[(_S + _P[_N & CTFF]) & CTFF];
	byte btmp = (byte)(Input ^ _P[(_P[(_P[_S & CTFF]) & CTFF] + 1) & CTFF]);

	_X4 = _P[(_X4 + _X3) & CTFF];
	_X3 = _P[(_X3 + _X2) & CTFF];
	_X2 = _P[(_X2 + _X1) & CTFF];
	_X1 = _P[(_X1 + _S + btmp) & CTFF];
	_T[_G & CT1F] = (byte)(_T[_G & CT1F] ^ _X1);
	_T[(_G + 1) & CT1F] = (byte)(_T[(_G + 1) & CT1F] ^ _X2);
	_T[(_G + 2) & CT1F] = (byte)(_T[(_G + 2) & CT1F] ^ _X3);
	_T[(_G + 3) & CT1F] = (byte)(_T[(_G + 3) & CT1F] ^ _X4);
	_G = (byte)((_G + 4) & CT1F);

	btmp = _P[_N & CTFF];
	_P[_N & CTFF] = _P[_S & CTFF];
	_P[_S & CTFF] = btmp;
	_N = (byte)((_N + 1) & CTFF);
}

void VMAC::InitKey(std::vector<byte> &Key, std::vector<byte> &Iv)
{
	size_t ctr = 0;

	while (ctr != 256)
	{
		_P[ctr] = (byte)ctr;
		++ctr;
	}

	byte btmp = 0;

	ctr = 0;
	while (ctr != 768)
	{
		_S = _P[(_S + _P[ctr & CTFF] + Key[ctr % Key.size()]) & CTFF];
		btmp = _P[ctr & CTFF];
		_P[ctr & CTFF] = _P[_S & CTFF];
		_P[_S & CTFF] = btmp;
		++ctr;
	}

	ctr = 0;
	while (ctr != 768)
	{
		_S = _P[(_S + _P[ctr & CTFF] + Iv[ctr % Iv.size()]) & CTFF];
		btmp = _P[ctr & CTFF];
		_P[ctr & CTFF] = _P[_S & CTFF];
		_P[_S & CTFF] = btmp;
		++ctr;
	}

	_N = 0;
}

NAMESPACE_MACEND