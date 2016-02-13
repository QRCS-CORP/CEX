#include "ISCRsg.h"
#include "IntUtils.h"
#include "CSPRsg.h"

NAMESPACE_SEED

//** Public Methods **//

void ISCRsg::Destroy()
{
	if (!_isDestroyed)
	{
		_accululator = 0;
		_cycCounter = 0;
		_rndCount = 0;
		_rslCounter = 0;
		CEX::Utility::IntUtils::ClearVector(_rndResult);
		CEX::Utility::IntUtils::ClearVector(_wrkBuffer);
		_isDestroyed = true;
	}
}

void ISCRsg::GetBytes(std::vector<byte> &Output)
{
	size_t offset = 0;
	int X;
	size_t len = SIZE32;

	while (offset < Output.size())
	{
		X = Next();

		if (Output.size() - offset < len)
			len = Output.size() - offset;

		memcpy(&Output[offset], &X, len);
		offset += len;
	}
}

std::vector<byte> ISCRsg::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

int ISCRsg::Next()
{
	if (0 == _rslCounter--)
	{
		Generate();
		_rslCounter = MSIZE - 1;
	}
	return _rndResult[_rslCounter];
}

void ISCRsg::Reset()
{
	Generate();
}

//** Protected Methods **//

void ISCRsg::Generate()
{
	const int SSZ = MSIZE / 2;
	int i = 0;
	int j = SSZ - 1;
	int X, Y;
	_lstResult += ++_cycCounter;

	while (i != SSZ)
	{
		X = _wrkBuffer[i];
		_accululator ^= _accululator << 13;
		_accululator += _wrkBuffer[++j];
		_wrkBuffer[i] = Y = _wrkBuffer[(X & MASK) >> 2] + _accululator + _lstResult;
		_rndResult[i] = _lstResult = _wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = _wrkBuffer[++i];
		_accululator ^= (int)((uint)_accululator >> 6);
		_accululator += _wrkBuffer[++j];
		_wrkBuffer[i] = Y = _wrkBuffer[(X & MASK) >> 2] + _accululator + _lstResult;
		_rndResult[i] = _lstResult = _wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = _wrkBuffer[++i];
		_accululator ^= _accululator << 2;
		_accululator += _wrkBuffer[++j];
		_wrkBuffer[i] = Y = _wrkBuffer[(X & MASK) >> 2] + _accululator + _lstResult;
		_rndResult[i] = _lstResult = _wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = _wrkBuffer[++i];
		_accululator ^= (int)((uint)_accululator >> 16);
		_accululator += _wrkBuffer[++j];
		_wrkBuffer[i] = Y = _wrkBuffer[(X & MASK) >> 2] + _accululator + _lstResult;
		_rndResult[i] = _lstResult = _wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;
		++i;
	}

	j = 0;
	while (j != SSZ)
	{
		X = _wrkBuffer[i];
		_accululator ^= _accululator << 13;
		_accululator += _wrkBuffer[j];
		_wrkBuffer[i] = Y = _wrkBuffer[(X & MASK) >> 2] + _accululator + _lstResult;
		_rndResult[i] = _lstResult = _wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = _wrkBuffer[++i];
		_accululator ^= (int)((uint)_accululator >> 6);
		_accululator += _wrkBuffer[++j];
		_wrkBuffer[i] = Y = _wrkBuffer[(X & MASK) >> 2] + _accululator + _lstResult;
		_rndResult[i] = _lstResult = _wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = _wrkBuffer[++i];
		_accululator ^= _accululator << 2;
		_accululator += _wrkBuffer[++j];
		_wrkBuffer[i] = Y = _wrkBuffer[(X & MASK) >> 2] + _accululator + _lstResult;
		_rndResult[i] = _lstResult = _wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = _wrkBuffer[++i];
		_accululator ^= (int)((uint)_accululator >> 16);
		_accululator += _wrkBuffer[++j];
		_wrkBuffer[i] = Y = _wrkBuffer[(X & MASK) >> 2] + _accululator + _lstResult;
		_rndResult[i] = _lstResult = _wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;
		++i;
		++j;
	}

	_rslCounter = MSIZE;
}

void ISCRsg::Initialize(bool MixState)
{
	int ctr = 0;
	int A, B, C, D, E, F, G, H;
	A = B = C = D = E = F = G = H = GDNR;

	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);

	while (ctr != MSIZE)
	{
		if (MixState)
		{
			A += _rndResult[ctr];
			B += _rndResult[ctr + 1];
			C += _rndResult[ctr + 2];
			D += _rndResult[ctr + 3];
			E += _rndResult[ctr + 4];
			F += _rndResult[ctr + 5];
			G += _rndResult[ctr + 6];
			H += _rndResult[ctr + 7];
		}

		Mix(A, B, C, D, E, F, G, H);

		_wrkBuffer[ctr] = A;
		_wrkBuffer[ctr + 1] = B;
		_wrkBuffer[ctr + 2] = C;
		_wrkBuffer[ctr + 3] = D;
		_wrkBuffer[ctr + 4] = E;
		_wrkBuffer[ctr + 5] = F;
		_wrkBuffer[ctr + 6] = G;
		_wrkBuffer[ctr + 7] = H;
		ctr += 8;
	}

	if (MixState)
	{
		// second pass makes all of seed affect all of mem
		ctr = 0;
		while (ctr != MSIZE)
		{
			A += _wrkBuffer[ctr];
			B += _wrkBuffer[ctr + 1];
			C += _wrkBuffer[ctr + 2];
			D += _wrkBuffer[ctr + 3];
			E += _wrkBuffer[ctr + 4];
			F += _wrkBuffer[ctr + 5];
			G += _wrkBuffer[ctr + 6];
			H += _wrkBuffer[ctr + 7];

			Mix(A, B, C, D, E, F, G, H);

			_wrkBuffer[ctr] = A;
			_wrkBuffer[ctr + 1] = B;
			_wrkBuffer[ctr + 2] = C;
			_wrkBuffer[ctr + 3] = D;
			_wrkBuffer[ctr + 4] = E;
			_wrkBuffer[ctr + 5] = F;
			_wrkBuffer[ctr + 6] = G;
			_wrkBuffer[ctr + 7] = H;
			ctr += 8;
		}
	}

	Generate();
}

void ISCRsg::GetSeed(size_t Size)
{
	CSPRsg rnd;
	std::vector<byte> seed(Size);
	seed = rnd.GetBytes(Size);
	memcpy(&_rndResult[0], &seed[0], Size);
}

NAMESPACE_SEEDEND
