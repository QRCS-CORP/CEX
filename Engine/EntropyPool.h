#ifndef _CEXENGINE_ENTROPYPOOL_H
#define _CEXENGINE_ENTROPYPOOL_H

#include "Common.h"
#include "IntUtils.h"

NAMESPACE_COMMON

/// <summary>
/// EntropyPool: Provides a source of system entropy for pseudo random generators.
/// <para>Uses various system state, timers, and counters, which are compressed into an entropy pool.</para>
/// </summary> 
class EntropyPool
{
private:
	bool _isDestroyed;

public:
	/// <summary>
	/// Initialize this class
	/// </summary>
	EntropyPool()
		:
		_isDestroyed(false)
	{
		throw std::exception("Not Implemented!");
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~EntropyPool()
	{
		Destroy();
	}

	void Destroy()
	{
		if (!_isDestroyed)
		{
			//CEX::Utility::IntUtils::ClearVector(_key);

			_isDestroyed = true;
		}
	}
};

NAMESPACE_COMMONEND
#endif


/*
void XSPRsg::Mix128(const std::vector<ulong> &Seed)
{
unsigned int len = Seed.size();
std::vector<ulong> X(len);
memcpy(&X[0], &Seed[0], sizeof Seed);

X[0] += (Split(Seed[0]) ^ IntUtils::RotateLeft(X[1], 8));
X[len - 1] ^= (Split(Seed[1]) * IntUtils::RotateLeft(X[0], 12));

for (unsigned int i = 1; i < len - 1; ++i)
{
X[i] += (Split(Seed[i]) ^ IntUtils::RotateLeft(X[len - i], 12));
X[i - 1] ^= (Split(Seed[i - 1]) * IntUtils::RotateLeft(X[len - i], 4));
}

memcpy(&_wrkBuffer[0], &X[0], sizeof X);
}

void XSPRsg::Mix1024(const std::vector<ulong> &Seed)
{
// salsa style mixer extended for uint64
std::vector<ulong> X = Seed;
unsigned int ctr = 16;

while (ctr > 0)
{
// round 1
X[4] ^= IntUtils::RotateLeft(X[0] + X[12], 7);
X[8] ^= IntUtils::RotateLeft(X[4] + X[0], 9);
X[12] ^= IntUtils::RotateLeft(X[8] + X[4], 13);
X[0] ^= IntUtils::RotateLeft(X[12] + X[8], 18);
X[9] ^= IntUtils::RotateLeft(X[5] + X[1], 21);
X[13] ^= IntUtils::RotateLeft(X[9] + X[5], 24);
X[1] ^= IntUtils::RotateLeft(X[13] + X[9], 28);
X[5] ^= IntUtils::RotateLeft(X[1] + X[13], 31);
X[14] ^= IntUtils::RotateLeft(X[10] + X[6], 7);
X[2] ^= IntUtils::RotateLeft(X[14] + X[10], 9);
X[6] ^= IntUtils::RotateLeft(X[2] + X[14], 13);
X[10] ^= IntUtils::RotateLeft(X[6] + X[2], 18);
X[3] ^= IntUtils::RotateLeft(X[15] + X[11], 21);
X[7] ^= IntUtils::RotateLeft(X[3] + X[15], 24);
X[11] ^= IntUtils::RotateLeft(X[7] + X[3], 28);
X[15] ^= IntUtils::RotateLeft(X[11] + X[7], 31);
// round 2
X[1] ^= IntUtils::RotateLeft(X[0] + X[3], 7);
X[2] ^= IntUtils::RotateLeft(X[1] + X[0], 9);
X[3] ^= IntUtils::RotateLeft(X[2] + X[1], 13);
X[0] ^= IntUtils::RotateLeft(X[3] + X[2], 18);
X[6] ^= IntUtils::RotateLeft(X[5] + X[4], 21);
X[7] ^= IntUtils::RotateLeft(X[6] + X[5], 24);
X[4] ^= IntUtils::RotateLeft(X[7] + X[6], 28);
X[5] ^= IntUtils::RotateLeft(X[4] + X[7], 31);
X[11] ^= IntUtils::RotateLeft(X[10] + X[9], 7);
X[8] ^= IntUtils::RotateLeft(X[11] + X[10], 9);
X[9] ^= IntUtils::RotateLeft(X[8] + X[11], 13);
X[10] ^= IntUtils::RotateLeft(X[9] + X[8], 18);
X[12] ^= IntUtils::RotateLeft(X[15] + X[14], 21);
X[13] ^= IntUtils::RotateLeft(X[12] + X[15], 24);
X[14] ^= IntUtils::RotateLeft(X[13] + X[12], 28);
X[15] ^= IntUtils::RotateLeft(X[14] + X[13], 31);

ctr -= 2;
}

memcpy(&_wrkBuffer[0], &X[0], sizeof X);
}

*/