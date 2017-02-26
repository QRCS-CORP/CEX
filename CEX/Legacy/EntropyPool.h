#ifndef _CEXENGINE_ENTROPYPOOL_H
#define _CEXENGINE_ENTROPYPOOL_H

#include "CEXNS.h"
#include "IntUtils.h"

NAMESPACE_COMMON

/// <summary>
/// Provides a source of system entropy for pseudo random generators.
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
#if defined(CPPEXCEPTIONS_ENABLED)
		throw std::exception("Not Implemented!");
#endif
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~EntropyPool()
	{
		Destroy();
	}

	/// <summary>
	/// Destroy this class
	/// </summary>
	void Destroy()
	{
		if (!_isDestroyed)
			_isDestroyed = true;
	}
};

NAMESPACE_COMMONEND
#endif