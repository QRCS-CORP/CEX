#ifndef _CEXENGINE_CPU_H
#define _CEXENGINE_CPU_H

#include "Common.h"

NAMESPACE_UTILITY

/// <summary>
/// Cpu functions class
/// </summary>
class Cpu
{
public:
	inline static bool HasAESNI() // ToDo: temp function, poll cpu for capabilities
	{
		bool state = false;
#if defined(AESNI_AVAILABLE)
		state = true;
#endif

		return state;
	}
};

NAMESPACE_UTILITYEND
#endif