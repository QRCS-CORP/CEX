// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef _CEXENGINE_SKEINPARAMS_H
#define _CEXENGINE_SKEINPARAMS_H

#include "CexDomain.h"

NAMESPACE_DIGEST

/// <summary>
/// The Skein configuration parameters structure
/// </summary> 
struct SkeinState
{
public:

	// state
	std::vector<ulong> S;
	// tweak
	std::vector<ulong> T;
	// config
	std::vector<ulong> V;

	SkeinState(size_t StateSize, size_t CounterSize, size_t CounterSize)
		:
		S(4),
		T(2),
		V(4)
	{
	}

	void Increase(size_t Length)
	{
		T[0] += Length;
	}

	void Reset()
	{
		if (S.size() > 0)
		{
			std::memset(&S[0], 0, S.size() * sizeof(ulong));
		}
		if (T.size() > 0)
		{
			std::memset(&T[0], 0, T.size() * sizeof(ulong));
		}
		if (V.size() > 0)
		{
			std::memset(&V[0], 0, V.size() * sizeof(ulong));
		}
	}

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor; state is initialized to zero defaults
	/// </summary>
	SkeinState();

};

NAMESPACE_DIGESTEND
#endif