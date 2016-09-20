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

#ifndef _CEXENGINE_ICIPHERMODE_H
#define _CEXENGINE_ICIPHERMODE_H

#include "Common.h"
#include "BlockCiphers.h"
#include "CipherModes.h"
#include "IBlockCipher.h"
#if defined(CPPEXCEPTIONS_ENABLED)
#	include "CryptoCipherModeException.h"
#endif

NAMESPACE_MODE

using CEX::Enumeration::BlockCiphers;
using CEX::Enumeration::CipherModes; 
using CEX::Cipher::Symmetric::Block::IBlockCipher;
using CEX::Common::KeyParams;
#if defined(CPPEXCEPTIONS_ENABLED)
	using CEX::Exception::CryptoCipherModeException;
#endif

/// <summary>
/// Cipher mode virtual interface class.
/// <para>Provides virtual interfaces for standard symmetric block cipher modes.</para>
/// </summary>
class ICipherMode
{
	ICipherMode(const ICipherMode&) = delete;
	ICipherMode& operator=(const ICipherMode&) = delete;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the ICipherMode virtual interface class
	/// </summary>
	explicit ICipherMode() {}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~ICipherMode() {}


	//~~~Properties~~~//

	/// <summary>
	/// Get: Block size of internal cipher in bytes
	/// </summary>
	virtual const size_t BlockSize() = 0;

	/// <summary>
	/// Get: The underlying Block Cipher instance
	/// </summary>
	virtual IBlockCipher* Engine() = 0;

	/// <summary>
	/// Get: The Cipher Modes enumeration type name
	/// </summary>
	virtual const CipherModes Enumeral() = 0;

	/// <summary>
	/// Get: Returns True if the cipher supports AVX intrinsics
	/// </summary>
	virtual const bool HasAVX() = 0;

	/// <summary>
	/// Get: Returns True if the cipher supports SIMD intrinsics
	/// </summary>
	virtual const bool HasSSE() = 0;

	/// <summary>
	/// Get: True if initialized for encryption, False for decryption
	/// </summary>
	virtual const bool IsEncryption() = 0;

	/// <summary>
	/// Get: The Block Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Get: Enable automatic processor parallelization
	/// </summary>
	virtual bool &IsParallel() = 0;

	/// <summary>
	/// Get: The current state of the Initialization Vector
	/// </summary>
	virtual const std::vector<byte> &IV() = 0;

	/// <summary>
	/// Get: Array of valid encryption key byte lengths
	/// </summary>
	virtual const std::vector<size_t> &LegalKeySizes() = 0;

	/// <summary>
	/// Get: The Cipher Mode name
	/// </summary>
	virtual const char* Name() = 0;

	/// <summary>
	/// Get/Set: Parallel block size; must be a multiple of <see cref="ParallelMinimumSize"/>
	/// </summary>
	virtual size_t &ParallelBlockSize() = 0;

	/// <summary>
	/// Get: Maximum input block byte length when using multi-threaded processing
	/// </summary>
	virtual const size_t ParallelMaximumSize() = 0;

	/// <summary>
	/// Get: The smallest valid input block byte length, when using multi-threaded processing; parallel blocks must be a multiple of this size
	/// </summary>
	virtual const size_t ParallelMinimumSize() = 0;

	/// <remarks>
	/// Get: Available system processor core count
	/// </remarks>
	virtual const size_t ProcessorCount() = 0;


	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Initialize the Cipher instance
	/// </summary>
	///
	/// <param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
	/// <param name="KeyParam">The KeyParams containing key and vector</param>
	virtual void Initialize(bool Encryption, const KeyParams &KeyParam) = 0;

	/// <summary>
	/// Transform a block of bytes. 
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Initialize() must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Transform a block of bytes with offset parameters.  
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Initialize() must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) = 0;
};

NAMESPACE_MODEEND
#endif
