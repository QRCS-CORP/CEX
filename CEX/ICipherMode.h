﻿// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.If not, see <http://www.gnu.org/licenses/>.

#ifndef _CEX_ICIPHERMODE_H
#define _CEX_ICIPHERMODE_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "CipherModes.h"
#include "CryptoCipherModeException.h"
#include "IBlockCipher.h"
#include "ParallelOptions.h"
#include "SymmetricKeySize.h"

NAMESPACE_MODE

using Enumeration::BlockCiphers;
using Enumeration::CipherModes; 
using Exception::CryptoCipherModeException;
using Block::IBlockCipher;
using Key::Symmetric::ISymmetricKey;
using Common::ParallelOptions;
using Key::Symmetric::SymmetricKeySize;

/// <summary>
/// Block Cipher standard Mode virtual interface class.
/// <para>Provides virtual interfaces for standard symmetric block cipher modes.</para>
/// </summary>
class ICipherMode
{
public:

	ICipherMode(const ICipherMode&) = delete;
	ICipherMode& operator=(const ICipherMode&) = delete;

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the ICipherMode virtual interface class
	/// </summary>
	ICipherMode() {}

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
	/// Get: The block ciphers formal type name
	/// </summary>
	virtual BlockCiphers CipherType() = 0;

	/// <summary>
	/// Get: The underlying Block Cipher instance
	/// </summary>
	virtual IBlockCipher* Engine() = 0;

	/// <summary>
	/// Get: The Cipher Modes enumeration type name
	/// </summary>
	virtual const CipherModes Enumeral() = 0;

	/// <summary>
	/// Get: True if initialized for encryption, False for decryption
	/// </summary>
	virtual const bool IsEncryption() = 0;

	/// <summary>
	/// Get: The Block Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Get: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() = 0;

	/// <summary>
	/// Get: Array of allowed cipher input key byte-sizes
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const = 0;

	/// <summary>
	/// Get: The cipher mode name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Get: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.<para>
	/// </summary>
	virtual const size_t ParallelBlockSize() = 0;

	/// <summary>
	/// Get/Set: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by ParallelMinimumSize().
	/// Changes to these values must be made before the <see cref="Initialize(SymmetricKey)"/> function is called.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Initialize the Cipher instance
	/// </summary>
	///
	/// <param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
	/// <param name="KeyParams">The SymmetricKey containing key and vector</param>
	virtual void Initialize(bool Encryption, ISymmetricKey &KeyParams) = 0;

	/// <summary>
	/// Transform an entire block of bytes. 
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// This method is used in a buffering strategy, where buffers of size BlockSize() for sequential processing, 
	/// or ParallelBlockSize() for parallel processing, are processed and copied to a larger array by the caller.
	/// Buffers should be of the same size, either BlockSize(), or ParallelBlockSize() if parallel processing is available.
	/// If the Input and Output array sizes differ, the smallest array size will be processed.
	/// To disable parallel processing, set the ParallelOptions().IsParallel() property to false.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	virtual size_t Transform(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Transform a block of bytes with offset parameters.
	/// <para>Transforms one block of bytes at the designated offsets.
	/// This method is used when looping through two large arrays utilizing offsets incremented by the caller.
	/// One block is processed of either ParallelBlockSize() if parallel processing is available, or BlockSize() for sequential mode.
	/// To disable parallel processing, set the ParallelOptions().IsParallel() property to false.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	virtual size_t Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) = 0;

	/// <summary>
	/// Transform a length of bytes with offset parameters. 
	/// <para>This method processes a specified length of bytes, utilizing offsets incremented by the caller.
	/// If IsParallel() is set to true, and the length is at least ParallelBlockSize(), the transform is run in parallel processing mode.
	/// To disable parallel processing, set the ParallelOptions().IsParallel() property to false.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	/// <param name="Length">The number of bytes to transform</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length) = 0;
};

NAMESPACE_MODEEND
#endif
