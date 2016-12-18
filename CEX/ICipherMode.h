// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
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
#include "IBlockCipher.h"
#include "CryptoCipherModeException.h"
#include "SymmetricKeySize.h"

NAMESPACE_MODE

using Enumeration::BlockCiphers;
using Enumeration::CipherModes; 
using Exception::CryptoCipherModeException;
using Block::IBlockCipher;
using Key::Symmetric::ISymmetricKey;
using Key::Symmetric::SymmetricKeySize;

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
	/// Get: Returns True if the cipher supports AVX intrinsics
	/// </summary>
	virtual const bool HasAVX2() = 0;

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
	/// Get: Array of valid encryption key byte lengths
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const = 0;

	/// <summary>
	/// Get: The cipher mode name
	/// </summary>
	virtual const std::string Name() = 0;

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
	/// <param name="KeyParam">The SymmetricKey containing key and vector</param>
	virtual void Initialize(bool Encryption, ISymmetricKey &KeyParam) = 0;

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
