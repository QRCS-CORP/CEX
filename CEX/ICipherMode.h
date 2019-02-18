// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_ICIPHERMODE_H
#define CEX_ICIPHERMODE_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "BlockCipherExtensions.h"
#include "CipherModes.h"
#include "CryptoCipherModeException.h"
#include "IBlockCipher.h"
#include "ParallelOptions.h"
#include "SymmetricKeySize.h"

NAMESPACE_MODE

using Enumeration::BlockCiphers;
using Enumeration::BlockCipherExtensions;
using Enumeration::CipherModes; 
using Exception::CryptoCipherModeException;
using Enumeration::ErrorCodes;
using Block::IBlockCipher;
using Cipher::ISymmetricKey;
using Cipher::SymmetricKeySize;

/// <summary>
/// Block Cipher standard Mode virtual interface class.
/// <para>Provides virtual interfaces for standard symmetric block cipher modes.</para>
/// </summary>
class ICipherMode
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ICipherMode(const ICipherMode&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ICipherMode& operator=(const ICipherMode&) = delete;

	/// <summary>
	/// Initialize the ICipherMode virtual interface class
	/// </summary>
	ICipherMode() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~ICipherMode() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Block size of internal cipher in bytes
	/// </summary>
	virtual const size_t BlockSize() = 0;

	/// <summary>
	/// Read Only: The block ciphers formal type name
	/// </summary>
	virtual const BlockCiphers CipherType() = 0;

	/// <summary>
	/// Read Only: The underlying Block Cipher instance
	/// </summary>
	virtual IBlockCipher* Engine() = 0;

	/// <summary>
	/// Read Only: The Cipher Modes enumeration type name
	/// </summary>
	virtual const CipherModes Enumeral() = 0;

	/// <summary>
	/// Read Only: True if initialized for encryption, False for decryption
	/// </summary>
	virtual const bool IsEncryption() = 0;

	/// <summary>
	/// Read Only: The Block Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() = 0;

	/// <summary>
	/// Read Only: Array of allowed cipher input key byte-sizes
	/// </summary>
	virtual const std::vector<SymmetricKeySize> &LegalKeySizes() = 0;

	/// <summary>
	/// Read Only: The mode and cipher name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	virtual const size_t ParallelBlockSize() = 0;

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by ParallelMinimumSize().
	/// Changes to these values must be made before the <see cref="Initialize(SymmetricKey)"/> function is called.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	virtual void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para>Decrypts one block of bytes using the designated offsets.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) = 0;

	/// <summary>
	/// Encrypt a single block of bytes. 
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	virtual void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Encrypt a block of bytes using offset parameters. 
	/// <para>Encrypts one block of bytes using the designated offsets.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) = 0;

	/// <summary>
	/// Initialize the Cipher instance
	/// </summary>
	///
	/// <param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
	/// <param name="Parameters">The SymmetricKey containing key and vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid key or nonce is used</exception>
	virtual void Initialize(bool Encryption, ISymmetricKey &Parameters) = 0;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads to allocate</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	virtual void ParallelMaxDegree(size_t Degree) = 0;

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
