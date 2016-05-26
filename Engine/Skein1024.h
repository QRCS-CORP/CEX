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
// 
// Principal Algorithms:
// The Skein Hash Function Family: <a href="https://www.schneier.com/skein1.3.pdf">Skein V1.1</a>.
// Implementation Details:
// An implementation of the Skein digest with a 1024 bit return size. 
// Written by John Underhill, January 13, 2015
// contact: develop@vtdev.com

#ifndef _CEXENGINE_SKEIN1024_H
#define _CEXENGINE_SKEIN1024_H

#include "IDigest.h"
#include "Skein.h"
#include "Threefish1024.h"

NAMESPACE_DIGEST

/// <summary>
/// Skein1024: An implementation of the Skein digest with a 1024 bit digest return size.
/// <para>SHA-3 finalist: The Skein digest</para>
/// </summary> 
/// 
/// <example>
/// <description>Example using the ComputeHash method:</description>
/// <code>
/// Skein1024 digest;
/// std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// digest.ComputeHash(Input, hash);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Digest::IDigest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Block size is 128 bytes, (1024 bits).</description></item>
/// <item><description>Digest size is 128 bytes, (1024 bits).</description></item>
/// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods, and resets the internal state.</description>/></item>
/// <item><description>The <see cref="DoFinal(byte[], int)"/> method does NOT reset the internal state; call <see cref="Reset()"/> to reinitialize.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
/// <item><description>The Skein Hash Function Family <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</a>.</description></item>
/// <item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein-proofs.pdf">Provable Security</a> Support for the Skein Hash Family.</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3 Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition>.</description></item>
/// </list>
/// </remarks>
class Skein1024 : public IDigest
{
private:
	static constexpr size_t BLOCK_SIZE = 128;
	static constexpr size_t DIGEST_SIZE = 128;
	static constexpr size_t STATE_SIZE = 1024;
	static constexpr size_t STATE_BYTES = STATE_SIZE / 8;
	static constexpr size_t STATE_WORDS = STATE_SIZE / 64;
	static constexpr size_t STATE_OUTPUT = (STATE_SIZE + 7) / 8;

	size_t _bytesFilled;
	Threefish1024 _blockCipher;
	std::vector<ulong> _cipherInput;
	std::vector<ulong> _configString;
	std::vector<ulong> _configValue;
	std::vector<ulong> _digestState;
	SkeinInitializationType _initializationType;
	std::vector<byte> _inputBuffer;
	bool _isDestroyed;
	UbiTweak _ubiParameters;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual size_t BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get: Size of returned digest in bytes
	/// </summary>
	virtual size_t DigestSize() { return DIGEST_SIZE; }

	/// <summary>
	/// Get: The digests type enumeration member
	/// </summary>
	virtual CEX::Enumeration::Digests Enumeral() { return CEX::Enumeration::Digests::Skein1024; }

	/// <summary>
	/// Get: Digest name
	/// </summary>
	virtual const char *Name() { return "Skein1024"; }

	/// <summary>
	/// Get the post-chain configuration value
	/// </summary>
	std::vector<ulong> GetConfigValue()
	{
		return _configValue;
	}

	/// <summary>
	/// Get the pre-chain configuration string
	/// </summary>
	std::vector<ulong> GetConfigString()
	{
		return _configString;
	}

	/// <summary>
	/// Get the initialization type
	/// </summary>
	SkeinInitializationType GetInitializationType()
	{
		return _initializationType;
	}

	/// <summary>
	/// Get the state size in bits
	/// </summary>
	size_t GetStateSize()
	{
		return STATE_SIZE;
	}

	/// <summary>
	/// Ubi Tweak parameters
	/// </summary>
	UbiTweak GetUbiParameters()
	{
		return _ubiParameters;
	}

	// *** Constructor *** //

	/// <summary>
	/// Initialize the digest
	/// </summary>
	explicit Skein1024(SkeinInitializationType InitializationType = SkeinInitializationType::Normal)
		:
		_blockCipher(),
		_cipherInput(STATE_WORDS),
		_configString(STATE_SIZE),
		_configValue(STATE_SIZE),
		_isDestroyed(false),
		_digestState(STATE_WORDS),
		_inputBuffer(STATE_BYTES),
		_ubiParameters()
	{
		_initializationType = InitializationType;
		// generate the configuration string
		_configString[1] = (ulong)(DigestSize() * 8);
		// "SHA3"
		std::vector<byte> schema(4, 0);
		schema[0] = 83;
		schema[1] = 72;
		schema[2] = 65;
		schema[3] = 51;
		SetSchema(schema);
		SetVersion(1);
		GenerateConfiguration();
		Initialize(InitializationType);
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Skein1024()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the input buffer is too short</exception>
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length);

	/// <summary>
	/// Get the Hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The hash output value array</param>
	virtual void ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Do final processing and get the hash value
	/// </summary>
	/// 
	/// <param name="Output">The Hash output value array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <returns>Size of Hash value</returns>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output buffer is too short</exception>
	virtual size_t DoFinal(std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Generate a configuration using a state key
	/// </summary>
	/// 
	/// <param name="InitialState">Twofish Cipher key</param>
	void GenerateConfiguration(std::vector<ulong> InitialState);

	/// <summary>
	/// Used to re-initialize the digest state.
	/// <para>Creates the initial state with zeros instead of the configuration block, then initializes the hash. 
	/// This does not start a new UBI block type, and must be done manually.</para>
	/// </summary>
	/// 
	/// <param name="InitializationType">Initialization parameters</param>
	void Initialize(SkeinInitializationType InitializationType);

	/// <summary>
	/// Reset the internal state
	/// </summary>
	void Reset();

	/// <summary>
	/// Set the tree height. Tree height must be zero or greater than 1.
	/// </summary>
	/// 
	/// <param name="Height">Tree height</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoDigestException">Thrown if an invalid tree height is used</exception>
	void SetMaxTreeHeight(const byte Height);

	/// <summary>
	/// Set the Schema. Schema must be 4 bytes.
	/// </summary>
	/// 
	/// <param name="Schema">Schema Configuration string</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoDigestException">Thrown if an invalid schema is used</exception>
	void SetSchema(const std::vector<byte> &Schema);

	/// <summary>
	/// Set the tree fan out size
	/// </summary>
	/// 
	/// <param name="Size">Fan out size</param>
	void SetTreeFanOutSize(const byte Size);

	/// <summary>
	/// Set the tree leaf size
	/// </summary>
	/// 
	/// <param name="Size">Leaf size</param>
	void SetTreeLeafSize(const byte Size);

	/// <summary>
	/// Set the version string. Version must be between 0 and 3, inclusive.
	/// </summary>
	/// 
	/// <param name="Version">Version string</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoDigestException">Thrown if an invalid version is used</exception>
	void SetVersion(const uint Version);

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	void Update(byte Input);

private:
	void GenerateConfiguration();
	void Initialize();
	void ProcessBlock(uint Value);
	static void PutBytes(std::vector<ulong> Input, std::vector<byte> &Output, size_t Offset, size_t ByteCount);
};
NAMESPACE_DIGESTEND
#endif
