<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="8">
<summary>
Generalized cryptographic error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="T:CEX.Exception.CryptoRandomException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="8">
<summary>
Wraps exceptions thrown within Pseudo Random Number Generator operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="12">
<summary>
A Secure Seed Generator using RNGCryptoServiceProvider
</summary>
</member>
<member name="F:ISCRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="16">
<summary>
A Secure Seed Generator using the entropy pool and an ISAAC generator
</summary>
</member>
<member name="F:XSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="20">
<summary>
A (fast but less secure) Seed Generator using the entropy pool and an XorShift+ generator
</summary>
</member>
<member name="T:CEX.Enumeration.SeedGenerators" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="7">
<summary>
Seed Generators
</summary>
</member>
<member name="T:CEX.Seed.ISeed" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="13">
<summary>
ISeed: Pseudo random seed generator interface
</summary>
</member>
<member name="M:CEX.Seed.ISeed.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="21">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="26">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="33">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="38">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="45">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="50">
<summary>
Get the pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="57">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.ISeed.Next" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="66">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="71">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Helper.SeedFromName" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedfromname.h" line="15">
<summary>
SeedFromName: Get a seed generator instance from it's enumeration name
</summary>
</member>
<member name="M:CEX.Helper.SeedFromName.GetInstance(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedfromname.h" line="21">
<summary>
Get a Seed Generator instance with default initialization parameters
</summary>

<param name="SeedType">The seed generator enumeration name</param>

<returns>An initialized seed generator</returns>

<exception cref="T:CEX.Exception.CryptoException">Thrown if the enumeration name is not supported</exception>
</member>
<member name="T:CEX.Seed.CSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="17">
<summary>
CSPRsg: Operating system pseudo random provider.
<para>On a windows system uses the CryptGenRandom api, otherwise uses calls to arc4random.</para>
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
CSPRsg gen;
gen.GetSeed(Output);
</code>
</example>

<revisionHistory>
<revision date="2015/06/09" version="1.0.0.0">Initial release</revision>
</revisionHistory>
</member>
<member name="M:CEX.Seed.CSPRsg.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="43">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="48">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="55">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="63">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="73">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="78">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Input">The array to fill</param>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="85">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.CSPRsg.Next" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="94">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="99">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Seed.ISCRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="8">
<summary>
ISCRsg: Generates seed material using an ISAAC random number generator.
<para>A high speed, cryptographically secure pseudo random provider.</para>
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
ISCRsg gen(Seed);
gen.GetSeed(Output);
</code>
</example>

<revisionHistory>
<revision date="2015/06/09" version="1.0.0.0">Initial release</revision>
</revisionHistory>

<remarks>
<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>ISAAC: a fast cryptographic random number generator: <see href="http://www.burtleburtle.net/bob/rand/isaacafa.html"/>.</description></item>
<item><description>Rossettacode example implementations: <see href="http://rosettacode.org/wiki/The_ISAAC_Cipher"/>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Seed.ISCRsg.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="54">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="59">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="66">
<summary>
Initialize this class using a seed generated by the default random provider
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.#ctor(std.vector&lt;System.Int32,std.allocator&lt;System.Int32&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="85">
<summary>
Initialize this class using a seed value
</summary>

<param name="Seed">The initial state values; must be between 2 and 256, 32bit values</param>

<exception cref="T:CEX.Exception.CryptoRandomException">Thrown if an invalid seed size is used</exception>
</member>
<member name="M:CEX.Seed.ISCRsg.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="111">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="121">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="126">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Input">The array to fill</param>
</member>
<member name="M:CEX.Seed.ISCRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="133">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.ISCRsg.Initialize(System.Boolean)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="142">
<summary>
initializes the generator with new state
</summary>

<param name="MixState">Mix with the initial state values</param>
</member>
<member name="M:CEX.Seed.ISCRsg.Next" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="149">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.ISCRsg.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iscrsg.h" line="154">
<summary>
Reinitialize the internal state using existing state as a seed
</summary>
</member>
<member name="T:CEX.Seed.XSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="8">
<summary>
XSPRsg: Generates seed material using an XorShift+ generator.
<para>This generator is not generally considered a cryptographic quality generator. 
This generator is suitable as a quality high-speed number generator, but not to be used directly for tasks that require secrecy, ex. key generation.</para>
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
XSPRsg gen(Seed);
gen.GetSeed(Output);
</code>
</example>

<revisionHistory>
<revision date="2015/06/09" version="1.0.0.0">Initial release</revision>
</revisionHistory>

<remarks>
<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>Further scramblings of Marsaglia’s xorshift generators <see href="http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf"/>.</description></item>
<item><description>Xorshift+ generators and the PRNG shootout: <see href="http://xorshift.di.unimi.it/"/>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Seed.XSPRsg.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="55">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="60">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="67">
<summary>
Initialize this class using the default random provider to generate 16 ulongs and invoke the 1024 bit function
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.#ctor(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="92">
<summary>
Initialize this class with a random seed array.
<para>Initializing with 2 ulongs invokes the 128 bit function, initializing with 16 ulongs
invokes the 1024 bit function.</para>
</summary>

<param name="Seed">The initial state values; can be either 2, or 16, 64bit values</param>

<exception cref="T:CEX.Exception.CryptoRandomException">Thrown if an invalid seed size is used</exception>
</member>
<member name="M:CEX.Seed.XSPRsg.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="135">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="145">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="150">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Output">The array to fill</param>
</member>
<member name="M:CEX.Seed.XSPRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="157">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.XSPRsg.Jump" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="166">
<summary>
Increment the state by 64 blocks; used with the 128 and 1024 implementations
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.Next" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="171">
<summary>
Returns the next pseudo random 32bit integer
</summary>

<returns>A pseudo random 32bit integer</returns>
</member>
<member name="M:CEX.Seed.XSPRsg.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="178">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Seed.XSPRsg.Split(System.UInt64)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\xsprsg.h" line="183">
<summary>
Implementation of java's Splittable function
</summary>

<param name="X">Input integer</param>

<returns>A processed long integer</returns>
</member>
</members>
</doc>