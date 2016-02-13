<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoPaddingException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="8">
<summary>
Wraps exceptions thrown within a cipher padding operation
</summary>
</member>
<member name="M:CEX.Exception.CryptoPaddingException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoPaddingException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoPaddingException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoPaddingException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptopaddingexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:None" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="12">
<summary>
Specify None if the input should not require padding (block aligned)
</summary>
</member>
<member name="F:ISO7816" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="16">
<summary>
ISO7816 Padding Mode
</summary>
</member>
<member name="F:PKCS7" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="20">
<summary>
PKCS7 Padding Mode
</summary>
</member>
<member name="F:TBC" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="24">
<summary>
Trailing Bit Complement Padding Mode
</summary>
</member>
<member name="F:X923" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="28">
<summary>
X923 Padding Mode
</summary>
</member>
<member name="T:CEX.Enumeration.PaddingModes" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="7">
<summary>
Block Cipher Padding Modes
</summary>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Padding.IPadding" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="12">
<summary>
Padding Mode Interface
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="20">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="25">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="32">
<summary>
Get: The padding modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.Name" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="37">
<summary>
Get: Padding name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.AddPadding(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="44">
<summary>
Add padding to input array
</summary>

<param name="Input">Array to modify</param>
<param name="Offset">Offset into array</param>

<returns>Length of padding</returns>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.GetPaddingLength(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="54">
<summary>
Get the length of padding in an array
</summary>

<param name="Input">Padded array of bytes</param>

<returns>Length of padding</returns>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.IPadding.GetPaddingLength(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\ipadding.h" line="63">
<summary>
Get the length of padding in an array
</summary>

<param name="Input">Padded array of bytes</param>
<param name="Offset">Offset into array</param>

<returns>Length of padding</returns>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Padding.ISO7816" decl="false" source="c:\users\john\documents\github\cex\engine\iso7816.h" line="8">
<summary>
The ISO7816 Padding Scheme
</summary>

<remarks>
<description>Guiding Publications:</description>
<list type="number">
<item><description>ISO/IEC <a href="http://www.iso.org/iso/home/store/catalogue_tc/catalogue_detail.htm?csnumber=36134">7816-4:2005</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.ISO7816.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\iso7816.h" line="27">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.ISO7816.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\iso7816.h" line="32">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.ISO7816.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\iso7816.h" line="39">
<summary>
Get: The padding modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.ISO7816.Name" decl="false" source="c:\users\john\documents\github\cex\engine\iso7816.h" line="44">
<summary>
Get: Padding name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.ISO7816.AddPadding(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\iso7816.h" line="51">
<summary>
Add padding to input array
</summary>

<param name="Input">Array to modify</param>
<param name="Offset">Offset into array</param>

<returns>Length of padding</returns>

<exception cref="T:CEX.Exception.CryptoPaddingException">Thrown if the padding offset value is longer than the array length</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.ISO7816.GetPaddingLength(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\iso7816.h" line="63">
<summary>
Get the length of padding in an array
</summary>

<param name="Input">Padded array of bytes</param>

<returns>Length of padding</returns>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Padding.ISO7816.GetPaddingLength(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\iso7816.h" line="72">
<summary>
Get the length of padding in an array
</summary>

<param name="Input">Padded array of bytes</param>
<param name="Offset">Offset into array</param>

<returns>Length of padding</returns>
</member>
</members>
</doc>