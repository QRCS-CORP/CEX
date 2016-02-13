<?xml version="1.0"?><doc>
<members>
<member name="T:Threefish256" decl="false" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="6">
<summary>
Part of Skein256: the Threefish cipher using a 256bit key size.
</summary> 
</member>
<member name="M:Threefish256.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="22">
<summary>
Threefish with a 256 bit block
</summary>
</member>
<member name="M:Threefish256.Clear" decl="true" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="34">
<summary>
Reset the state
</summary>
</member>
<member name="M:Threefish256.Encrypt(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="39">
<summary>
Encrypt a block
</summary>

<param name="Input">Input array</param>
<param name="Output">Processed bytes</param>
</member>
<member name="M:Threefish256.SetKey(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="47">
<summary>
Initialize the key
</summary>

<param name="Key">The cipher key</param>
</member>
<member name="M:Threefish256.SetTweak(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="54">
<summary>
Initialize the tweak
</summary>

<param name="Tweak">The cipher tweak</param>
</member>
</members>
</doc>