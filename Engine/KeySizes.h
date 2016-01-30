#ifndef _CEXENGINE_KEYSIZES_H
#define _CEXENGINE_KEYSIZES_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// <para>Key Sizes in bits. Can be cast as Key byte size integers, 
/// i.e. (int sz = KeySizes.K256) is equal to 32.</para>
/// </summary>
enum class KeySizes : unsigned int
{
	/// <summary>
	/// 128 bit Key
	/// </summary>
	K128 = 16,
	/// <summary>
	/// 192 bit Key
	/// </summary>
	K192 = 24,
	/// <summary>
	/// 256 bit Key
	/// </summary>
	K256 = 32,
	/// <summary>
	/// 384 bit Key
	/// </summary>
	K384 = 48,
	/// <summary>
	/// 448 bit Key
	/// </summary>
	K448 = 56,
	/// <summary>
	/// 512 bit Key
	/// </summary>
	K512 = 64,
	/// <summary>
	/// 768 bit Key
	/// </summary>
	K768 = 96,
	/// <summary>
	/// 1024 bit Key
	/// </summary>
	K1024 = 128,
	/// <summary>
	/// 1088 bit Key
	/// </summary>
	K1088 = 136,
	/// <summary>
	/// 1280 bit Key
	/// </summary>
	K1280 = 160,
	/// <summary>
	/// 1536 bit Key
	/// </summary>
	K1536 = 192,
	/// <summary>
	/// 1664 bit Key
	/// </summary>
	K1664 = 208,
	/// <summary>
	/// 1792 bit Key
	/// </summary>
	K1792 = 224,
	/// <summary>
	/// 2048 bit Key
	/// </summary>
	K2048 = 256,
	/// <summary>
	/// 2240 bit Key
	/// </summary>
	K2240 = 280,
	/// <summary>
	/// 2304 bit Key
	/// </summary>
	K2304 = 288,
	/// <summary>
	/// 2560 bit Key
	/// </summary>
	K2560 = 320,
	/// <summary>
	/// 2816 bit Key 
	/// </summary>
	K2816 = 352,
	/// <summary>
	/// 3072 bit Key
	/// </summary>
	K3072 = 384,
	/// <summary>
	/// 3584 bit Key
	/// </summary>
	K3584 = 448,
	/// <summary>
	/// 4096 bit Key
	/// </summary>
	K4096 = 512,
	/// <summary>
	/// 4608 bit Key
	/// </summary>
	K4608 = 576,
	/// <summary>
	/// 5120 bit Key
	/// </summary>
	K5120 = 640
};

NAMESPACE_ENUMERATIONEND
#endif