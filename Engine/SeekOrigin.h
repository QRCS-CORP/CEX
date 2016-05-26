#ifndef _CEXENGINE_SEEKORIGIN_H
#define _CEXENGINE_SEEKORIGIN_H

#include "Common.h"

NAMESPACE_IO
/// <summary>
/// Seek origin position flags
/// </summary>
enum class SeekOrigin : uint
{
	/// <summary>
	/// Start at the beginning of the stream
	/// </summary>
	Begin = 1,
	/// <summary>
	/// Start at the streams current position
	/// </summary>
	Current = 2,
	/// <summary>
	/// Start at the end of the stream
	/// </summary>
	End = 4
};
NAMESPACE_IOEND

#endif

