#ifndef CEX_SEEKORIGIN_H
#define CEX_SEEKORIGIN_H

#include "CexDomain.h"

NAMESPACE_IO

/// <summary>
/// Seek origin position flags
/// </summary>
enum class SeekOrigin : uint32_t
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

