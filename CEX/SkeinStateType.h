#ifndef _CEX_SKEINSTATETYPE_H
#define _CEX_SKEINSTATETYPE_H

/// <summary>
/// Specifies the Skein initialization type
/// </summary>
enum class SkeinStateType : uint
{
	/// <summary>
	/// Identical to the standard Skein initialization.
	/// </summary>
	Normal = 1,
	/// <summary>
	/// Creates the initial state with zeros instead of the configuration block, then initializes the hash.
	/// This does not start a new UBI block type, and must be done manually.
	/// </summary>
	ZeroedState = 2,
	/// <summary>
	/// Leaves the initial state set to its previous value, which is then chained with subsequent block transforms.
	/// This does not start a new UBI block type, and must be done manually.
	/// </summary>
	ChainedState = 4,
	/// <summary>
	/// Creates the initial state by chaining the previous state value with the config block, then initializes the hash.
	/// This starts a new UBI block type with the standard Payload type.
	/// </summary>
	ChainedConfig = 8
};

#endif