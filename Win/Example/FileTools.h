#ifndef CEXEXAMPLE_FILETOOLS_H
#define CEXEXAMPLE_FILETOOLS_H

#include "Common.h"

namespace Example
{
	class FileTools final
	{
	public:

		/// <summary>
		/// Create a new empty file
		/// </summary>
		///
		/// <param name="FilePath">The full file path, including the file name</param>
		///
		/// <returns>Returns true on file creation, false for failure</returns>
		static bool Create(const std::string &FilePath);

		/// <summary>
		/// Delete a file
		/// </summary>
		///
		/// <param name="FilePath">The full file path, including the file name</param>
		///
		/// <returns>Returns true on successful deletion, false for failure</returns>
		static bool Delete(const std::string &FilePath);

		/// <summary>
		/// Erase a file
		/// </summary>
		///
		/// <param name="FilePath">The full file path, including the file name</param>
		///
		/// <returns>Returns true on successful erasure, false for failure</returns>
		static bool Erase(const std::string &FilePath);

		/// <summary>
		/// Test for the existence of a file
		/// </summary>
		///
		/// <param name="FilePath">The full file path, including the file name</param>
		///
		/// <returns>Returns true if the file exists</returns>
		static bool Exists(const std::string &FilePath);

		/// <summary>
		/// Parse the file extension from the full path and name
		/// </summary>
		///
		/// <returns>The file extension</returns>
		static std::string Extension(std::string const &FilePath)
		{
			std::string tnme = Name(FilePath);

			return FilePath.substr(FilePath.find_last_of(".") + 1);
		}

		/// <summary>
		/// Parse the file name with extension from the file path
		/// </summary>
		///
		/// <returns>The file name</returns>
		static std::string Name(std::string const &FilePath)
		{
			std::string tmpn;

			tmpn = FilePath.substr(FilePath.find_last_of("/\\") + 1);
			tmpn = tmpn.substr(0, tmpn.find_last_of("."));

			return tmpn;
		}

		/// <summary>
		/// Parse the file path from the full path and name
		/// </summary>
		///
		/// <returns>The file path</returns>
		static std::string Path(std::string const &FilePath)
		{
			const size_t NMELEN = Name(FilePath).size() + Extension(FilePath).size() + 1;

			return FilePath.substr(0, FilePath.size() - NMELEN);
		}

		/// <summary>
		/// Get a files size in bytes
		/// </summary>
		///
		/// <param name="FilePath">The full file path, including the file name</param>
		///
		/// <returns>The size of the file in bytes</returns>
		static size_t Size(const std::string &FilePath);

		/// <summary>
		/// Read a vector of bytes from a file
		/// </summary>
		///
		/// <param name="FilePath">The full file path, including the file name</param>
		/// <param name="Output">The output byte vector</param>
		///
		/// <returns>Returns true if the read operation was successful</returns>
		static bool Read(const std::string &FilePath, std::vector<uint8_t> &Output);

		/// <summary>
		/// Write a vector of of bytes to a file
		/// </summary>
		///
		/// <param name="FilePath">The full file path, including the file name</param>
		/// <param name="Input">The input byte vector</param>
		///
		/// <returns>Returns true if the read operation was successful</returns>
		static bool Write(const std::string &FilePath, const std::vector<uint8_t> &Input);
	};
}

#endif
