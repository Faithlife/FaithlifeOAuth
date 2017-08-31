using System;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Provides a mechanism for getting the current system time.
	/// </summary>
	/// <remarks>This is intended to return the current system time in production, but can return a fixed value for testing.</remarks>
	public interface ISystemTime
	{
		/// <summary>
		/// Gets the current UTC time.
		/// </summary>
		/// <returns>A <see cref="DateTime"/> whose value is the current UTC date and time.</returns>
		DateTime GetUtcNow();
	}
}
