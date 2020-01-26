using System;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Implements the standard way of getting the system time.
	/// </summary>
	public sealed class StandardSystemTime : ISystemTime
	{
		/// <summary>
		/// Gets the current UTC time.
		/// </summary>
		/// <returns>A <see cref="DateTime"/> whose value is the current UTC date and time.</returns>
		public DateTime GetUtcNow() => DateTime.UtcNow;
	}
}
