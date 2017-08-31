using System;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Methods for working with <see cref="SecureString"/>.
	/// </summary>
	public static class SecureStringUtility
	{
		/// <summary>
		/// Creates a <see cref="SecureString"/> from a normal <see cref="String"/>.
		/// </summary>
		/// <param name="input">The string to convert to a <see cref="SecureString"/>.</param>
		/// <returns>A <see cref="SecureString"/> containing the text in <paramref name="input"/>.</returns>
		public static SecureString FromString(string input)
		{
			if (input == null)
				throw new ArgumentNullException("input");

			SecureString secureString = new SecureString();
			foreach (char ch in input)
				secureString.AppendChar(ch);
			secureString.MakeReadOnly();
			return secureString;
		}

		/// <summary>
		/// Converts the specified <see cref="SecureString"/> to a normal <see cref="String"/>.
		/// </summary>
		/// <param name="secureString">The <see cref="SecureString"/> to convert.</param>
		/// <returns>A <see cref="String"/> containing the text in <paramref name="secureString"/>.</returns>
		public static string ToString(SecureString secureString)
		{
			if (secureString == null)
				throw new ArgumentNullException("secureString");

			return secureString.GetString();
		}

		/// <summary>
		/// Makes a read-only copy of the specified string.
		/// </summary>
		/// <param name="secureString">The <see cref="SecureString"/> to copy.</param>
		/// <returns>A read-only copy of <paramref name="secureString"/>.</returns>
		public static SecureString CopyAsReadOnly(this SecureString secureString)
		{
			if (secureString == null)
				throw new ArgumentNullException("secureString");

			SecureString copy = secureString.Copy();
			copy.MakeReadOnly();
			return copy;
		}
	}
}
