using System;
using Faithlife.Utility;

namespace Faithlife.OAuth
{
	/// <summary>
	/// <see cref="GuidNonceCreator"/> creates a new nonce by creating a GUID and converting it to a string.
	/// </summary>
	public sealed class GuidNonceCreator : INonceCreator
	{
		/// <summary>
		/// Creates a new nonce.
		/// </summary>
		/// <returns>A new GUID, converted to a string.</returns>
		public string CreateNonce() => Guid.NewGuid().ToLowerNoDashString();
	}
}
