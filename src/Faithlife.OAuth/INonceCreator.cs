namespace Faithlife.OAuth
{
	/// <summary>
	/// Creates a nonce.
	/// </summary>
	/// <remarks>
	/// <para>Implementations of this interface may vary in the length or randomness of the nonces they create.</para>
	/// <para>See also <a href="http://en.wikipedia.org/wiki/Cryptographic_nonce">cryptographic nonce</a>.</para>
	/// </remarks>
	public interface INonceCreator
	{
		/// <summary>
		/// Creates a new nonce.
		/// </summary>
		/// <returns>A non-<c>null</c>, non-<c>empty</c> string that contains a random nonce value.</returns>
		string CreateNonce();
	}
}
