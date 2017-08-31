namespace Faithlife.OAuth
{
	/// <summary>
	/// OAuth version 1.0 constant strings.
	/// </summary>
	public static class OAuthConstants
	{
		/// <summary>
		/// Authorization header key.
		/// </summary>
		public const string Authorization = "Authorization";

		/// <summary>
		/// Version of OAuth these constants correspond to.
		/// </summary>
		public const string OAuthVersion = "1.0";

		/// <summary>
		/// Prefix for authorization header.
		/// </summary>
		public const string HeaderPrefix = "OAuth";

		/// <summary>
		/// Prefix for parameter keys.
		/// </summary>
		public const string ParameterPrefix = "oauth_";

		/// <summary>
		/// OAuth verifier constant.
		/// </summary>
		public const string Verifier = "oauth_verifier";

		/// <summary>
		/// OAuth token constant.
		/// </summary>
		public const string Token = "oauth_token";

		/// <summary>
		/// OAuth token secret constant.
		/// </summary>
		public const string TokenSecret = "oauth_token_secret";

		/// <summary>
		/// Callback uri.
		/// </summary>
		public const string Callback = "oauth_callback";

		/// <summary>
		/// Consumer key.
		/// </summary>
		public const string ConsumerKey = "oauth_consumer_key";

		/// <summary>
		/// Signature method the Consumer used to sign the request.
		/// </summary>
		public const string SignatureMethod = "oauth_signature_method";

		/// <summary>
		/// OAuth version.
		/// </summary>
		public const string Version = "oauth_version";

		/// <summary>
		/// Has the callback been confirmed
		/// </summary>
		public const string CallbackConfirmed = "oauth_callback_confirmed";

		/// <summary>
		/// Random string, generated for each request, based on the timestamp value.
		/// </summary>
		public const string Nonce = "oauth_nonce";

		/// <summary>
		/// Timestamp for the request (usually in seconds since Jan 1, 1970).
		/// </summary>
		public const string TimeStamp = "oauth_timestamp";

		/// <summary>
		/// Signature method the Consumer used to sign the request.
		/// </summary>
		public const string Signature = "oauth_signature";

		/// <summary>
		/// Relative URL for request token.
		/// </summary>
		public const string RequestTokenRelativeUrl = "oauth/request_token";

		/// <summary>
		/// Relative URL for access token.
		/// </summary>
		public const string AccessTokenRelativeUrl = "oauth/access_token";

		/// <summary>
		/// Relative URL for authorization.
		/// </summary>
		public const string AuthorizeRelativeUrl = "oauth/authorize";
	}
}
