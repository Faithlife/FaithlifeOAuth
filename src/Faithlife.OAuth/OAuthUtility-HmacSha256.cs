using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Faithlife.Utility;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Utility code for OAuth authentication.
	/// </summary>
	/// <remarks>
	/// This code was copied from http://git/Logos/WebCommon/blob/master/src/Logos.Common.Web.OAuth/OAuthUtility.cs.
	/// </remarks>
	public static partial class OAuthUtility
	{
		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA256 signature method.
		/// </summary>
		public static Uri CreateHmacSha256Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret)
		{
			string newUri;
			string signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha256Parameters(consumerToken, s_nonceCreator, s_systemTime), out newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha256Signature(signatureBase, consumerSecret, null)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA256 signature method.
		/// </summary>
		public static Uri CreateHmacSha256Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string callback)
		{
			string newUri;
			string signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha256Parameters(consumerToken, s_nonceCreator, s_systemTime, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Callback, callback) }), out newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha256Signature(signatureBase, consumerSecret, null)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA256 signature method.
		/// </summary>
		public static Uri CreateHmacSha256Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier)
		{
			string newUri;
			string signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha256Parameters(consumerToken, s_nonceCreator, s_systemTime, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, temporaryToken), NewKeyValuePair(OAuthConstants.Verifier, verifier) }), out newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha256Signature(signatureBase, consumerSecret, temporarySecret)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA256 signature method.
		/// </summary>
		public static Uri CreateHmacSha256Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret)
		{
			string newUri;
			string signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha256Parameters(consumerToken, s_nonceCreator, s_systemTime, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, accessToken) }), out newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha256Signature(signatureBase, consumerSecret, accessSecret)));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, string timeStamp)
		{
			return CreateHmacSha256Signature(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonce, timeStamp));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>> formParameters)
		{
			return CreateHmacSha256Signature(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonce, timeStamp, formParameters));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string callback, string nonce, string timeStamp)
		{
			return CreateHmacSha256Signature(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonce, timeStamp, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Callback, callback) }));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string callback, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>> formParameters)
		{
			List<KeyValuePair<string, string>> additionalParameters = new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Callback, callback) };
			if (formParameters != null)
				additionalParameters.AddRange(formParameters);
			return CreateHmacSha256Signature(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonce, timeStamp, additionalParameters));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, string nonce, string timeStamp)
		{
			return CreateHmacSha256Signature(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha256Parameters(consumerToken, nonce, timeStamp, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, temporaryToken), NewKeyValuePair(OAuthConstants.Verifier, verifier) }));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>> formParameters)
		{
			List<KeyValuePair<string, string>> additionalParameters = new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, temporaryToken), NewKeyValuePair(OAuthConstants.Verifier, verifier) };
			if (formParameters != null)
				additionalParameters.AddRange(formParameters);
			return CreateHmacSha256Signature(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha256Parameters(consumerToken, nonce, timeStamp, additionalParameters));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string nonce, string timeStamp)
		{
			return CreateHmacSha256Signature(uri, httpMethod, consumerSecret, accessSecret, GetHmacSha256Parameters(consumerToken, nonce, timeStamp, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, accessToken) }));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>> formParameters)
		{
			List<KeyValuePair<string, string>> additionalParameters = new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, accessToken) };
			if (formParameters != null)
				additionalParameters.AddRange(formParameters);
			return CreateHmacSha256Signature(uri, httpMethod, consumerSecret, accessSecret, GetHmacSha256Parameters(consumerToken, nonce, timeStamp, additionalParameters));
		}

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null)
		{
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime));
		}

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, IEnumerable<KeyValuePair<string, string>> formParameters, string httpMethod, string consumerToken, string consumerSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null)
		{
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, formParameters));
		}

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string callback, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null)
		{
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Callback, callback) }));
		}

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, IEnumerable<KeyValuePair<string, string>> formParameters, string httpMethod, string consumerToken, string consumerSecret, string callback, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null)
		{
			List<KeyValuePair<string, string>> additionalParameters = new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Callback, callback) };
			if (formParameters != null)
				additionalParameters.AddRange(formParameters);
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, additionalParameters));
		}

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null)
		{
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, temporaryToken), NewKeyValuePair(OAuthConstants.Verifier, verifier) }));
		}

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, IEnumerable<KeyValuePair<string, string>> formParameters, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null)
		{
			List<KeyValuePair<string, string>> additionalParameters = new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, temporaryToken), NewKeyValuePair(OAuthConstants.Verifier, verifier) };
			if (formParameters != null)
				additionalParameters.AddRange(formParameters);
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, additionalParameters));
		}

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null)
		{
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, accessSecret, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, accessToken) }));
		}

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, IEnumerable<KeyValuePair<string, string>> formParameters, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null)
		{
			List<KeyValuePair<string, string>> additionalParameters = new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, accessToken) };
			if (formParameters != null)
				additionalParameters.AddRange(formParameters);
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, accessSecret, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, additionalParameters));
		}

		internal static string CreateHmacSha256Signature(string signatureBase, string consumerSecret, string? tokenSecret)
		{
			using var hmacsha256 = new HMACSHA256(Encoding.UTF8.GetBytes(CreatePlainTextSignature(consumerSecret, tokenSecret)));
			return Convert.ToBase64String(hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(signatureBase)));
		}

		private static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters)
		{
			string signatureBase = CreateSignatureBase(uri, httpMethod, parameters, out var newUri);

			parameters.Add(new KeyValuePair<string, string>(OAuthConstants.Signature, CreateHmacSha256Signature(signatureBase, consumerSecret, tokenSecret)));

			return OAuthConstants.HeaderPrefix + " " + parameters
				.Where(parameter => parameter.Key.StartsWithOrdinal(OAuthConstants.ParameterPrefix) && parameter.Value != null)
				.Select(p => "{0}=\"{1}\"".FormatInvariant(p.Key, PercentEncode(p.Value)))
				.Join(",");
		}

		private static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters)
		{
			return CreateHmacSha256Signature(CreateSignatureBase(uri, httpMethod, parameters, out string _), consumerSecret, tokenSecret);
		}

		private static ICollection<KeyValuePair<string, string>> GetHmacSha256Parameters(string consumerToken, INonceCreator nonceCreator, ISystemTime systemTime, IEnumerable<KeyValuePair<string, string>>? additionalParameters = null)
		{
			return GetHmacSha256Parameters(consumerToken, nonceCreator.CreateNonce(), DateTimeUtility.ToUnixTimestamp(systemTime.GetUtcNow()).ToInvariantString(), additionalParameters);
		}

		private static ICollection<KeyValuePair<string, string>> GetHmacSha256Parameters(string consumerToken, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>>? additionalParameters = null)
		{
			return new List<KeyValuePair<string, string>>
			{
				NewKeyValuePair(OAuthConstants.ConsumerKey, consumerToken),
				NewKeyValuePair(OAuthConstants.Nonce, nonce),
				NewKeyValuePair(OAuthConstants.SignatureMethod, OAuthSignatureMethods.HmacSha256),
				NewKeyValuePair(OAuthConstants.TimeStamp, timeStamp),
				NewKeyValuePair(OAuthConstants.Version, OAuthConstants.OAuthVersion),
			}.Union(additionalParameters.EmptyIfNull().Where(kvp => kvp.Value != null)).ToList();
		}
	}
}
