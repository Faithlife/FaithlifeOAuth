using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Faithlife.Utility;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Utility code for OAuth authentication.
	/// </summary>
	public static class OAuthUtility
	{
		/// <summary>
		/// Create OAuth signature using the PLAINTEXT signature method.
		/// </summary>
		public static string CreatePlainTextSignature(string consumerSecret, string? tokenSecret) =>
			PercentEncode(consumerSecret) + "&" + PercentEncode(tokenSecret);

		/// <summary>
		/// Create OAuth authentication header.
		/// </summary>
		public static string CreateAuthorizationHeaderValue(string consumerToken, string consumerSecret)
		{
			var signature = CreatePlainTextSignature(consumerSecret, null);
			return CreateAuthorizationHeaderValue(consumerToken, signature, new Dictionary<string, string?>(0));
		}

		/// <summary>
		/// Create OAuth authentication header with callback attribute.
		/// </summary>
		public static string CreateAuthorizationHeaderValue(string consumerToken, string consumerSecret, string callback)
		{
			var signature = CreatePlainTextSignature(consumerSecret, null);
			return CreateAuthorizationHeaderValue(consumerToken, signature, new Dictionary<string, string?> { { OAuthConstants.Callback, callback } });
		}

		/// <summary>
		/// Create OAuth authentication header with temporary token, secret, and verifier.
		/// </summary>
		public static string CreateAuthorizationHeaderValue(string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier)
		{
			var signature = CreatePlainTextSignature(consumerSecret, temporarySecret);
			return CreateAuthorizationHeaderValue(consumerToken, signature, new Dictionary<string, string?> { { OAuthConstants.Token, temporaryToken }, { OAuthConstants.Verifier, verifier } });
		}

		/// <summary>
		/// Create OAuth authentication header with access token and secret.
		/// </summary>
		public static string CreateAuthorizationHeaderValue(string consumerToken, string consumerSecret, string accessToken, string accessSecret)
		{
			var signature = CreatePlainTextSignature(consumerSecret, accessSecret);
			return CreateAuthorizationHeaderValue(consumerToken, signature, new Dictionary<string, string?> { { OAuthConstants.Token, accessToken } });
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA1 signature method.
		/// </summary>
		public static Uri CreateHmacSha1Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret)
		{
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha1Parameters(consumerToken, s_nonceCreator, s_systemTime), out var newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha1Signature(signatureBase, consumerSecret, null)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA1 signature method.
		/// </summary>
		public static Uri CreateHmacSha1Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string callback)
		{
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha1Parameters(consumerToken, s_nonceCreator, s_systemTime, new Dictionary<string, string?> { { OAuthConstants.Callback, callback } }), out var newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha1Signature(signatureBase, consumerSecret, null)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA1 signature method.
		/// </summary>
		public static Uri CreateHmacSha1Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier)
		{
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha1Parameters(consumerToken, s_nonceCreator, s_systemTime, new Dictionary<string, string?> { { OAuthConstants.Token, temporaryToken }, { OAuthConstants.Verifier, verifier } }), out var newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha1Signature(signatureBase, consumerSecret, temporarySecret)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA1 signature method.
		/// </summary>
		public static Uri CreateHmacSha1Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret)
		{
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha1Parameters(consumerToken, s_nonceCreator, s_systemTime, new Dictionary<string, string?> { { OAuthConstants.Token, accessToken } }), out var newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha1Signature(signatureBase, consumerSecret, accessSecret)));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, string timeStamp) =>
			CreateHmacSha1Signature(uri, httpMethod, consumerSecret, null, GetHmacSha1Parameters(consumerToken, nonce, timeStamp));

		/// <summary>
		/// Create OAuth signature using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string callback, string nonce, string timeStamp) =>
			CreateHmacSha1Signature(uri, httpMethod, consumerSecret, null, GetHmacSha1Parameters(consumerToken, nonce, timeStamp, new Dictionary<string, string?> { { OAuthConstants.Callback, callback } }));

		/// <summary>
		/// Create OAuth signature using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, string nonce, string timeStamp) =>
			CreateHmacSha1Signature(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha1Parameters(consumerToken, nonce, timeStamp, new Dictionary<string, string?> { { OAuthConstants.Token, temporaryToken }, { OAuthConstants.Verifier, verifier } }));

		/// <summary>
		/// Create OAuth signature using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string nonce, string timeStamp) =>
			CreateHmacSha1Signature(uri, httpMethod, consumerSecret, accessSecret, GetHmacSha1Parameters(consumerToken, nonce, timeStamp, new Dictionary<string, string?> { { OAuthConstants.Token, accessToken } }));

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null) =>
			CreateHmacSha1AuthorizationHeaderValue(uri, httpMethod, consumerSecret, null, GetHmacSha1Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime));

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string callback, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null) =>
			CreateHmacSha1AuthorizationHeaderValue(uri, httpMethod, consumerSecret, null, GetHmacSha1Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new Dictionary<string, string?> { { OAuthConstants.Callback, callback } }));

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null) =>
			CreateHmacSha1AuthorizationHeaderValue(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha1Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new Dictionary<string, string?> { { OAuthConstants.Token, temporaryToken }, { OAuthConstants.Verifier, verifier } }));

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null) =>
			CreateHmacSha1AuthorizationHeaderValue(uri, httpMethod, consumerSecret, accessSecret, GetHmacSha1Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new Dictionary<string, string?> { { OAuthConstants.Token, accessToken } }));

		/// <summary>
		/// Encode string per OAuth spec (see http://oauth.net/core/1.0/ section 5.1).
		/// </summary>
		internal static string PercentEncode(string? value)
		{
			if (value is null)
				return "";

			var valueBytes = Encoding.UTF8.GetBytes(value);

			var builder = new StringBuilder();
			foreach (var valueByte in valueBytes)
			{
				if (IsUnreserved(valueByte))
					builder.Append((char) valueByte);
				else
					builder.Append('%' + "{0:X2}".FormatInvariant((int) valueByte));
			}

			return builder.ToString();
		}

		[SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "By design.")]
		internal static string CreateHmacSha1Signature(string signatureBase, string consumerSecret, string? tokenSecret)
		{
			using var hmacsha1 = new HMACSHA1(Encoding.UTF8.GetBytes(CreatePlainTextSignature(consumerSecret, tokenSecret)));
			return Convert.ToBase64String(hmacsha1.ComputeHash(Encoding.UTF8.GetBytes(signatureBase)));
		}

		internal static string CreateSignatureBase(Uri uri, string httpMethod, ICollection<KeyValuePair<string, string>> parameters, out string newUri)
		{
			if (string.IsNullOrEmpty(httpMethod))
				throw new ArgumentNullException(nameof(httpMethod));

			parameters.AddRange(GetQueryParameters(uri.Query));

			var normalizedUriBase = "{0}{1}{2}{3}".FormatInvariant(uri.Scheme, "://", uri.Authority.ToLowerInvariant(), uri.AbsolutePath);
			var normalizedParameters = parameters
				.Select(x => new KeyValuePair<string, string>(PercentEncode(x.Key), PercentEncode(x.Value)))
				.OrderBy(p => p.Key, StringComparer.Ordinal)
				.ThenBy(p => p.Value, StringComparer.Ordinal)
				.Select(p => "{0}={1}".FormatInvariant(p.Key, p.Value))
				.Join("&");

			newUri = "{0}?{1}".FormatInvariant(normalizedUriBase, normalizedParameters);

			return "{0}&{1}&{2}".FormatInvariant(httpMethod.ToUpperInvariant(), PercentEncode(normalizedUriBase), PercentEncode(normalizedParameters));
		}

		private static string CreateAuthorizationHeaderValue(string consumerToken, string signature, Dictionary<string, string?> additionalParameters)
		{
			if (additionalParameters is null)
				throw new ArgumentNullException(nameof(additionalParameters));

			var parameters = new Dictionary<string, string?>
			{
				{ OAuthConstants.ConsumerKey, consumerToken },
				{ OAuthConstants.Signature, signature },
				{ OAuthConstants.SignatureMethod, OAuthSignatureMethods.PlainText },
				{ OAuthConstants.Version, OAuthConstants.OAuthVersion },
			}.Union(additionalParameters).ToDictionary(x => x.Key, x => x.Value);

			return OAuthConstants.HeaderPrefix + " " + parameters
				.Where(parameter => parameter.Value is object)
				.Select(p => "{0}=\"{1}\"".FormatInvariant(p.Key, PercentEncode(p.Value)))
				.Join(",");
		}

		private static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters)
		{
			var signatureBase = CreateSignatureBase(uri, httpMethod, parameters, out var newUri);

			parameters.Add(new KeyValuePair<string, string>(OAuthConstants.Signature, CreateHmacSha1Signature(signatureBase, consumerSecret, tokenSecret)));

			return OAuthConstants.HeaderPrefix + " " + parameters
				.Where(parameter => parameter.Key.StartsWithOrdinal(OAuthConstants.ParameterPrefix) && parameter.Value != null)
				.Select(p => "{0}=\"{1}\"".FormatInvariant(p.Key, PercentEncode(p.Value)))
				.Join(",");
		}

		private static string CreateHmacSha1Signature(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters) =>
			CreateHmacSha1Signature(CreateSignatureBase(uri, httpMethod, parameters, out _), consumerSecret, tokenSecret);

		private static ICollection<KeyValuePair<string, string>> GetHmacSha1Parameters(string consumerToken, INonceCreator nonceCreator, ISystemTime systemTime, Dictionary<string, string?>? additionalParameters = null) =>
			GetHmacSha1Parameters(consumerToken, nonceCreator.CreateNonce(), DateTimeUtility.ToUnixTimestamp(systemTime.GetUtcNow()).ToInvariantString(), additionalParameters);

		private static ICollection<KeyValuePair<string, string>> GetHmacSha1Parameters(string consumerToken, string nonce, string timeStamp, Dictionary<string, string?>? additionalParameters = null)
		{
			var parameters = new Dictionary<string, string>
			{
				{ OAuthConstants.ConsumerKey, consumerToken },
				{ OAuthConstants.Nonce, nonce },
				{ OAuthConstants.SignatureMethod, OAuthSignatureMethods.HmacSha1 },
				{ OAuthConstants.TimeStamp, timeStamp },
				{ OAuthConstants.Version, OAuthConstants.OAuthVersion },
			};
			if (additionalParameters is object)
			{
				foreach (var pair in additionalParameters)
				{
					if (pair.Value is object)
						parameters.Add(pair.Key, pair.Value);
				}
			}
			return parameters;
		}

		internal static IEnumerable<KeyValuePair<string, string>> GetQueryParameters(string query)
		{
			if (query is null || query.Length < 2 || query[0] != '?')
				return Array.Empty<KeyValuePair<string, string>>();

			return query.Substring(1)
				.Split('&')
				.Select(str => str.Split(new[] { '=' }, 2))
				.Select(x => new KeyValuePair<string, string>(UrlEncoding.Decode(x[0], UrlEncodingSettings.HttpUtilitySettings), x.Length == 1 ? "" : UrlEncoding.Decode(x[1], UrlEncodingSettings.HttpUtilitySettings)));
		}

		private static bool IsUnreserved(byte value) =>
			(value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || s_unencodedPunctuation.Contains(value);

		private static readonly INonceCreator s_nonceCreator = new GuidNonceCreator();
		private static readonly ISystemTime s_systemTime = new StandardSystemTime();
		private static readonly byte[] s_unencodedPunctuation = Encoding.UTF8.GetBytes(new[] { '-', '.', '_', '~' });
	}
}
