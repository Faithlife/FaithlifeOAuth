using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Faithlife.Utility;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Utility code for OAuth authentication.
	/// </summary>
	public static partial class OAuthUtility
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
				{ OAuthConstants.Version, OAuthConstants.OAuthVersion }
			}.Union(additionalParameters).ToDictionary(x => x.Key, x => x.Value);

			return OAuthConstants.HeaderPrefix + " " + parameters
				.Where(parameter => parameter.Value is object)
				.Select(p => "{0}=\"{1}\"".FormatInvariant(p.Key, PercentEncode(p.Value)))
				.Join(",");
		}

		internal static IEnumerable<KeyValuePair<string, string>> GetQueryParameters(string query)
		{
			if (query is null || query.Length < 2 || query[0] != '?')
				return new KeyValuePair<string, string>[0];

			return query.Substring(1)
				.Split('&')
				.Select(str => str.Split(new[] { '=' }, 2))
				.Select(x => new KeyValuePair<string, string>(UrlEncoding.Decode(x[0], UrlEncodingSettings.HttpUtilitySettings), x.Length == 1 ? "" : UrlEncoding.Decode(x[1], UrlEncodingSettings.HttpUtilitySettings)));
		}

		private static bool IsUnreserved(byte value) =>
			(value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || s_unencodedPunctuation.Contains(value);

		private static KeyValuePair<string, string> NewKeyValuePair(string key, string value) => new KeyValuePair<string, string>(key, value);
		
		public static bool IsNullOrEmpty(this string? str) => string.IsNullOrEmpty(str);
		public static bool IsNullOrWhiteSpace(this string? str) => string.IsNullOrWhiteSpace(str);

		static readonly INonceCreator s_nonceCreator = new GuidNonceCreator();
		static readonly ISystemTime s_systemTime = new StandardSystemTime();
		static readonly byte[] s_unencodedPunctuation = Encoding.UTF8.GetBytes(new[] { '-', '.', '_', '~' });
	}
}
