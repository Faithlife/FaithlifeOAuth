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
			return CreateAuthorizationHeaderValue(consumerToken, signature, new Dictionary<string, string>(0));
		}

		/// <summary>
		/// Create OAuth authentication header with callback attribute.
		/// </summary>
		public static string CreateAuthorizationHeaderValue(string consumerToken, string consumerSecret, string callback)
		{
			var signature = CreatePlainTextSignature(consumerSecret, null);
			return CreateAuthorizationHeaderValue(consumerToken, signature, new Dictionary<string, string> { { OAuthConstants.Callback, callback } });
		}

		/// <summary>
		/// Create OAuth authentication header with temporary token, secret, and verifier.
		/// </summary>
		public static string CreateAuthorizationHeaderValue(string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier)
		{
			var signature = CreatePlainTextSignature(consumerSecret, temporarySecret);
			return CreateAuthorizationHeaderValue(consumerToken, signature, new Dictionary<string, string> { { OAuthConstants.Token, temporaryToken }, { OAuthConstants.Verifier, verifier } });
		}

		/// <summary>
		/// Create OAuth authentication header with access token and secret.
		/// </summary>
		public static string CreateAuthorizationHeaderValue(string consumerToken, string consumerSecret, string accessToken, string accessSecret)
		{
			var signature = CreatePlainTextSignature(consumerSecret, accessSecret);
			return CreateAuthorizationHeaderValue(consumerToken, signature, new Dictionary<string, string> { { OAuthConstants.Token, accessToken } });
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA256 signature method.
		/// </summary>
		public static Uri CreateHmacSha256Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string? callback = null)
		{
			List<KeyValuePair<string, string>>? additionalParameters = null;
			if (callback != null)
				additionalParameters = new List<KeyValuePair<string, string>>() { NewKeyValuePair(OAuthConstants.Callback, callback) };
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha256Parameters(consumerToken, s_nonceCreator, s_systemTime, additionalParameters), out var newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha256Signature(signatureBase, consumerSecret, null)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA256 signature method.
		/// </summary>
		public static Uri CreateHmacSha256Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string? verifier = null)
		{
			var additionalParameters = new List<KeyValuePair<string, string>> { NewKeyValuePair(OAuthConstants.Token, accessToken) };
			if (verifier != null)
				additionalParameters.Add(NewKeyValuePair(OAuthConstants.Verifier, verifier));
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha256Parameters(consumerToken, s_nonceCreator, s_systemTime, additionalParameters), out var newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha256Signature(signatureBase, consumerSecret, accessSecret)));
		}

		/// <summary>
		/// Create OAuth signature using the HMACSHA256 signature method.
		/// </summary>
		public static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>>? formParameters = null) =>
			CreateHmacSha256Signature(uri, httpMethod, consumerSecret, null, GetHmacSha256Parameters(consumerToken, nonce, timeStamp, formParameters));

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA256 signature method. Accepts arbitrary number of form parameters.
		/// </summary>
		public static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null, string? temporaryToken = null, string? temporarySecret = null, IEnumerable<KeyValuePair<string, string>>? formParameters = null)
		{
			var additionalParameters = formParameters.EmptyIfNull().ToList();
			if (temporaryToken != null)
				additionalParameters.Add(NewKeyValuePair(OAuthConstants.Token, temporaryToken));
			return CreateHmacSha256AuthorizationHeaderValue(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha256Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, additionalParameters));
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
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha1Parameters(consumerToken, s_nonceCreator, s_systemTime, new Dictionary<string, string> { { OAuthConstants.Callback, callback } }), out var newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha1Signature(signatureBase, consumerSecret, null)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA1 signature method.
		/// </summary>
		public static Uri CreateHmacSha1Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier)
		{
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha1Parameters(consumerToken, s_nonceCreator, s_systemTime, new Dictionary<string, string> { { OAuthConstants.Token, temporaryToken }, { OAuthConstants.Verifier, verifier } }), out var newUri);
			return new Uri("{0}&{1}={2}".FormatInvariant(newUri, OAuthConstants.Signature, CreateHmacSha1Signature(signatureBase, consumerSecret, temporarySecret)));
		}

		/// <summary>
		/// Create uri to use with an OAuth authentication header created using the HMACSHA1 signature method.
		/// </summary>
		public static Uri CreateHmacSha1Uri(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret)
		{
			var signatureBase = CreateSignatureBase(uri, httpMethod, GetHmacSha1Parameters(consumerToken, s_nonceCreator, s_systemTime, new Dictionary<string, string> { { OAuthConstants.Token, accessToken } }), out var newUri);
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
			CreateHmacSha1Signature(uri, httpMethod, consumerSecret, null, GetHmacSha1Parameters(consumerToken, nonce, timeStamp, new Dictionary<string, string> { { OAuthConstants.Callback, callback } }));

		/// <summary>
		/// Create OAuth signature using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string nonce, string timeStamp) =>
			CreateHmacSha1Signature(uri, httpMethod, consumerSecret, accessSecret, GetHmacSha1Parameters(consumerToken, nonce, timeStamp, new Dictionary<string, string> { { OAuthConstants.Token, accessToken } }));

		/// <summary>
		/// Create OAuth signature using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1Signature(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, string nonce, string timeStamp) =>
			CreateHmacSha1Signature(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha1Parameters(consumerToken, nonce, timeStamp, new Dictionary<string, string> { { OAuthConstants.Token, temporaryToken }, { OAuthConstants.Verifier, verifier } }));


		/// <summary>
		/// Create OAuth authentication header using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null) =>
			CreateHmacSha1AuthorizationHeaderValue(uri, httpMethod, consumerSecret, null, GetHmacSha1Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime));

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string callback, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null) =>
			CreateHmacSha1AuthorizationHeaderValue(uri, httpMethod, consumerSecret, null, GetHmacSha1Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new Dictionary<string, string> { { OAuthConstants.Callback, callback } }));

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null) =>
			CreateHmacSha1AuthorizationHeaderValue(uri, httpMethod, consumerSecret, temporarySecret, GetHmacSha1Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new Dictionary<string, string> { { OAuthConstants.Token, temporaryToken }, { OAuthConstants.Verifier, verifier } }));

		/// <summary>
		/// Create OAuth authentication header using the HMACSHA1 signature method.
		/// </summary>
		public static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, INonceCreator? nonceCreator = null, ISystemTime? systemTime = null) =>
			CreateHmacSha1AuthorizationHeaderValue(uri, httpMethod, consumerSecret, accessSecret, GetHmacSha1Parameters(consumerToken, nonceCreator ?? s_nonceCreator, systemTime ?? s_systemTime, new Dictionary<string, string> { { OAuthConstants.Token, accessToken } }));

		private static string CreateHmacSha1Signature(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters) =>
			CreateHmacSha1Signature(CreateSignatureBase(uri, httpMethod, parameters, out _), consumerSecret, tokenSecret);

		private static string CreateHmacSha256Signature(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters) =>
			CreateHmacSha256Signature(CreateSignatureBase(uri, httpMethod, parameters, out string _), consumerSecret, tokenSecret);

		internal static string CreateHmacSha1Signature(string signatureBase, string consumerSecret, string? tokenSecret)
		{
			using var hmacsha1 = new HMACSHA1(Encoding.UTF8.GetBytes(CreatePlainTextSignature(consumerSecret, tokenSecret)));
			return Convert.ToBase64String(hmacsha1.ComputeHash(Encoding.UTF8.GetBytes(signatureBase)));
		}

		internal static string CreateHmacSha256Signature(string signatureBase, string consumerSecret, string? tokenSecret)
		{
			using var hmacsha256 = new HMACSHA256(Encoding.UTF8.GetBytes(CreatePlainTextSignature(consumerSecret, tokenSecret)));
			return Convert.ToBase64String(hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(signatureBase)));
		}

		private static string CreateHmacSha256AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters) =>
			CreateHmacShaAuthorizationHeaderValue(uri, httpMethod, consumerSecret, tokenSecret, parameters, CreateHmacSha256Signature(CreateSignatureBase(uri, httpMethod, parameters, out var newUIUri), consumerSecret, tokenSecret));

		private static string CreateHmacSha1AuthorizationHeaderValue(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters) =>
			CreateHmacShaAuthorizationHeaderValue(uri, httpMethod, consumerSecret, tokenSecret, parameters, CreateHmacSha1Signature(CreateSignatureBase(uri, httpMethod, parameters, out var newUIUri), consumerSecret, tokenSecret));

		private static string CreateHmacShaAuthorizationHeaderValue(Uri uri, string httpMethod, string consumerSecret, string? tokenSecret, ICollection<KeyValuePair<string, string>> parameters, string signatureMethod)
		{
			string signatureBase = CreateSignatureBase(uri, httpMethod, parameters, out var newUri);

			parameters.Add(new KeyValuePair<string, string>(OAuthConstants.Signature, signatureMethod));

			return OAuthConstants.HeaderPrefix + " " + parameters
				.Where(parameter => parameter.Key.StartsWithOrdinal(OAuthConstants.ParameterPrefix) && parameter.Value != null)
				.Select(p => "{0}=\"{1}\"".FormatInvariant(p.Key, PercentEncode(p.Value)))
				.Join(",");
		}

		public static ICollection<KeyValuePair<string, string>> GetHmacSha1Parameters(string consumerToken, INonceCreator nonceCreator, ISystemTime systemTime, Dictionary<string, string>? additionalParameters = null) =>
			GetHmacShaParameters(consumerToken, nonceCreator.CreateNonce(), DateTimeUtility.ToUnixTimestamp(systemTime.GetUtcNow()).ToInvariantString(), additionalParameters, OAuthSignatureMethods.HmacSha1);

		public static ICollection<KeyValuePair<string, string>> GetHmacSha1Parameters(string consumerToken, string nonce, string timeStamp, Dictionary<string, string>? additionalParameters = null) =>
			GetHmacShaParameters(consumerToken, nonce, timeStamp, additionalParameters, OAuthSignatureMethods.HmacSha1);

		public static ICollection<KeyValuePair<string, string>> GetHmacSha256Parameters(string consumerToken, INonceCreator nonceCreator, ISystemTime systemTime, IEnumerable<KeyValuePair<string, string>>? additionalParameters = null) =>
			GetHmacShaParameters(consumerToken, nonceCreator.CreateNonce(), DateTimeUtility.ToUnixTimestamp(systemTime.GetUtcNow()).ToInvariantString(), additionalParameters, OAuthSignatureMethods.HmacSha256);

		public static ICollection<KeyValuePair<string, string>> GetHmacSha256Parameters(string consumerToken, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>>? additionalParameters = null) =>
			GetHmacShaParameters(consumerToken, nonce, timeStamp, additionalParameters, OAuthSignatureMethods.HmacSha256);

		private static ICollection<KeyValuePair<string, string>> GetHmacShaParameters(string consumerToken, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>>? additionalParameters = null, string? signatureMethod = null) =>
			new List<KeyValuePair<string, string>>
			{
				NewKeyValuePair(OAuthConstants.ConsumerKey, consumerToken),
				NewKeyValuePair(OAuthConstants.Nonce, nonce),
				NewKeyValuePair(OAuthConstants.SignatureMethod, signatureMethod ?? OAuthSignatureMethods.HmacSha256),
				NewKeyValuePair(OAuthConstants.TimeStamp, timeStamp),
				NewKeyValuePair(OAuthConstants.Version, OAuthConstants.OAuthVersion),
			}.Union(additionalParameters.EmptyIfNull().Where(kvp => kvp.Value != null)).ToList();

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

		private static string CreateAuthorizationHeaderValue(string consumerToken, string signature, Dictionary<string, string> additionalParameters)
		{
			if (additionalParameters is null)
				throw new ArgumentNullException(nameof(additionalParameters));

			var parameters = new Dictionary<string, string>
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

		private static bool IsUnreserved(byte value) =>
			(value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || s_unencodedPunctuation.Contains(value);

		private static KeyValuePair<string, string> NewKeyValuePair(string key, string value) => new KeyValuePair<string, string>(key, value);
		public static IEnumerable<T> EmptyIfNull<T>(this IEnumerable<T>? seq) => seq ?? Enumerable.Empty<T>();
		public static bool IsNullOrWhiteSpace(this string? str) => string.IsNullOrWhiteSpace(str);
		public static bool IsNullOrEmpty(this string? str) => string.IsNullOrEmpty(str);

		static readonly INonceCreator s_nonceCreator = new GuidNonceCreator();
		static readonly ISystemTime s_systemTime = new StandardSystemTime();
		static readonly byte[] s_unencodedPunctuation = Encoding.UTF8.GetBytes(new[] { '-', '.', '_', '~' });
	}
}
