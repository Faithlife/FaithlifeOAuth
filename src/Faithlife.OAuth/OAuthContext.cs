using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Faithlife.Utility;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Provides methods for obtaining access tokens and making authorized requests.
	/// </summary>
	public class OAuthContext
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="OAuthContext"/> class.
		/// </summary>
		/// <param name="oauthEndpoint">The OAuth endpoint.</param>
		/// <param name="requestTokenHttpMethod">The http request method for getting the request token.</param>
		/// <param name="requestAccessTokenHttpMethod">The http request method for getting the access token.</param>
		/// <param name="consumerKey">The consumer key.</param>
		/// <param name="consumerSecret">The consumer secret.</param>
		/// <param name="signatureMethod">The signature method.</param>
		public OAuthContext(string oauthEndpoint, string requestTokenHttpMethod, string requestAccessTokenHttpMethod, string consumerKey, string consumerSecret, string signatureMethod)
		{
			if (signatureMethod != OAuthSignatureMethods.HmacSha1)
				throw new NotSupportedException("Only HMAC-SHA1 is supported at this time");

			OAuthEndpoint = oauthEndpoint;
			RequestTokenHttpMethod = requestTokenHttpMethod;
			RequestAccessTokenHttpMethod = requestAccessTokenHttpMethod;
			m_consumerKey = consumerKey;
			m_consumerSecret = consumerSecret;
			m_signatureMethod = signatureMethod;
		}

		/// <summary>
		/// Gets the encoding settings.
		/// </summary>
		public static UrlEncodingSettings EncodingSettings { get; } = new UrlEncodingSettings
		{
			ShouldEncodeChar = ch =>
				!(ch >= '0' && ch <= '9') &&
				!(ch >= 'A' && ch <= 'Z') &&
				!(ch >= 'a' && ch <= 'z') &&
				!(ch == '-' || ch == '_' || ch == '.' || ch == '~'),
			EncodedBytePrefixChar = '%',
			UppercaseHexDigits = true,
			TextEncoding = Encoding.UTF8,
			PreventDoubleEncoding = true,
		};

		/// <summary>
		/// Gets the OAuth endpoint.
		/// </summary>
		public string OAuthEndpoint { get; }

		/// <summary>
		/// Gets the request token HTTP method.
		/// </summary>
		public string RequestTokenHttpMethod { get; }

		/// <summary>
		/// Gets the request access token HTTP method.
		/// </summary>
		public string RequestAccessTokenHttpMethod { get; }

		/// <summary>
		/// Gets the access token.
		/// </summary>
		public string? AccessToken { get; private set; }

		/// <summary>
		/// Gets the request token.
		/// </summary>
		public string? RequestToken { get; private set; }

		/// <summary>
		/// Gets the access token secret.
		/// </summary>
		public string? AccessTokenSecret { get; private set; }

		/// <summary>
		/// Gets a value indicating if authorization has already occurred.
		/// </summary>
		public bool IsAuthorized => !string.IsNullOrEmpty(AccessToken) && AccessTokenSecret is object;

		/// <summary>
		/// Returns a value indicating if request token is present.
		/// </summary>
		public bool HasRequestToken => !string.IsNullOrEmpty(RequestToken) && !string.IsNullOrEmpty(RequestTokenSecret);

		/// <summary>
		/// Gets a uri for authorizing the user.
		/// </summary>
		public Uri GetUriForAuthorization()
		{
			if (HasRequestToken)
				return new Uri("{0}/{1}?{2}={3}".FormatInvariant(OAuthEndpoint, OAuthConstants.AuthorizeRelativeUrl, Encode(OAuthConstants.Token), Encode(RequestToken)));

			return new Uri(OAuthEndpoint);
		}

		/// <summary>
		/// Sets the request token and secret.
		/// </summary>
		/// <param name="requestToken">The request token.</param>
		/// <param name="requestTokenSecret">The token secret.</param>
		public void SetRequestTokenAndSecret(string? requestToken, string? requestTokenSecret)
		{
			RequestToken = requestToken;
			RequestTokenSecret = requestTokenSecret;
		}

		/// <summary>
		/// Sets access credentials.
		/// </summary>
		/// <param name="accessToken">The access token.</param>
		/// <param name="accessSecret">The access secret.</param>
		public void SetAccessTokenAndSecret(string? accessToken, string? accessSecret)
		{
			AccessToken = accessToken;
			AccessTokenSecret = accessSecret;
		}

		/// <summary>
		/// Clears all saved credentials.
		/// </summary>
		public void ClearCredentials()
		{
			RequestToken = null;
			RequestTokenSecret = null;
			AccessToken = null;
			AccessTokenSecret = null;

			ClearAccessCredentialsCore();
		}

		/// <summary>
		/// Gets the OAuth authorization header.
		/// </summary>
		/// <param name="requestMethod">The HTTP request method.</param>
		/// <param name="url">The request URL.</param>
		/// <param name="authorizedRequest">if set to <c>true</c> the request is authorized.</param>
		/// <param name="parameters">Optional header parameters.</param>
		public WebHeaderCollection GetAuthorizationHeader(string requestMethod, string url, bool authorizedRequest, params string[] parameters) =>
			GetAuthorizationHeader(requestMethod, new Uri(url), authorizedRequest, parameters);

		/// <summary>
		/// Gets the OAuth authorization header.
		/// </summary>
		/// <param name="requestMethod">The HTTP request method.</param>
		/// <param name="uri">The request URL.</param>
		/// <param name="authorizedRequest">if set to <c>true</c> the request is authorized.</param>
		/// <param name="parameters">Optional header parameters.</param>
		public WebHeaderCollection GetAuthorizationHeader(string requestMethod, Uri uri, bool authorizedRequest, params string[] parameters)
		{
			var stringCount = parameters.Length;
			if (stringCount % 2 == 1)
				throw new ArgumentException("The number of strings must be even.");

			var additionalParameters = new List<Parameter>();
			if (authorizedRequest)
				additionalParameters.Add(new Parameter(OAuthConstants.Token, AccessToken) { IsEncoded = true });

			for (var stringIndex = 0; stringIndex < stringCount; stringIndex += 2)
				additionalParameters.Add(new Parameter(parameters[stringIndex], parameters[stringIndex + 1]) { IsEncoded = true });

			var headerParameters = GetDefaultParametersForSignature().Concat(additionalParameters).ToList();

			// create signature
			var signature = CreateSignature(requestMethod, uri, authorizedRequest, SortParameters(headerParameters.Concat(GetQueryStringParameters(uri.Query))));
			headerParameters.Add(new Parameter(OAuthConstants.Signature, signature));

			// then add signature to header parameters
			var headerStringValue = SortParameters(headerParameters)
				.Select(p => "{0}=\"{1}\"".FormatInvariant(Encode(p.Key), Encode(p.Value, !p.IsEncoded)))
				.Join(",");

			return new WebHeaderCollection
			{
				[HttpRequestHeader.Authorization] = "{0} {1}".FormatInvariant(OAuthConstants.HeaderPrefix, headerStringValue)
			};
		}

		/// <summary>
		/// Creates a dictionary from a string.
		/// </summary>
		/// <param name="valuesString">The string.</param>
		/// <returns>The dictionary.</returns>
		protected static Dictionary<string, string> GetValues(string valuesString) =>
			valuesString.Split('&').Select(str => str.Split('=')).ToDictionary(kvp => kvp[0], kvp => kvp[1]);

		/// <summary>
		/// Allows derived classes to remove any extra credentials.
		/// </summary>
		protected virtual void ClearAccessCredentialsCore()
		{
		}

		private string? RequestTokenSecret { get; set; }

		private string CreateSignature(string requestMethod, Uri uri, bool authorizedRequest, IEnumerable<Parameter> parameters)
		{
			if (m_signatureMethod != OAuthSignatureMethods.HmacSha1)
				return "";

			var key = Encoding.UTF8.GetBytes(GetNormalizedKeyString(authorizedRequest));
			using var hashAlgorithm = new HMACSHA1(key);
			var dataBytes = Encoding.UTF8.GetBytes(CreateSignatureBase(requestMethod, uri, parameters));
			var hashBytes = hashAlgorithm.ComputeHash(dataBytes);

			return Convert.ToBase64String(hashBytes);
		}

		private static string CreateSignatureBase(string requestMethod, Uri uri, IEnumerable<Parameter> parameters)
		{
			var builder = new StringBuilder();
			builder.AppendFormat("{0}&", requestMethod.ToUpperInvariant());
			builder.AppendFormat("{0}&", GetNormalizedUrl(uri));
			builder.Append(GetNormalizedParameters(parameters));

			return builder.ToString();
		}

		private IEnumerable<Parameter> GetDefaultParametersForSignature() => new List<Parameter>
			{
				new Parameter(OAuthConstants.ConsumerKey, m_consumerKey),
				new Parameter(OAuthConstants.Nonce, Guid.NewGuid().ToString()),
				new Parameter(OAuthConstants.TimeStamp, GetTimestamp().ToInvariantString()),
				new Parameter(OAuthConstants.Version, OAuthConstants.OAuthVersion),
				new Parameter(OAuthConstants.SignatureMethod, m_signatureMethod),
			};

		private ReadOnlyCollection<Parameter> SortParameters(IEnumerable<Parameter> parameters) =>
			parameters
				.OrderBy(p => p.Key)
				.ThenBy(p => p.Value)
				.ToList().AsReadOnly();

		private string GetNormalizedKeyString(bool authorizedRequest) =>
			"{0}&{1}".FormatInvariant(Encode(m_consumerSecret), authorizedRequest ? AccessTokenSecret : RequestTokenSecret);

		private static string GetNormalizedUrl(Uri uri)
		{
			var normalizedUriBuilder = new StringBuilder();
			normalizedUriBuilder.Append(uri.Scheme);
			normalizedUriBuilder.Append("://");
			normalizedUriBuilder.Append(uri.Authority.ToLowerInvariant());
			normalizedUriBuilder.Append(uri.AbsolutePath);

			return Encode(normalizedUriBuilder.ToString())!; // TODO: Update Faithlife.Utility
		}

		private static string GetNormalizedParameters(IEnumerable<Parameter> parameters) =>
			Encode(parameters.Select(p => "{0}={1}".FormatInvariant(p.Key, p.Value)).Join("&"))!; // TODO: Update Faithlife.Utility

		/// <summary>
		/// Gets the time elapsed since 1/1/1970 in seconds.
		/// </summary>
		private static long GetTimestamp() => DateTimeUtility.ToUnixTimestamp(DateTime.UtcNow);

		private static string? Encode(string? str) => Encode(str, true);

		private static string? Encode(string? str, bool encode) =>
			encode ? UrlEncoding.Encode(str, EncodingSettings) : str;

		private static ReadOnlyCollection<Parameter> GetQueryStringParameters(string query)
		{
			if (string.IsNullOrEmpty(query) || !query.StartsWith("?", StringComparison.OrdinalIgnoreCase))
				return new List<Parameter>().AsReadOnly();

			return GetValues(query.Substring(1)).Select(x => new Parameter(x.Key, x.Value))
				.ToList().AsReadOnly();
		}

		private class Parameter
		{
			public Parameter(string key, string? value)
			{
				Key = key;
				Value = value;
			}

			public string Key { get; }

			public string? Value { get; }

			public bool IsEncoded { get; set; }
		}

		readonly string m_consumerKey;
		readonly string m_consumerSecret;
		readonly string m_signatureMethod;
	}
}
