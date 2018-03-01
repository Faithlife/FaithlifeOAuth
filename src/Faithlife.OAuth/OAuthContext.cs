using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Security;
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

			m_oauthEndpoint = oauthEndpoint;
			m_requestTokenHttpMethod = requestTokenHttpMethod;
			m_requestAccessTokenHttpMethod = requestAccessTokenHttpMethod;
			m_consumerKey = consumerKey;
			m_consumerSecret = consumerSecret;
			m_signatureMethod = signatureMethod;
		}

		/// <summary>
		/// Gets the encoding settings.
		/// </summary>
		public static UrlEncodingSettings EncodingSettings
		{
			get { return s_encodingSettings; }
		}

		/// <summary>
		/// Gets the OAuth endpoint.
		/// </summary>
		public string OAuthEndpoint
		{
			get { return m_oauthEndpoint; }
		}

		/// <summary>
		/// Gets the request token HTTP method.
		/// </summary>
		public string RequestTokenHttpMethod
		{
			get { return m_requestTokenHttpMethod; }
		}

		/// <summary>
		/// Gets the request access token HTTP method.
		/// </summary>
		public string RequestAccessTokenHttpMethod
		{
			get { return m_requestAccessTokenHttpMethod; }
		}

		/// <summary>
		/// Gets the access token.
		/// </summary>
		public string AccessToken
		{
			get { return m_accessToken; }
		}

		/// <summary>
		/// Gets the request token.
		/// </summary>
		public string RequestToken
		{
			get { return m_requestToken; }
		}

		/// <summary>
		/// Gets the access token secret.
		/// </summary>
		public string AccessTokenSecret
		{
			get { return m_accessTokenSecret; }
		}

		/// <summary>
		/// Gets a value indicating if authorization has already occurred.
		/// </summary>
		public bool IsAuthorized
		{
			get
			{
				return !string.IsNullOrEmpty(m_accessToken) && m_accessTokenSecret != null;
			}
		}

		/// <summary>
		/// Returns a value indicating if request token is present.
		/// </summary>
		public bool HasRequestToken
		{
			get
			{
				return !string.IsNullOrEmpty(m_requestToken) && !string.IsNullOrEmpty(m_requestTokenSecret);
			}
		}

		/// <summary>
		/// Gets a uri for authorizing the user.
		/// </summary>
		public Uri GetUriForAuthorization()
		{
			if (HasRequestToken)
				return new Uri("{0}/{1}?{2}={3}".FormatInvariant(m_oauthEndpoint, OAuthConstants.AuthorizeRelativeUrl, Encode(OAuthConstants.Token), Encode(m_requestToken)));

			return new Uri(m_oauthEndpoint);
		}

		/// <summary>
		/// Sets the request token and secret.
		/// </summary>
		/// <param name="requestToken">The request token.</param>
		/// <param name="requestTokenSecret">The token secret.</param>
		public void SetRequestTokenAndSecret(string requestToken, string requestTokenSecret)
		{
			m_requestToken = requestToken;
			m_requestTokenSecret = requestTokenSecret;
		}

		/// <summary>
		/// Sets access credentials.
		/// </summary>
		/// <param name="accessToken">The access token.</param>
		/// <param name="accessSecret">The access secret.</param>
		public void SetAccessTokenAndSecret(string accessToken, string accessSecret)
		{
			m_accessToken = accessToken;
			m_accessTokenSecret = accessSecret;
		}

		/// <summary>
		/// Clears all saved credentials.
		/// </summary>
		public void ClearCredentials()
		{
			m_requestToken = null;
			m_requestTokenSecret = null;
			m_accessToken = null;
			m_accessTokenSecret = null;

			ClearAccessCredentialsCore();
		}

		/// <summary>
		/// Gets the OAuth authorization header.
		/// </summary>
		/// <param name="requestMethod">The HTTP request method.</param>
		/// <param name="url">The request URL.</param>
		/// <param name="authorizedRequest">if set to <c>true</c> the request is authorized.</param>
		/// <param name="parameters">Optional header parameters.</param>
		public WebHeaderCollection GetAuthorizationHeader(string requestMethod, string url, bool authorizedRequest, params string[] parameters)
		{
			return GetAuthorizationHeader(requestMethod, new Uri(url), authorizedRequest, parameters);
		}

		/// <summary>
		/// Gets the OAuth authorization header.
		/// </summary>
		/// <param name="requestMethod">The HTTP request method.</param>
		/// <param name="uri">The request URL.</param>
		/// <param name="authorizedRequest">if set to <c>true</c> the request is authorized.</param>
		/// <param name="parameters">Optional header parameters.</param>
		public WebHeaderCollection GetAuthorizationHeader(string requestMethod, Uri uri, bool authorizedRequest, params string[] parameters)
		{
			int stringCount = parameters.Length;
			if (stringCount % 2 == 1)
				throw new ArgumentException("The number of strings must be even.");

			List<Parameter> additionalParameters = new List<Parameter>();
			if (authorizedRequest)
				additionalParameters.Add(new Parameter(OAuthConstants.Token, m_accessToken) { IsEncoded = true });

			for (int stringIndex = 0; stringIndex < stringCount; stringIndex += 2)
				additionalParameters.Add(new Parameter(parameters[stringIndex], parameters[stringIndex + 1]) { IsEncoded = true });

			List<Parameter> headerParameters = GetDefaultParametersForSignature()
				.Concat(additionalParameters)
				.ToList();

			// create signature
			string signature = CreateSignature(requestMethod, uri, authorizedRequest, SortParameters(headerParameters.Concat(GetQueryStringParameters(uri.Query))));
			headerParameters.Add(new Parameter(OAuthConstants.Signature, signature));

			// then add signature to header parameters
			string headerStringValue = SortParameters(headerParameters)
				.Select(p => "{0}=\"{1}\"".FormatInvariant(Encode(p.Key), Encode(p.Value, !p.IsEncoded)))
				.Join(",");

			WebHeaderCollection headers = new WebHeaderCollection();
			headers[HttpRequestHeader.Authorization] = "{0} {1}".FormatInvariant(OAuthConstants.HeaderPrefix, headerStringValue);
			return headers;
		}

		/// <summary>
		/// Creates a dictionary from a string.
		/// </summary>
		/// <param name="valuesString">The string.</param>
		/// <returns>The dictionary.</returns>
		protected static Dictionary<string, string> GetValues(string valuesString)
		{
			return valuesString.Split('&').Select(str => str.Split('=')).ToDictionary(kvp => kvp[0], kvp => kvp[1]);
		}

		/// <summary>
		/// Allows derived classes to remove any extra credentials.
		/// </summary>
		protected virtual void ClearAccessCredentialsCore()
		{
		}

		private string CreateSignature(string requestMethod, Uri uri, bool authorizedRequest, IEnumerable<Parameter> parameters)
		{
			if (m_signatureMethod != OAuthSignatureMethods.HmacSha1)
				return string.Empty;

			byte[] key = Encoding.UTF8.GetBytes(GetNormalizedKeyString(authorizedRequest));
			using (HMACSHA1 hashAlgorithm = new HMACSHA1(key))
			{
				byte[] dataBytes = Encoding.UTF8.GetBytes(CreateSignatureBase(requestMethod, uri, parameters));
				byte[] hashBytes = hashAlgorithm.ComputeHash(dataBytes);

				return Convert.ToBase64String(hashBytes);
			}
		}

		private static string CreateSignatureBase(string requestMethod, Uri uri, IEnumerable<Parameter> parameters)
		{
			StringBuilder builder = new StringBuilder();
			builder.AppendFormat("{0}&", requestMethod.ToUpperInvariant());
			builder.AppendFormat("{0}&", GetNormalizedUrl(uri));
			builder.Append(GetNormalizedParameters(parameters));

			return builder.ToString();
		}

		private IEnumerable<Parameter> GetDefaultParametersForSignature()
		{
			return new List<Parameter>
			{
				new Parameter(OAuthConstants.ConsumerKey, m_consumerKey),
				new Parameter(OAuthConstants.Nonce, Guid.NewGuid().ToString()),
				new Parameter(OAuthConstants.TimeStamp, GetTimestamp().ToInvariantString()),
				new Parameter(OAuthConstants.Version, OAuthConstants.OAuthVersion),
				new Parameter(OAuthConstants.SignatureMethod, m_signatureMethod),
			};
		}

		private ReadOnlyCollection<Parameter> SortParameters(IEnumerable<Parameter> parameters)
		{
			return parameters
				.OrderBy(p => p.Key)
				.ThenBy(p => p.Value)
				.ToList().AsReadOnly();
		}

		private string GetNormalizedKeyString(bool authorizedRequest)
		{
			return "{0}&{1}".FormatInvariant(Encode(m_consumerSecret), authorizedRequest ? m_accessTokenSecret : m_requestTokenSecret);
		}

		private static string GetNormalizedUrl(Uri uri)
		{
			StringBuilder normalizedUriBuilder = new StringBuilder();
			normalizedUriBuilder.Append(uri.Scheme);
			normalizedUriBuilder.Append("://");
			normalizedUriBuilder.Append(uri.Authority.ToLowerInvariant());
			normalizedUriBuilder.Append(uri.AbsolutePath);

			return Encode(normalizedUriBuilder.ToString());
		}

		private static string GetNormalizedParameters(IEnumerable<Parameter> parameters)
		{
			return Encode(parameters.Select(p => "{0}={1}".FormatInvariant(p.Key, p.Value)).Join("&"));
		}

		/// <summary>
		/// Gets the time elapsed since 1/1/1970 in seconds.
		/// </summary>
		private static long GetTimestamp()
		{
			return DateTimeUtility.ToUnixTimestamp(DateTime.UtcNow);
		}

		private static string Encode(string str)
		{
			return Encode(str, true);
		}

		private static string Encode(string str, bool encode)
		{
			return encode ? UrlEncoding.Encode(str, s_encodingSettings) : str;
		}

		private static ReadOnlyCollection<Parameter> GetQueryStringParameters(string query)
		{
			if (string.IsNullOrEmpty(query) || !query.StartsWith("?", StringComparison.OrdinalIgnoreCase))
				return new List<Parameter>().AsReadOnly();

			return GetValues(query.Substring(1)).Select(x => new Parameter(x.Key, x.Value))
				.ToList().AsReadOnly();
		}

		private class Parameter
		{
			public Parameter(string key, string value)
			{
				Key = key;
				Value = value;
			}

			public string Key { get; private set; }

			public string Value { get; private set; }

			public bool IsEncoded { get; set; }
		}

		static readonly UrlEncodingSettings s_encodingSettings = new UrlEncodingSettings
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

		readonly string m_oauthEndpoint;
		readonly string m_requestTokenHttpMethod;
		readonly string m_requestAccessTokenHttpMethod;

		readonly string m_consumerKey;
		readonly string m_consumerSecret;
		readonly string m_signatureMethod;
		string m_requestToken;
		string m_requestTokenSecret;
		string m_accessToken;
		string m_accessTokenSecret;
	}
}
