using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using Faithlife.Utility;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Utility methods for dealing with an OAuthContext.
	/// </summary>
	public static class OAuthContextUtility
	{
		/// <summary>
		/// Tries to set the request token and token secret values from the specified HTTP response.
		/// </summary>
		/// <param name="context">The OAuth context.</param>
		/// <param name="httpResponseStream">The HTTP response stream.</param>
		public static bool TrySetUnauthorizedRequestValues(OAuthContext context, Stream httpResponseStream)
		{
			return TrySetTokenAndSecret(httpResponseStream, context.SetRequestTokenAndSecret);
		}

		/// <summary>
		/// Tries to set the access token and token secret values from the specified HTTP response.
		/// </summary>
		/// <param name="context">The OAuth context.</param>
		/// <param name="httpResponseStream">The HTTP response stream.</param>
		public static bool TrySetAccessTokenValues(OAuthContext context, Stream httpResponseStream)
		{
			return TrySetTokenAndSecret(httpResponseStream, (token, secret) => context.SetAccessTokenAndSecret(token, secret));
		}

		/// <summary>
		/// Tries to get the acess token request header parameters.
		/// </summary>
		/// <param name="context">The context.</param>
		/// <param name="uri">The URI.</param>
		/// <param name="headerParameters">The header parameters.</param>
		public static bool TryGetAcessTokenRequestHeaderParameters(OAuthContext context, Uri uri, out string[] headerParameters)
		{
			if (context == null)
				throw new ArgumentNullException("context");
			if (uri == null)
				throw new ArgumentNullException("uri");

			headerParameters = null;

			if (!context.HasRequestToken)
				return false;

			ReadOnlyDictionary<string, string> parameters = GetParameters(uri.Query);

			if (!parameters.ContainsKey(OAuthConstants.Verifier))
				return false;

			headerParameters = new[]
			{
				OAuthConstants.Token, context.RequestToken,
				OAuthConstants.Verifier, parameters[OAuthConstants.Verifier]
			};

			return true;
		}

		/// <summary>
		/// Creates a dictionary from the specified HTTP response body content.
		/// </summary>
		public static ReadOnlyDictionary<string, string> GetParameters(string responseContent)
		{
			if (string.IsNullOrEmpty(responseContent))
				return new Dictionary<string, string>().AsReadOnly();

			return responseContent
				.Split('&')
				.Select(str => str.Split('='))
				.ToDictionary(kvp => kvp[0], kvp => kvp[1])
				.AsReadOnly();
		}

		private static bool TrySetTokenAndSecret(Stream httpResponseStream, Action<string, string> setTokenAndSecret)
		{
			bool success = false;

			using (StreamReader streamReader = new StreamReader(httpResponseStream))
			{
				string responseString = streamReader.ReadToEnd();
				ReadOnlyDictionary<string, string> parameters = GetParameters(responseString);

				string token = parameters.GetValueOrDefault(OAuthConstants.Token);
				string secret = parameters.GetValueOrDefault(OAuthConstants.TokenSecret);

				if (!string.IsNullOrEmpty(token) && !string.IsNullOrEmpty(secret))
				{
					setTokenAndSecret(token, secret);
					success = true;
				}

				return success;
			}
		}
	}
}
