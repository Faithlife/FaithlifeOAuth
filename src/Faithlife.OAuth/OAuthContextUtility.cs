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
		public static bool TrySetUnauthorizedRequestValues(OAuthContext context, Stream httpResponseStream) =>
			TrySetTokenAndSecret(httpResponseStream, context.SetRequestTokenAndSecret);

		/// <summary>
		/// Tries to set the access token and token secret values from the specified HTTP response.
		/// </summary>
		/// <param name="context">The OAuth context.</param>
		/// <param name="httpResponseStream">The HTTP response stream.</param>
		public static bool TrySetAccessTokenValues(OAuthContext context, Stream httpResponseStream) =>
			TrySetTokenAndSecret(httpResponseStream, (token, secret) => context.SetAccessTokenAndSecret(token, secret));

		/// <summary>
		/// Tries to get the acess token request header parameters.
		/// </summary>
		/// <param name="context">The context.</param>
		/// <param name="uri">The URI.</param>
		/// <param name="headerParameters">The header parameters.</param>
		public static bool TryGetAcessTokenRequestHeaderParameters(OAuthContext context, Uri uri, out string[]? headerParameters)
		{
			if (context is null)
				throw new ArgumentNullException(nameof(context));
			if (uri is null)
				throw new ArgumentNullException(nameof(uri));

			headerParameters = null;

			if (!context.HasRequestToken)
				return false;

			var parameters = GetParameters(uri.Query);

			if (!parameters.ContainsKey(OAuthConstants.Verifier))
				return false;

			headerParameters = new string[]
			{
				OAuthConstants.Token, context.RequestToken!,
				OAuthConstants.Verifier, parameters[OAuthConstants.Verifier],
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
			var success = false;

			using var streamReader = new StreamReader(httpResponseStream);
			var responseString = streamReader.ReadToEnd();
			var parameters = GetParameters(responseString);

			var token = parameters.GetValueOrDefault(OAuthConstants.Token);
			var secret = parameters.GetValueOrDefault(OAuthConstants.TokenSecret);

			if (!string.IsNullOrEmpty(token) && !string.IsNullOrEmpty(secret))
			{
				setTokenAndSecret(token, secret);
				success = true;
			}

			return success;
		}
	}
}
