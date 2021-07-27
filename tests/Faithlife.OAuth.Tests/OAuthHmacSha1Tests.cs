using System;
using System.Collections.Generic;
using System.Linq;
using Faithlife.Utility;
using NUnit.Framework;

namespace Faithlife.OAuth.Tests
{
	/// <summary>
	/// Tests for OAuthUtility.
	/// </summary>
	/// <remarks>
	/// This code was copied from http://git/Logos/WebCommon/blob/master/tests/Logos.Common.Web.OAuth.UnitTests/OAuthUtilityTests.cs.
	/// </remarks>
	[TestFixture]
	public class OAuthHmacSha1Tests
	{
		[TestCase("POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7",
			"r6/TJjbCOr97/+UU0NsvSne7s5g=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "j49sk3j29djd", "dh893hdasih9",
			"oauth_consumer_key", "9djdj82h48djs9d2", "oauth_token", "kkk9d7dh3k39sjv7", "oauth_signature_method", "HMAC-SHA1", "oauth_timestamp", "137131201", "oauth_nonce", "7d8f3e4a", "c2", "", "a3", "2 q",
			Description = "RFC 5849, section 3.4.1.1, amended by errata 2550")]
		[TestCase("POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521",
			"tnnArxj06cWHq44gCs1OSKk/jLY=", "https://api.twitter.com/1/statuses/update.json?include_entities=true", "POST", "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw", "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
			"oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog", "oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "oauth_signature_method", "HMAC-SHA1", "oauth_timestamp", "1318622958", "oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", "oauth_version", "1.0", "status", "Hello Ladies + Gentlemen, a signed OAuth request!",
			Description = "From https://dev.twitter.com/docs/auth/creating-signature")]
		[TestCase("GET&http%3A%2F%2Fwww.example.net%2Fresource&Name%3Dvalue3%26Name%3Dvalue4%26name%3Dvalue1%26name%3Dvalue2%26oauth_consumer_key%3Dabcd%26oauth_nonce%3DNJoXy4OiHud%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1438360868%26oauth_token%3Dijkl%26oauth_version%3D1.0",
			"S59QRSfIG/XpgtSCdOV24n86gsg=", "http://www.example.net/resource?name=value1&name=value2&Name=value3&Name=value4", "GET", "efgh", "mnop",
			"oauth_consumer_key", "abcd", "oauth_token", "ijkl", "oauth_signature_method", "HMAC-SHA1", "oauth_timestamp", "1438360868", "oauth_nonce", "NJoXy4OiHud", "oauth_version", "1.0",
			Description = "From http://oauth.googlecode.com/svn/code/javascript/example/signature.html")]
		[TestCase("GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3DchapoH%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131202%26oauth_token%3Dnnch734d00sl2jdk%26size%3Doriginal",
			"MdpQcU8iPSUjWoN/UDMsK2sui9I=", "http://photos.example.net/photos?file=vacation.jpg&size=original", "GET", "kd94hf93k423kf44", "pfkkdhi9sl3r4s00",
			"oauth_consumer_key", "dpf43f3p2l4k3l03", "oauth_nonce", "chapoH", "oauth_signature_method", "HMAC-SHA1", "oauth_timestamp", "137131202", "oauth_token", "nnch734d00sl2jdk", Description = "RFC 5849, section 1.2")]
		public void CreateSignature(string expectedSignatureBase, string expectedSignature, string uri, string httpMethod, string consumerSecret, string tokenSecret, params string[] parameters)
		{
			string signatureBase = OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, ToPairs(parameters).ToList(), out var newUri);
			Assert.AreEqual(expectedSignatureBase, signatureBase);

			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(signatureBase, consumerSecret, tokenSecret));
		}

		[TestCase("/oRgs7HwVC0K2Ou1j0tuVTR6bRI=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "7d8f3e4a", "137131201", "c2", "", "a3", "2 q", Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("/oRgs7HwVC0K2Ou1j0tuVTR6bRI=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "7d8f3e4a", "137131201", Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha1Signature(string expectedSignature, string uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, string timeStamp, params string[] parameters)
		{
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(new Uri(uri), httpMethod, consumerToken, consumerSecret, nonce, timeStamp, ToPairs(parameters).ToList()));

			var hmacSha1Parameters = GetHmacSha1Parameters(consumerToken, nonce, timeStamp, ToPairs(parameters));
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, hmacSha1Parameters, out string _), consumerSecret, null));
		}

		[TestCase("RCEx3aTTfxXndwskapOhauQuLvc=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "http://example.com/callback", "7d8f3e4a", "137131201", "c2", "", "a3", "2 q", Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("RCEx3aTTfxXndwskapOhauQuLvc=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "http://example.com/callback", "7d8f3e4a", "137131201", Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha1SignatureWithCallback(string expectedSignature, string uri, string httpMethod, string consumerToken, string consumerSecret, string callback, string nonce, string timeStamp, params string[] parameters)
		{
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(new Uri(uri), httpMethod, consumerToken, consumerSecret, callback, nonce, timeStamp, ToPairs(parameters).ToList()));

			var hmacSha1Parameters = GetHmacSha1Parameters(consumerToken, nonce, timeStamp, ToPairs(parameters))
				.Union(new List<KeyValuePair<string, string>>
				{
					new KeyValuePair<string, string>(OAuthConstants.Callback, callback),
				}).ToList();
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, hmacSha1Parameters, out string _), consumerSecret, null));
		}

		[TestCase("6O1GslHxGzyF0sWbYA8vivyaVpg=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "473f82d3", "7d8f3e4a", "137131201", "c2", "", "a3", "2 q", Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("6O1GslHxGzyF0sWbYA8vivyaVpg=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "473f82d3", "7d8f3e4a", "137131201", Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha1SignatureWithVerifier(string expectedSignature, string uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, string nonce, string timeStamp, params string[] parameters)
		{
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(new Uri(uri), httpMethod, consumerToken, consumerSecret, temporaryToken, temporarySecret, verifier, nonce, timeStamp, ToPairs(parameters).ToList()));

			var hmacSha1Parameters = GetHmacSha1Parameters(consumerToken, nonce, timeStamp, ToPairs(parameters))
				.Union(new List<KeyValuePair<string, string>>
				{
					new KeyValuePair<string, string>(OAuthConstants.Token, temporaryToken),
					new KeyValuePair<string, string>(OAuthConstants.Verifier, verifier),
				}).ToList();
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, hmacSha1Parameters, out string _), consumerSecret, temporarySecret));
		}

		[TestCase("OB33pYjWAnf+xtOHN4Gmbdil168=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "7d8f3e4a", "137131201", "c2", "", "a3", "2 q", Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("OB33pYjWAnf+xtOHN4Gmbdil168=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "7d8f3e4a", "137131201", Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha1SignatureWithAccessToken(string expectedSignature, string uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string nonce, string timeStamp, params string[] parameters)
		{
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(new Uri(uri), httpMethod, consumerToken, consumerSecret, accessToken, accessSecret, nonce, timeStamp, ToPairs(parameters).ToList()));

			var hmacSha1Parameters = GetHmacSha1Parameters(consumerToken, nonce, timeStamp, ToPairs(parameters))
				.Union(new List<KeyValuePair<string, string>>
				{
					new KeyValuePair<string, string>(OAuthConstants.Token, accessToken),
				}).ToList();
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, hmacSha1Parameters, out string _), consumerSecret, accessSecret));
		}

		[TestCase("http://example.com/path?query=test", "GET", "(abc123)", "[ABC456]", "{def789}", 1390954246, "/f3ZnP8HBAWH0FY1gLDxp6+wGsA=")]
		[TestCase("http://example.com/path?query=test1&query=test2", "GET", "(abc123)", "[ABC456]", "{def789}", 1390954246, "zVCpL3X6FBeooVi0CLbfm3i7D+o=")]
		public void CreateHmacSha1AuthorizationHeader(string uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, long timestamp, string expectedSignature)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			string header = OAuthUtility.CreateHmacSha1AuthorizationHeaderValue(new Uri(uri), httpMethod, consumerToken, consumerSecret, nonceCreator, systemTime);
			AssertAuthorizationHeader(header, new[] { "oauth_consumer_key", consumerToken, "oauth_nonce", nonce, "oauth_timestamp", timestamp.ToInvariantString(), "oauth_signature_method", "HMAC-SHA1", "oauth_version", "1.0", "oauth_signature", expectedSignature });
		}

		[TestCase("OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_nonce=\"wIjqoS\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"137131200\",oauth_version=\"1.0\",oauth_callback=\"http%3A%2F%2Fprinter.example.com%2Fready\",oauth_signature=\"msrTmwtDEKqeVXeJaufuiXOpbJI%3D\"",
			"https://photos.example.net/initiate", "POST", "dpf43f3p2l4k3l03", "kd94hf93k423kf44", "http://printer.example.com/ready", "wIjqoS", 137131200,
			Description = "RFC 5849, section 1.2")]
		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\",oauth_signature=\"RCEx3aTTfxXndwskapOhauQuLvc%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "http://example.com/callback", "7d8f3e4a", 137131201, "c2", "", "a3", "2 q",
			Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\",oauth_signature=\"RCEx3aTTfxXndwskapOhauQuLvc%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "http://example.com/callback", "7d8f3e4a", 137131201,
			Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha1AuthorizationHeaderWithCallback(string expectedHeader, string uri, string httpMethod, string consumerToken, string consumerSecret, string callback, string nonce, long timestamp, params string[] parameters)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha1AuthorizationHeaderValue(AppendPostToQuery(new Uri(uri), parameters), httpMethod, consumerToken, consumerSecret, callback, nonceCreator, systemTime));
			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha1AuthorizationHeaderValue(new Uri(uri), GetHmacSha1Parameters(consumerToken, nonce, timestamp.ToInvariantString(), ToPairs(parameters)), httpMethod, consumerToken, consumerSecret, callback, nonceCreator, systemTime));
		}

		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_token=\"kkk9d7dh3k39sjv7\",oauth_verifier=\"473f82d3\",oauth_signature=\"6O1GslHxGzyF0sWbYA8vivyaVpg%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "473f82d3", "7d8f3e4a", 137131201, "c2", "", "a3", "2 q",
			Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_token=\"kkk9d7dh3k39sjv7\",oauth_verifier=\"473f82d3\",oauth_signature=\"6O1GslHxGzyF0sWbYA8vivyaVpg%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "473f82d3", "7d8f3e4a", 137131201,
			Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreatHmacSha1AuthorizationHeaderWithVerifier(string expectedHeader, string uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, string nonce, long timestamp, params string[] parameters)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha1AuthorizationHeaderValue(AppendPostToQuery(new Uri(uri), parameters), httpMethod, consumerToken, consumerSecret, temporaryToken, temporarySecret, verifier, nonceCreator, systemTime));
			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha1AuthorizationHeaderValue(new Uri(uri), GetHmacSha1Parameters(consumerToken, nonce, timestamp.ToInvariantString(), ToPairs(parameters)), httpMethod, consumerToken, consumerSecret, temporaryToken, temporarySecret, verifier, nonceCreator, systemTime));
		}

		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_token=\"kkk9d7dh3k39sjv7\",oauth_signature=\"OB33pYjWAnf%2BxtOHN4Gmbdil168%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "7d8f3e4a", 137131201, "c2", "", "a3", "2 q",
			Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_token=\"kkk9d7dh3k39sjv7\",oauth_signature=\"OB33pYjWAnf%2BxtOHN4Gmbdil168%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "7d8f3e4a", 137131201,
			Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreatHmacSha1AuthorizationHeaderWithAccessToken(string expectedHeader, string uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string nonce, long timestamp, params string[] parameters)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha1AuthorizationHeaderValue(AppendPostToQuery(new Uri(uri), parameters), httpMethod, consumerToken, consumerSecret, accessToken, accessSecret, nonceCreator, systemTime));
			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha1AuthorizationHeaderValue(new Uri(uri), GetHmacSha1Parameters(consumerToken, nonce, timestamp.ToInvariantString(), ToPairs(parameters)), httpMethod, consumerToken, consumerSecret, accessToken, accessSecret, nonceCreator, systemTime));
		}

		private static ICollection<KeyValuePair<string, string>> GetHmacSha1Parameters(string consumerToken, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>>? additionalParameters = null)
		{
			return new List<KeyValuePair<string, string>>
			{
				new KeyValuePair<string, string>(OAuthConstants.ConsumerKey, consumerToken),
				new KeyValuePair<string, string>(OAuthConstants.Nonce, nonce),
				new KeyValuePair<string, string>(OAuthConstants.SignatureMethod, OAuthSignatureMethods.HmacSha1),
				new KeyValuePair<string, string>(OAuthConstants.TimeStamp, timeStamp),
				new KeyValuePair<string, string>(OAuthConstants.Version, OAuthConstants.OAuthVersion),
			}.Union(additionalParameters.EmptyIfNull().Where(kvp => kvp.Value != null)).ToList();
		}

		private static Uri AppendPostToQuery(Uri uri, string[] parameters) =>
			parameters == null || parameters.Length == 0
				? uri
				: new Uri($"{uri}{(uri.Query.IsNullOrWhiteSpace() ? "?" : "&")}{string.Join("&", ToPairs(parameters).Where(x => !x.Key.IsNullOrEmpty()).Select(x => $"{x.Key}={x.Value}"))}");

		private static IEnumerable<KeyValuePair<string, string>> ToPairs(params string[] keysAndValues)
		{
			for (int i = 0; i < keysAndValues.Length; i += 2)
				yield return new KeyValuePair<string, string>(keysAndValues[i], keysAndValues[i + 1]);
		}

		private sealed class TestNonceCreator : INonceCreator
		{
			public TestNonceCreator(string nonce)
			{
				m_nonce = nonce;
			}

			public string CreateNonce()
			{
				return m_nonce;
			}

			private readonly string m_nonce;
		}

		private sealed class TestSystemTime : ISystemTime
		{
			public TestSystemTime(long timestamp)
			{
				m_timestamp = timestamp;
			}

			public DateTime GetUtcNow()
			{
				return DateTimeUtility.FromUnixTimestamp(m_timestamp);
			}

			private readonly long m_timestamp;
		}

		private static void AssertAuthorizationHeader(string header, params string[] expectedKeysAndValues)
		{
			Assert.IsTrue(header.StartsWithOrdinal("OAuth "));
			var parameters = header.Substring(6)
				.Split(',')
				.Select(x => x.Split('='))
				.ToDictionary(x => x[0].Trim(), x => x[1].Trim());

			foreach (var expected in ToPairs(expectedKeysAndValues))
			{
				Assert.IsTrue(parameters.TryGetValue(expected.Key, out var value));
				Assert.AreEqual("\"" + OAuthUtility.PercentEncode(expected.Value) + "\"", value);
				parameters.Remove(expected.Key);
			}

			Assert.AreEqual(Array.Empty<KeyValuePair<string, string>>(), parameters);
		}
	}
}
