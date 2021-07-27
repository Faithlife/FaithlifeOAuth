using System;
using System.Collections.Generic;
using System.Linq;
using Faithlife.Utility;
using NUnit.Framework;

namespace Faithlife.OAuth.Tests
{
	public class OAuthHmacSha256Tests
	{
		[TestCase("POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7",
			"ypAxjNip++Dm0fTM+gCl8wAo6ufSnseu1WHxL7py3BU=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "j49sk3j29djd", "dh893hdasih9",
			"oauth_consumer_key", "9djdj82h48djs9d2", "oauth_token", "kkk9d7dh3k39sjv7", "oauth_signature_method", "HMAC-SHA256", "oauth_timestamp", "137131201", "oauth_nonce", "7d8f3e4a", "c2", "", "a3", "2 q",
			Description = "RFC 5849, section 3.4.1.1, amended by errata 2550")]
		[TestCase("POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521",
			"lrpvd+UOGVsQnRf5skaXYTNeIPFJ0C+qK3OGpK/XB9Q=", "https://api.twitter.com/1/statuses/update.json?include_entities=true", "POST", "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw", "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
			"oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog", "oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "oauth_signature_method", "HMAC-SHA256", "oauth_timestamp", "1318622958", "oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", "oauth_version", "1.0", "status", "Hello Ladies + Gentlemen, a signed OAuth request!",
			Description = "From https://dev.twitter.com/docs/auth/creating-signature")]
		[TestCase("GET&http%3A%2F%2Fwww.example.net%2Fresource&Name%3Dvalue3%26Name%3Dvalue4%26name%3Dvalue1%26name%3Dvalue2%26oauth_consumer_key%3Dabcd%26oauth_nonce%3DNJoXy4OiHud%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D1438360868%26oauth_token%3Dijkl%26oauth_version%3D1.0",
			"k5Tbz5Wmo4dJXUFjC2g8+fUjMRr50cGKuE05Xkjx04g=", "http://www.example.net/resource?name=value1&name=value2&Name=value3&Name=value4", "GET", "efgh", "mnop",
			"oauth_consumer_key", "abcd", "oauth_token", "ijkl", "oauth_signature_method", "HMAC-SHA256", "oauth_timestamp", "1438360868", "oauth_nonce", "NJoXy4OiHud", "oauth_version", "1.0",
			Description = "From http://oauth.googlecode.com/svn/code/javascript/example/signature.html")]
		[TestCase("GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3DchapoH%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D137131202%26oauth_token%3Dnnch734d00sl2jdk%26size%3Doriginal",
			"HtMwoX2zenlFjgGg/SNEoKEQmL7CzxYFEKzs7er044Y=", "http://photos.example.net/photos?file=vacation.jpg&size=original", "GET", "kd94hf93k423kf44", "pfkkdhi9sl3r4s00",
			"oauth_consumer_key", "dpf43f3p2l4k3l03", "oauth_nonce", "chapoH", "oauth_signature_method", "HMAC-SHA256", "oauth_timestamp", "137131202", "oauth_token", "nnch734d00sl2jdk", Description = "RFC 5849, section 1.2")]
		public void CreateSignature(string expectedSignatureBase, string expectedSignature, string uri, string httpMethod, string consumerSecret, string tokenSecret, params string[] parameters)
		{
			string signatureBase = OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, ToPairs(parameters).ToList(), out var newUri);
			Assert.AreEqual(expectedSignatureBase, signatureBase);

			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(signatureBase, consumerSecret, tokenSecret));
		}

		[TestCase("wCSSpa0QAeuG2SDsgPE5JQvJyNOSjLGua7dZcBbNUnE=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "7d8f3e4a", "137131201", "c2", "", "a3", "2 q", Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("wCSSpa0QAeuG2SDsgPE5JQvJyNOSjLGua7dZcBbNUnE=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "7d8f3e4a", "137131201", Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha256Signature(string expectedSignature, string uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, string timeStamp, params string[] parameters)
		{
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(new Uri(uri), httpMethod, consumerToken, consumerSecret, nonce, timeStamp, ToPairs(parameters).ToList()));

			var hmacSha256Parameters = GetHmacSha256Parameters(consumerToken, nonce, timeStamp, ToPairs(parameters));
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, hmacSha256Parameters, out string _), consumerSecret, null));
		}

		[TestCase("S5Pmd594CQxBStPRWCOq54BBrRDzfWT0FbPt9ttkdIk=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "http://example.com/callback", "7d8f3e4a", "137131201", "c2", "", "a3", "2 q", Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("S5Pmd594CQxBStPRWCOq54BBrRDzfWT0FbPt9ttkdIk=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "http://example.com/callback", "7d8f3e4a", "137131201", Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha256SignatureWithCallback(string expectedSignature, string uri, string httpMethod, string consumerToken, string consumerSecret, string callback, string nonce, string timeStamp, params string[] parameters)
		{
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(new Uri(uri), httpMethod, consumerToken, consumerSecret, callback, nonce, timeStamp, ToPairs(parameters).ToList()));

			var hmacSha256Parameters = GetHmacSha256Parameters(consumerToken, nonce, timeStamp, ToPairs(parameters))
				.Union(new List<KeyValuePair<string, string>>
				{
					new KeyValuePair<string, string>(OAuthConstants.Callback, callback),
				}).ToList();
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, hmacSha256Parameters, out string _), consumerSecret, null));
		}

		[TestCase("XP2OzKl4jLRjl0S0gd0q60idTSWFVpR65ocUyCdcW7s=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "473f82d3", "7d8f3e4a", "137131201", "c2", "", "a3", "2 q", Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("XP2OzKl4jLRjl0S0gd0q60idTSWFVpR65ocUyCdcW7s=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "473f82d3", "7d8f3e4a", "137131201", Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha256SignatureWithVerifier(string expectedSignature, string uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, string nonce, string timeStamp, params string[] parameters)
		{
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(new Uri(uri), httpMethod, consumerToken, consumerSecret, temporaryToken, temporarySecret, verifier, nonce, timeStamp, ToPairs(parameters).ToList()));

			var hmacSha256Parameters = GetHmacSha256Parameters(consumerToken, nonce, timeStamp, ToPairs(parameters))
				.Union(new List<KeyValuePair<string, string>>
				{
					new KeyValuePair<string, string>(OAuthConstants.Token, temporaryToken),
					new KeyValuePair<string, string>(OAuthConstants.Verifier, verifier),
				}).ToList();
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, hmacSha256Parameters, out string _), consumerSecret, temporarySecret));
		}

		[TestCase("xie2kqHv7CoC3VI1g/IUClHXm4q+1H3XJZG1izUgBXs=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "7d8f3e4a", "137131201", "c2", "", "a3", "2 q", Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("xie2kqHv7CoC3VI1g/IUClHXm4q+1H3XJZG1izUgBXs=", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "7d8f3e4a", "137131201", Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha256SignatureWithAccessToken(string expectedSignature, string uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string nonce, string timeStamp, params string[] parameters)
		{
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(new Uri(uri), httpMethod, consumerToken, consumerSecret, accessToken, accessSecret, nonce, timeStamp, ToPairs(parameters).ToList()));

			var hmacSha256Parameters = GetHmacSha256Parameters(consumerToken, nonce, timeStamp, ToPairs(parameters))
				.Union(new List<KeyValuePair<string, string>>
				{
					new KeyValuePair<string, string>(OAuthConstants.Token, accessToken),
				}).ToList();
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, hmacSha256Parameters, out string _), consumerSecret, accessSecret));
		}

		[TestCase("http://example.com/path?query=test", "GET", "(abc123)", "[ABC456]", "{def789}", 1390954246, "XsmWRY431G9EuWamnOaPoWS+IYjBepLg6gVQwM6N4e0=")]
		[TestCase("http://example.com/path?query=test1&query=test2", "GET", "(abc123)", "[ABC456]", "{def789}", 1390954246, "PUQY+375OBfALFHc2CwviI/w6h2wSHJVJvnWrz6tWeI=")]
		public void CreateHmacSha256AuthorizationHeader(string uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, long timestamp, string expectedSignature)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			string header = OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(new Uri(uri), httpMethod, consumerToken, consumerSecret, nonceCreator, systemTime);

			AssertAuthorizationHeader(header, new[] { "oauth_consumer_key", consumerToken, "oauth_nonce", nonce, "oauth_timestamp", timestamp.ToInvariantString(), "oauth_signature_method", "HMAC-SHA256", "oauth_version", "1.0", "oauth_signature", expectedSignature });
		}

		[TestCase("OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_nonce=\"wIjqoS\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"137131200\",oauth_version=\"1.0\",oauth_callback=\"http%3A%2F%2Fprinter.example.com%2Fready\",oauth_signature=\"WRDBO0foVD0tBkZ2wz6TzQJ5c0%2FKFGz6dfY2eXCcJoA%3D\"",
			"https://photos.example.net/initiate", "POST", "dpf43f3p2l4k3l03", "kd94hf93k423kf44", "http://printer.example.com/ready", "wIjqoS", 137131200,
			Description = "RFC 5849, section 1.2")]
		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\",oauth_signature=\"S5Pmd594CQxBStPRWCOq54BBrRDzfWT0FbPt9ttkdIk%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "http://example.com/callback", "7d8f3e4a", 137131201, "c2", "", "a3", "2 q",
			Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\",oauth_signature=\"S5Pmd594CQxBStPRWCOq54BBrRDzfWT0FbPt9ttkdIk%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "http://example.com/callback", "7d8f3e4a", 137131201,
			Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreateHmacSha256AuthorizationHeaderWithCallback(string expectedHeader, string uri, string httpMethod, string consumerToken, string consumerSecret, string callback, string nonce, long timestamp, params string[] parameters)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(AppendPostToQuery(new Uri(uri), parameters), httpMethod, consumerToken, consumerSecret, callback, nonceCreator, systemTime));
			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(new Uri(uri), GetHmacSha256Parameters(consumerToken, nonce, timestamp.ToInvariantString(), ToPairs(parameters)), httpMethod, consumerToken, consumerSecret, callback, nonceCreator, systemTime));
		}

		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_token=\"kkk9d7dh3k39sjv7\",oauth_verifier=\"473f82d3\",oauth_signature=\"XP2OzKl4jLRjl0S0gd0q60idTSWFVpR65ocUyCdcW7s%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "473f82d3", "7d8f3e4a", 137131201, "c2", "", "a3", "2 q",
			Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_token=\"kkk9d7dh3k39sjv7\",oauth_verifier=\"473f82d3\",oauth_signature=\"XP2OzKl4jLRjl0S0gd0q60idTSWFVpR65ocUyCdcW7s%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "473f82d3", "7d8f3e4a", 137131201,
			Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreatHmacSha256AuthorizationHeaderWithVerifier(string expectedHeader, string uri, string httpMethod, string consumerToken, string consumerSecret, string temporaryToken, string temporarySecret, string verifier, string nonce, long timestamp, params string[] parameters)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(AppendPostToQuery(new Uri(uri), parameters), httpMethod, consumerToken, consumerSecret, temporaryToken, temporarySecret, verifier, nonceCreator, systemTime));
			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(new Uri(uri), GetHmacSha256Parameters(consumerToken, nonce, timestamp.ToInvariantString(), ToPairs(parameters)), httpMethod, consumerToken, consumerSecret, temporaryToken, temporarySecret, verifier, nonceCreator, systemTime));
		}

		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_token=\"kkk9d7dh3k39sjv7\",oauth_signature=\"xie2kqHv7CoC3VI1g%2FIUClHXm4q%2B1H3XJZG1izUgBXs%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "7d8f3e4a", 137131201, "c2", "", "a3", "2 q",
			Description = "RFC 5849, section 3.4.1.3.1")]
		[TestCase("OAuth oauth_consumer_key=\"9djdj82h48djs9d2\",oauth_nonce=\"7d8f3e4a\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"137131201\",oauth_version=\"1.0\",oauth_token=\"kkk9d7dh3k39sjv7\",oauth_signature=\"xie2kqHv7CoC3VI1g%2FIUClHXm4q%2B1H3XJZG1izUgBXs%3D\"",
			"http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2%20q", "POST", "9djdj82h48djs9d2", "j49sk3j29djd", "kkk9d7dh3k39sjv7", "dh893hdasih9", "7d8f3e4a", 137131201,
			Description = "RFC 5849, section 3.4.1.3.1")]
		public void CreatHmacSha256AuthorizationHeaderWithAccessToken(string expectedHeader, string uri, string httpMethod, string consumerToken, string consumerSecret, string accessToken, string accessSecret, string nonce, long timestamp, params string[] parameters)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(AppendPostToQuery(new Uri(uri), parameters), httpMethod, consumerToken, consumerSecret, accessToken, accessSecret, nonceCreator, systemTime));
			Assert.AreEqual(expectedHeader, OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(new Uri(uri), GetHmacSha256Parameters(consumerToken, nonce, timestamp.ToInvariantString(), ToPairs(parameters)), httpMethod, consumerToken, consumerSecret, accessToken, accessSecret, nonceCreator, systemTime));
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

		private static ICollection<KeyValuePair<string, string>> GetHmacSha256Parameters(string consumerToken, string nonce, string timeStamp, IEnumerable<KeyValuePair<string, string>>? additionalParameters = null)
		{
			return new List<KeyValuePair<string, string>>
			{
				new KeyValuePair<string, string>(OAuthConstants.ConsumerKey, consumerToken),
				new KeyValuePair<string, string>(OAuthConstants.Nonce, nonce),
				new KeyValuePair<string, string>(OAuthConstants.SignatureMethod, OAuthSignatureMethods.HmacSha256),
				new KeyValuePair<string, string>(OAuthConstants.TimeStamp, timeStamp),
				new KeyValuePair<string, string>(OAuthConstants.Version, OAuthConstants.OAuthVersion),
			}.Union(additionalParameters.EmptyIfNull().Where(kvp => kvp.Value != null)).ToList();
		}
	}
}
