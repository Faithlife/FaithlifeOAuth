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
	[TestFixture]
	public class OAuthUtilityTests
	{
		[TestCase("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")]
		[TestCase("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz")]
		[TestCase("0123456789-._~", "0123456789-._~")]
		[TestCase(" !\"#$%&'()*+,/:;<=>?@[\\]^`{|}", "%20%21%22%23%24%25%26%27%28%29%2A%2B%2C%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E%60%7B%7C%7D")]
		[TestCase("Ûñïçóđè", "%C3%9B%C3%B1%C3%AF%C3%A7%C3%B3%C4%91%C3%A8")]
		public void PercentEncode(string input, string expected)
		{
			Assert.AreEqual(expected, OAuthUtility.PercentEncode(input));
		}

		[TestCase("abc", "def", "oauth_consumer_key", "abc", "oauth_signature_method", "PLAINTEXT", "oauth_version", "1.0", "oauth_signature", "def&")]
		[TestCase("!#$", "'()", "oauth_consumer_key", "!#$", "oauth_signature_method", "PLAINTEXT", "oauth_version", "1.0", "oauth_signature", "%27%28%29&")]
		public void CreatePlaintextAuthorizationHeader(string consumerKey, string consumerSecret, params string[] expectedKeysAndValues)
		{
			AssertAuthorizationHeader(OAuthUtility.CreateAuthorizationHeaderValue(consumerKey, consumerSecret), expectedKeysAndValues);
		}

		[TestCase("abc", "def", "ghi", "jkl", "oauth_consumer_key", "abc", "oauth_token", "ghi", "oauth_signature_method", "PLAINTEXT", "oauth_version", "1.0", "oauth_signature", "def&jkl")]
		[TestCase("!#$", "'()", "[^]", "{|}", "oauth_consumer_key", "!#$", "oauth_token", "[^]", "oauth_signature_method", "PLAINTEXT", "oauth_version", "1.0", "oauth_signature", "%27%28%29&%7B%7C%7D")]
		public void CreatePlaintextAuthorizationHeaderWithAccessKey(string consumerKey, string consumerSecret, string accessKey, string accessSecret, params string[] expectedKeysAndValues)
		{
			AssertAuthorizationHeader(OAuthUtility.CreateAuthorizationHeaderValue(consumerKey, consumerSecret, accessKey, accessSecret), expectedKeysAndValues);
		}

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
		public void CreateHmacSha1Signature(string expectedSignatureBase, string expectedSignature, string uri, string httpMethod, string consumerSecret, string tokenSecret, params string[] parameters)
		{
			var signatureBase = OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, ToPairs(parameters).ToList(), out _);
			Assert.AreEqual(expectedSignatureBase, signatureBase);

			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha1Signature(signatureBase, consumerSecret, tokenSecret));
		}

		[TestCase("http://example.com/path?query=test", "GET", "(abc123)", "[ABC456]", "{def789}", 1390954246, "/f3ZnP8HBAWH0FY1gLDxp6+wGsA=")]
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
		public void CreateHmacSha1AuthorizationHeader2(string expectedHeader, string uri, string httpMethod, string consumerToken, string consumerSecret, string callback, string nonce, long timestamp)
		{
			TestNonceCreator nonceCreator = new TestNonceCreator(nonce);
			TestSystemTime systemTime = new TestSystemTime(timestamp);

			string header = OAuthUtility.CreateHmacSha1AuthorizationHeaderValue(new Uri(uri), httpMethod, consumerToken, consumerSecret, callback, nonceCreator, systemTime);
			Assert.AreEqual(expectedHeader, header);
		}

   //     [TestCase("POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttp%253A%252F%252Flocalhost%253A3005%252Fthe_dance%252Fprocess_callback%253Fservice_provider_id%253D11%26oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DQP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D1272323042%26oauth_version%3D1.0",
			//"N0KBpiPbuPIMx2B77eIg7tNfGNF81iq3bcO9RO6lH+k=", "https://api.twitter.com/oauth/request_token", "POST", "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", null,
			//"oauth_consumer_key", "GDdmIQH6jhtmLUypg82g", "oauth_signature_method", "HMAC-SHA256", "oauth_timestamp", "1272323042", "oauth_version", "1.0", "oauth_nonce", "QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk", "oauth_callback", "http://localhost:3005/the_dance/process_callback?service_provider_id=11",
			//Description = "From https://github.com/request/oauth-sign/blob/18a2513da6ba7a2c0cd8179170d7c296c7625137/test.js")]
		//[TestCase("POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3D9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D1272323047%26oauth_token%3D8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc%26oauth_verifier%3DpDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY%26oauth_version%3D1.0",
		//	"y7S9eUhA0tC9/YfRzCPqkg3/bUdYRDpZ93Xi51AvhjQ=", "https://api.twitter.com/oauth/access_token", "POST", "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", "x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA",
		//	"oauth_consumer_key", "GDdmIQH6jhtmLUypg82g", "oauth_signature_method", "HMAC-SHA256", "oauth_token", "8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc", "oauth_timestamp", "1272323047", "oauth_version", "1.0", "oauth_nonce", "9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8", "oauth_verifier", "pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY",
		//	Description = "From https://github.com/request/oauth-sign/blob/18a2513da6ba7a2c0cd8179170d7c296c7625137/test.js")]
		//[TestCase("POST&http%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DoElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D1272325550%26oauth_token%3D819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw%26oauth_version%3D1.0%26status%3Dsetting%2520up%2520my%2520twitter%2520%25E7%25A7%2581%25E3%2581%25AE%25E3%2581%2595%25E3%2581%2588%25E3%2581%259A%25E3%2582%258A%25E3%2582%2592%25E8%25A8%25AD%25E5%25AE%259A%25E3%2581%2599%25E3%2582%258B",
		//	"xYhKjozxc3NYef7C26WU+gORdhEURdZRxSDzRttEKH0=", "http://api.twitter.com/1/statuses/update.json", "POST", "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", "J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA",
		//	"oauth_consumer_key", "GDdmIQH6jhtmLUypg82g", "oauth_signature_method", "HMAC-SHA256", "oauth_token", "819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw", "oauth_timestamp", "1272325550", "oauth_version", "1.0", "oauth_nonce", "oElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y", "status", "setting up my twitter 私のさえずりを設定する",
		//	Description = "From https://github.com/request/oauth-sign/blob/18a2513da6ba7a2c0cd8179170d7c296c7625137/test.js")]
		[TestCase("POST&http%3A%2F%2Fwordpress.com%2Fwp-json&filter%255Bnumber%255D%3D-1%26oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DoElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D1272325550%26oauth_token%3D819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw%26oauth_version%3D1.0",
			"6hXbe84vZjenN4Il6ko0dpIBxUXrWj4SBFoBwgCIK+8=", "http://wordpress.com/wp-json", "POST", "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", "J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA",
			"oauth_consumer_key", "GDdmIQH6jhtmLUypg82g", "oauth_signature_method", "HMAC-SHA256", "oauth_token", "819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw", "oauth_timestamp", "1272325550", "oauth_version", "1.0", "oauth_nonce", "oElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y", "filter[number]", "-1",
			Description = "From https://github.com/request/oauth-sign/blob/18a2513da6ba7a2c0cd8179170d7c296c7625137/test.js")]

		public void CreateHmacSha256Signature(string expectedSignatureBase, string expectedSignature, string uri, string httpMethod, string consumerSecret, string tokenSecret, params string[] parameters)
		{
			var signatureBase = OAuthUtility.CreateSignatureBase(new Uri(uri), httpMethod, ToPairs(parameters).ToList(), out _);

			Assert.AreEqual(expectedSignatureBase, signatureBase);
			Assert.AreEqual(expectedSignature, OAuthUtility.CreateHmacSha256Signature(signatureBase, consumerSecret, tokenSecret));
		}

		[TestCase("https://api.twitter.com/oauth/request_token", "POST", "GDdmIQH6jhtmLUypg82g", "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", "QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk", 1272323042, "http://localhost:3005/the_dance/process_callback?service_provider_id=11", "N0KBpiPbuPIMx2B77eIg7tNfGNF81iq3bcO9RO6lH+k=",
			Description = "From https://github.com/request/oauth-sign/blob/18a2513da6ba7a2c0cd8179170d7c296c7625137/test.js")]
		public void CreateHmacSha256AuthorizationHeader(string uri, string httpMethod, string consumerToken, string consumerSecret, string nonce, long timestamp, string callback, string expectedSignature)
		{
			var nonceCreator = new TestNonceCreator(nonce);
			var systemTime = new TestSystemTime(timestamp);
			
			var header = OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(new Uri(uri), httpMethod, consumerToken, consumerSecret, callback: callback, nonceCreator: nonceCreator, systemTime: systemTime);
			AssertAuthorizationHeader(header, new[] { "oauth_consumer_key", consumerToken, "oauth_nonce", nonce, "oauth_timestamp", timestamp.ToInvariantString(), "oauth_signature_method", "HMAC-SHA256", "oauth_version", "1.0", "oauth_callback", callback, "oauth_signature", expectedSignature });
		}

		[TestCase("OAuth oauth_consumer_key=\"GDdmIQH6jhtmLUypg82g\",oauth_nonce=\"9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"1272323047\",oauth_version=\"1.0\",oauth_token=\"8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc\",oauth_verifier=\"pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY\",oauth_signature=\"y7S9eUhA0tC9%2FYfRzCPqkg3%2FbUdYRDpZ93Xi51AvhjQ%3D\"",
			"https://api.twitter.com/oauth/access_token", "POST", "GDdmIQH6jhtmLUypg82g", "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", "8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc", "x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA", "pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY", "9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8", 1272323047,
			Description = "From https://github.com/request/oauth-sign/blob/18a2513da6ba7a2c0cd8179170d7c296c7625137/test.js")]
		public void CreateHmacSha256AuthorizationHeader2(string expectedHeader, string uri, string httpMethod, string consumerToken, string consumerSecret, string token, string tokenSecret, string verifier, string nonce, long timestamp)
		{
			var nonceCreator = new TestNonceCreator(nonce);
			var systemTime = new TestSystemTime(timestamp);

			var header = OAuthUtility.CreateHmacSha256AuthorizationHeaderValue(new Uri(uri), httpMethod, consumerToken, consumerSecret, token, tokenSecret, verifier: verifier, nonceCreator: nonceCreator, systemTime: systemTime);
			Assert.AreEqual(expectedHeader, header);
		}

		[TestCase("?659347508784", "659347508784", "")]
		[TestCase("?q=%25%26%3D&a=b&s=%22123%22", "q", "%&=", "a", "b", "s", "\"123\"")]
		[TestCase("?b5=%3D%253D&a3=a&c%40=&a2=r%20b", "b5", "=%3D", "a3", "a", "c@", "", "a2", "r b", Description = "From https://tools.ietf.org/html/rfc5849#section-3.4.1.3.1")]
		[TestCase("?c2&a3=2+q", "c2", "", "a3", "2 q", Description = "From POST body in https://tools.ietf.org/html/rfc5849#section-3.4.1.3.1")]
		[TestCase("")]
		[TestCase("?")]
		[TestCase(null)]
		public void GetQueryParameters(string query, params string[] keysAndValues)
		{
			CollectionAssert.AreEqual(ToPairs(keysAndValues), OAuthUtility.GetQueryParameters(query));
		}

		private static IEnumerable<KeyValuePair<string, string>> ToPairs(params string[] keysAndValues)
		{
			for (int i = 0; i < keysAndValues.Length; i += 2)
				yield return new KeyValuePair<string, string>(keysAndValues[i], keysAndValues[i + 1]);
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

			Assert.AreEqual(new KeyValuePair<string, string>[0], parameters);
		}

		private sealed class TestNonceCreator : INonceCreator
		{
			public TestNonceCreator(string nonce) => m_nonce = nonce;

			public string CreateNonce() => m_nonce;

			private readonly string m_nonce;
		}

		private sealed class TestSystemTime : ISystemTime
		{
			public TestSystemTime(long timestamp) => m_timestamp = timestamp;

			public DateTime GetUtcNow() => DateTimeUtility.FromUnixTimestamp(m_timestamp);

			private readonly long m_timestamp;
		}
	}
}
