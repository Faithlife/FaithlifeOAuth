using System;
using NUnit.Framework;

namespace Faithlife.OAuth.Tests
{
	[TestFixture]
	public class SecureStringUtilityTests
	{
		[Test]
		public void BadArguments()
		{
			Assert.Throws<ArgumentNullException>(() => SecureStringUtility.FromString(null));
			Assert.Throws<ArgumentNullException>(() => SecureStringUtility.ToString(null));
			Assert.Throws<ArgumentNullException>(() => SecureStringUtility.CopyAsReadOnly(null));
		}

		[TestCase("")]
		[TestCase("testing secure string")]
		public void SecureStringTests(string input)
		{
			using (SecureString s1 = SecureStringUtility.FromString(input))
			using (SecureString s2 = s1.CopyAsReadOnly())
			{
				Assert.IsTrue(s1.IsReadOnly());
				Assert.IsTrue(s2.IsReadOnly());
				Assert.AreEqual(input, SecureStringUtility.ToString(s1));
				Assert.AreEqual(input, SecureStringUtility.ToString(s2));
			}
		}
	}
}
