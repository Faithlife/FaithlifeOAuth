using System;

namespace Faithlife.OAuth
{
	/// <summary>
	/// Represents text that should be confidential. This is a stand-in for System.Security.SecureString. It does not encrypt its backing buffer.
	/// </summary>
	public sealed class SecureString : IDisposable
	{
		/// <summary>
		/// Creates a new <code>SecureString</code>.
		/// </summary>
		public SecureString()
		{
			m_buffer = new char[65536];
		}

		/// <summary>
		/// The length of the string.
		/// </summary>
		/// <exception cref="ObjectDisposedException">The string has already been disposed.</exception>
		public int Length
		{
			get
			{
				VerifyNotDisposed();
				return m_length;
			}
		}

		/// <summary>
		/// Appends a character to the end of the string.
		/// </summary>
		/// <param name="ch">The character to append.</param>
		/// <exception cref="ObjectDisposedException">The string has already been disposed.</exception>
		/// <exception cref="InvalidOperationException">The string has been marked read-only.</exception>
		/// <exception cref="ArgumentOutOfRangeException">The length of this string is already 65536.</exception>
		public void AppendChar(char ch)
		{
			VerifyNotDisposed();
			VerifyNotReadOnly();
			if (m_length == m_buffer.Length)
				throw new ArgumentOutOfRangeException();
			m_buffer[m_length++] = ch;
		}

		/// <summary>
		/// Makes this string read-only.
		/// </summary>
		/// <exception cref="ObjectDisposedException">The string has already been disposed.</exception>
		public void MakeReadOnly()
		{
			VerifyNotDisposed();
			m_isReadOnly = true;
		}

		/// <summary>
		/// Indicates whether this secure string is marked read-only.
		/// </summary>
		/// <returns><c>true</c>, if this secure string is marked read-only, <c>false</c> otherwise.</returns>
		/// <exception cref="ObjectDisposedException">The string has already been disposed.</exception>
		public bool IsReadOnly()
		{
			VerifyNotDisposed();
			return m_isReadOnly;
		}

		/// <summary>
		/// Clears the contents of this string.
		/// </summary>
		/// <exception cref="ObjectDisposedException">The string has already been disposed.</exception>
		/// <exception cref="InvalidOperationException">The string has been marked read-only.</exception>
		public void Clear()
		{
			VerifyNotDisposed();
			VerifyNotReadOnly();
			Array.Clear(m_buffer, 0, m_length);
			m_length = 0;
		}

		/// <summary>
		/// Creates a copy of this string.
		/// </summary>
		/// <returns>A copy.</returns>
		/// <exception cref="ObjectDisposedException">The string has already been disposed.</exception>
		public SecureString Copy()
		{
			VerifyNotDisposed();
			SecureString copy = new SecureString();
			copy.m_buffer = (char[]) m_buffer.Clone();
			copy.m_length = m_length;
			return copy;
		}

		/// <summary>
		/// Clears the contents of this string and destroys the backing buffer.
		/// </summary>
		public void Dispose()
		{
			if (m_buffer != null)
			{
				Array.Clear(m_buffer, 0, m_length);
				m_buffer = null;
			}
			m_length = 0;
			m_isDisposed = true;
		}

		internal string GetString()
		{
			return new string(m_buffer, 0, m_length);
		}

		private void VerifyNotReadOnly()
		{
			if (m_isReadOnly)
				throw new InvalidOperationException();
		}

		private void VerifyNotDisposed()
		{
			if (m_isDisposed)
				throw new ObjectDisposedException("SecureString");
		}

		int m_length;
		char[] m_buffer;
		bool m_isReadOnly;
		bool m_isDisposed;
	}
}
