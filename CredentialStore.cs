//---------------------------------------------------------------
//  <copyright file="CredentialStore.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
//  </copyright>
//
//  <summary>
//  Credential store.
//  </summary>
//
//  History:     14-Feb-2018   pelotla     Created
//----------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Xml;
using System.Xml.Schema;

namespace VMware.Security.CredentialStore
{
    /// <summary>
    /// The credential store.
    /// </summary>
    internal class CredentialStore : ICredentialStore
    {
        #region Static members

        /// <summary>
        /// Sleep interval.
        /// </summary>
        private const int AcquireLockSleepIntervalMilliseconds = 500;

        /// <summary>
        /// Timeout value.
        /// </summary>
        private const int AcquireLockTimeoutSeconds = 20;

        /// <summary>
        /// Credential element.
        /// </summary>
        private const string CredentialElementXPath =
           "/" + ViCredentialsElementName + "/" + CredentialEntryElementName;

        /// <summary>
        /// Credential entry element.
        /// </summary>
        private const string CredentialEntryElementName = "passwordEntry";

        /// <summary>
        /// Credentials element.
        /// </summary>
        private const string CredentialsElementXPath =
           "/" + ViCredentialsElementName;

        /// <summary>
        /// Element Id.
        /// </summary>
        private const string IdElementName = "Id";

        /// <summary>
        /// Element name.
        /// </summary>
        private const string FriendlyNameElementName = "FriendlyName";

        /// <summary>
        /// Element name.
        /// </summary>
        private const string PasswordElementName = "Password";

        /// <summary>
        /// Element name.
        /// </summary>
        private const string UsernameElementName = "Username";

        /// <summary>
        /// Element name.
        /// </summary>
        private const string VersionElementName = "Version";

        /// <summary>
        /// Element name.
        /// </summary>
        private const string VersionElementXPath =
           "/" + ViCredentialsElementName + "/" + VersionElementName;

        /// <summary>
        /// Element name.
        /// </summary>
        private const string ViCredentialsElementName =
           "viCredentials";

        /// <summary>
        /// Default path.
        /// </summary>
        private static readonly string DefaultCredentialFilePath =
           @"%APPDATA%\VMware\credstore\vicredentials.xml";

        #endregion Static members

        #region Instance members

        /// <summary>
        /// Credential files path.
        /// </summary>
        private readonly string credentialFilePath;

        /// <summary>
        /// IDisposable usage.
        /// </summary>
        private bool objectAlreadyDisposed;

        #endregion Instance members

        /// <summary>
        /// dd
        /// </summary>
        static CredentialStore()
        {
            // Look into the configuration file for a default credentials file path
            string settingFromConfigFile = @"C:\Users\akag\Desktop\Cert\VmWareCred.xml";
            if (!string.IsNullOrEmpty(settingFromConfigFile))
            {
                DefaultCredentialFilePath = settingFromConfigFile;
            }
        }

        /// <summary>
        /// fff
        /// </summary>
        public CredentialStore()
           : this(
              new FileInfo(
                 Environment.ExpandEnvironmentVariables(
                    DefaultCredentialFilePath)))
        {
        }

        /// <summary>
        /// ff
        /// </summary>
        /// <param name="file"></param>
        public CredentialStore(FileInfo file)
        {
            this.credentialFilePath = file.FullName;

            if (!file.Directory.Exists)
            {
                // Create the dir only if it's the default one
                string defaultDir = Path.GetDirectoryName(
                   Environment.ExpandEnvironmentVariables(
                      DefaultCredentialFilePath));

                if (file.DirectoryName.Equals(
                   defaultDir, StringComparison.OrdinalIgnoreCase))
                {
                    file.Directory.Create();
                }
                else
                {
                    throw new DirectoryNotFoundException(file.DirectoryName);
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        ~CredentialStore()
        {
            this.Dispose(false);
        }

        #region ICredentialStore Members

        /// <summary>
        /// Stores the password for a given host and username. If a password
        /// already exists for that host and username, it is overwritten.
        /// </summary>
        /// <returns><code>true</code> if a password for this host and username
        /// did not already exist</returns>
        /// <exception cref="IOException"/>
        public bool AddPassword(string friendlyName, string id, string username, char[] password)
        {
            if (this.objectAlreadyDisposed)
            {
                throw new ObjectDisposedException("CredentialStore");
            }

            if (string.IsNullOrEmpty(friendlyName))
            {
                throw new ArgumentException("Friendly name cannot be empty.", "friendlyName");
            }

            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("User name cannot be empty.", "username");
            }

            if (password == null)
            {
                password = new char[0];
            }

            bool result;

            FileStream credentialsFile = null;

            try
            {
                if (!File.Exists(this.credentialFilePath))
                {
                    // Create the credentials file
                    using (
                       File.Create(
                          this.credentialFilePath,
                          8192,
                          FileOptions.RandomAccess,
                          GetSecuritySettings()))
                    {
                    }

                    credentialsFile = this.OpenFile(FileShare.None);
                    InitializeCredentialsDocument(credentialsFile);
                }
                else
                {
                    credentialsFile = this.OpenFile(FileShare.None);
                }

                XmlDocument credentialsXmlDocument =
                   LoadCredentialsDocument(credentialsFile);

                // Check if a password exists for this host
                XmlNode credentialNode =
                   GetCredentialNode(credentialsXmlDocument, friendlyName);

                result = credentialNode == null;

                if (credentialNode == null)
                {
                    credentialNode =
                       credentialsXmlDocument.CreateElement(
                          CredentialEntryElementName);
                }
                else
                {
                    credentialNode.RemoveAll();
                }

                FillCredentialNode(credentialNode, friendlyName, id, username, password);

                // Clear the password so it does not reside in memory in clear text
                Array.Clear(password, 0, password.Length);

                XmlNode credentialsNode =
                   credentialsXmlDocument.SelectSingleNode(
                      CredentialsElementXPath);

                credentialsNode.AppendChild(credentialNode);

                SaveCredentialsDocument(credentialsXmlDocument, credentialsFile);
            }
            finally
            {
                if (credentialsFile != null)
                {
                    credentialsFile.Dispose();
                }
            }

            return result;
        }

        /// <summary>
        /// Removes all passwords.
        /// </summary>
        /// <exception cref="IOException"/>
        public void ClearPasswords()
        {
            if (this.objectAlreadyDisposed)
            {
                throw new ObjectDisposedException("CredentialStore");
            }

            if (File.Exists(this.credentialFilePath))
            {
                FileStream credentialsFile = null;

                try
                {
                    credentialsFile = this.OpenFile(FileShare.None);

                    XmlDocument credentialsXmlDocument =
                       LoadCredentialsDocument(credentialsFile);

                    XmlNode credentialsNode =
                       credentialsXmlDocument.SelectSingleNode(
                          CredentialsElementXPath);

                    XmlNodeList credentialNodes =
                       credentialsXmlDocument.SelectNodes(CredentialElementXPath);

                    foreach (XmlNode credentialNode in credentialNodes)
                    {
                        credentialsNode.RemoveChild(credentialNode);
                    }

                    SaveCredentialsDocument(credentialsXmlDocument, credentialsFile);
                }
                finally
                {
                    if (credentialsFile != null)
                    {
                        credentialsFile.Dispose();
                    }
                }
            }
        }

        /// <summary>
        /// Returns all hosts that have entries in the credential store.
        /// </summary>
        /// <exception cref="IOException"/>
        public IEnumerable<string> GetFriendlyNames()
        {
            if (this.objectAlreadyDisposed)
            {
                throw new ObjectDisposedException("CredentialStore");
            }

            Dictionary<string, string> friendlyNames = new Dictionary<string, string>();

            if (File.Exists(this.credentialFilePath))
            {
                FileStream credentialsFile = null;

                try
                {
                    credentialsFile = this.OpenFile(FileShare.Read);

                    XmlDocument credentialsXmlDocument =
                       LoadCredentialsDocument(credentialsFile);

                    XmlNodeList credentialNodesList =
                       credentialsXmlDocument.SelectNodes(CredentialElementXPath);

                    foreach (XmlNode credentialNode in credentialNodesList)
                    {
                        if (IsValidPasswordEntryNode(credentialNode))
                        {
                            string friendlyName = credentialNode[FriendlyNameElementName].InnerText;
                            string lowerFriendlyName = friendlyName.ToLower();

                            // Add the item if it's not already in the list
                            if (!friendlyNames.ContainsKey(lowerFriendlyName))
                            {
                                friendlyNames[lowerFriendlyName] = friendlyName;
                            }
                        }
                    }
                }
                finally
                {
                    if (credentialsFile != null)
                    {
                        credentialsFile.Dispose();
                    }
                }
            }

            return friendlyNames.Keys;
        }

        /// <summary>
        /// Gets the password for a given host and username.
        /// </summary>
        /// <returns>The password, or <code>null</code> if none is found
        /// </returns>
        /// <exception cref="IOException"/>
        public char[] GetPassword(string host, string username)
        {
            if (this.objectAlreadyDisposed)
            {
                throw new ObjectDisposedException("CredentialStore");
            }

            char[] password = null;

            if (File.Exists(this.credentialFilePath))
            {
                FileStream credentialsFile = null;

                try
                {
                    credentialsFile = this.OpenFile(FileShare.Read);

                    XmlDocument credentialsXmlDocument =
                       LoadCredentialsDocument(credentialsFile);

                    password =
                       GetPasswordInternal(credentialsXmlDocument, host, username);
                }
                finally
                {
                    if (credentialsFile != null)
                    {
                        credentialsFile.Dispose();
                    }
                }
            }

            return password;
        }

        /// <summary>
        /// Returns all usernames that have passwords stored for a given host.
        /// </summary>
        /// <exception cref="IOException"/>
        public IEnumerable<string> GetUsernames(string host)
        {
            if (this.objectAlreadyDisposed)
            {
                throw new ObjectDisposedException("CredentialStore");
            }

            List<string> usernames = new List<string>();

            if (File.Exists(this.credentialFilePath))
            {
                FileStream credentialsFile = null;

                try
                {
                    credentialsFile = this.OpenFile(FileShare.Read);

                    XmlDocument credentialsXmlDocument =
                       LoadCredentialsDocument(credentialsFile);

                    XmlNodeList credentialNodes =
                       credentialsXmlDocument.SelectNodes(CredentialElementXPath);

                    foreach (XmlNode credentialNode in credentialNodes)
                    {
                        if (IsValidPasswordEntryNode(credentialNode))
                        {
                            string hostEntry =
                               credentialNode[FriendlyNameElementName].InnerText;

                            // Host comparison is case-insensitive
                            if (
                               hostEntry.Equals(
                                  host, StringComparison.OrdinalIgnoreCase))
                            {
                                usernames.Add(
                                   credentialNode[UsernameElementName].InnerText);
                            }
                        }
                    }
                }
                finally
                {
                    if (credentialsFile != null)
                    {
                        credentialsFile.Dispose();
                    }
                }
            }

            return usernames;
        }

        /// <summary>
        /// Removes the password for a given host and username. If no such
        /// password exists, this method has no effect.
        /// </summary>
        /// <returns><code>true</code> if the password existed and was removed
        /// </returns>
        /// <exception cref="IOException"/>
        public bool RemovePassword(string friendlyName, string username)
        {
            if (this.objectAlreadyDisposed)
            {
                throw new ObjectDisposedException("CredentialStore");
            }

            bool result = false;

            if (File.Exists(this.credentialFilePath))
            {
                FileStream credentialsFile = null;

                try
                {
                    credentialsFile = this.OpenFile(FileShare.None);

                    XmlDocument credentialsXmlDocument =
                       LoadCredentialsDocument(credentialsFile);

                    XmlNode nodeToRemove =
                       GetCredentialNode(credentialsXmlDocument, friendlyName);

                    result = nodeToRemove != null;

                    if (nodeToRemove != null)
                    {
                        XmlNode credentials =
                           credentialsXmlDocument.SelectSingleNode(
                              CredentialsElementXPath);

                        credentials.RemoveChild(nodeToRemove);

                        SaveCredentialsDocument(
                           credentialsXmlDocument, credentialsFile);
                    }
                }
                finally
                {
                    if (credentialsFile != null)
                    {
                        credentialsFile.Dispose();
                    }
                }
            }

            return result;
        }
        #region Disposing

        /// <summary>
        /// Closes this credential store and frees all resources associated with
        /// it. No further <code>ICredentialStore</code> methods may be invoked
        /// on this object.
        /// </summary>
        /// <exception cref="IOException"/>
        public void Close()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion Disposing

        #endregion ICredentialStore Members

        /// <summary>
        /// 
        /// </summary>
        /// <param name="element"></param>
        /// <param name="friendlyName"></param>
        /// <param name="id"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        private static void FillCredentialNode(
           XmlNode element,
           string friendlyName,
           string id,
           string username,
           char[] password)
        {
            XmlElement friendlyNameElement =
               element.OwnerDocument.CreateElement(FriendlyNameElementName);
            friendlyNameElement.InnerText = friendlyName;
            element.AppendChild(friendlyNameElement);

            XmlElement usernameElement =
               element.OwnerDocument.CreateElement(UsernameElementName);
            usernameElement.InnerText = username;
            element.AppendChild(usernameElement);

            XmlElement passElement =
               element.OwnerDocument.CreateElement(PasswordElementName);
            passElement.InnerText = ObfuscatePassword(password, friendlyName, username);
            element.AppendChild(passElement);

            XmlElement idElement =
               element.OwnerDocument.CreateElement(IdElementName);
            idElement.InnerText = id;
            element.AppendChild(idElement);
        }

        /// <summary>
        /// Returns the credential node which is holding password for this host and username
        /// </summary>
        /// <param name="credentialsXmlDocument"></param>
        /// <param name="friendlyName">The host - search is case-insensitive.</param>
        /// <param name="username">The username - search is case-sensitive.</param>
        /// <returns>The node if found, else 'null'.</returns>
        private static XmlNode GetCredentialNode(
           XmlDocument credentialsXmlDocument, string friendlyName, string username = null)
        {
            XmlNode result = null;

            XmlNodeList passwordEntryNodes =
               credentialsXmlDocument.SelectNodes(CredentialElementXPath);

            foreach (XmlNode passwordEntryNode in passwordEntryNodes)
            {
                if (IsValidPasswordEntryNode(passwordEntryNode))
                {
                    string hostEntry =
                       passwordEntryNode[FriendlyNameElementName].InnerText;

                    // Host comparison is case-insensitive
                    if (hostEntry.Equals(friendlyName, StringComparison.OrdinalIgnoreCase))
                    {
                        result = passwordEntryNode;
                        break;
                        ////string usernameEntry =
                        ////   passwordEntryNode[UsernameElementName].InnerText;

                        ////// Username comparison is case-sensitive
                        ////if (usernameEntry == username)
                        ////{
                        ////    result = passwordEntryNode;
                        ////    break;
                        ////}
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Returns a hash code for this string.
        /// The hash code for a String object is computed as:
        /// s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]
        /// using int arithmetic, where:
        /// s[i] is the <code>ith</code> character of the string,
        /// n is the length of the string, and ^ indicates exponentiation.
        /// (The hash value of the empty string is zero.)
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        private static int GetHashCode(string s)
        {
            if (s == null)
            {
                throw new ArgumentNullException("s");
            }

            int result = 0;

            for (int i = 0; i < s.Length; i++)
            {
                result = (31 * result) + s[i];
            }

            return result;
        }

        private static char[] GetPasswordInternal(
           XmlDocument credentialsXmlDocument, string host, string username)
        {
            char[] result = null;

            XmlNode credentialNode =
               GetCredentialNode(credentialsXmlDocument, host, username);
            if (credentialNode != null)
            {
                result = UnobfuscatePassword(
                   credentialNode[PasswordElementName].InnerText,
                   host,
                   username);
            }

            return result;
        }

        private static FileSecurity GetSecuritySettings()
        {
            FileSecurity security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(
               (FileSystemAccessRule)security.AccessRuleFactory(
                                         new NTAccount(
                                            WindowsIdentity.GetCurrent().Name),
                                         -1, // Full control
                                         false,
                                         InheritanceFlags.None,
                                         PropagationFlags.None,
                                         AccessControlType.Allow));
            return security;
        }

        private static void InitializeCredentialsDocument(Stream credentialsFile)
        {
            XmlDocument credentialsXmlDocument = new XmlDocument();

            credentialsXmlDocument.AppendChild(
               credentialsXmlDocument.CreateXmlDeclaration("1.0", "UTF-8", null));

            XmlElement credentialsElement =
               credentialsXmlDocument.CreateElement(ViCredentialsElementName);

            XmlElement versionElement =
               credentialsXmlDocument.CreateElement(VersionElementName);
            versionElement.InnerText = "1.0";

            credentialsElement.AppendChild(versionElement);

            credentialsXmlDocument.AppendChild(credentialsElement);

            SaveCredentialsDocument(credentialsXmlDocument, credentialsFile);
        }

        private static bool IsValidPasswordEntryNode(XmlNode node)
        {
            bool result = true;
            result &= node.Name == CredentialEntryElementName;
            result &= node[FriendlyNameElementName] != null;
            result &= node[UsernameElementName] != null;
            result &= node[PasswordElementName] != null;
            return result;
        }

        private static XmlDocument LoadCredentialsDocument(Stream credentialsFile)
        {
            XmlDocument credentialsXmlDocument = new XmlDocument();
            credentialsFile.Position = 0;
            credentialsXmlDocument.Load(credentialsFile);

            ValidateCredentialsDocument(credentialsXmlDocument);

            return credentialsXmlDocument;
        }

        /// <summary>
        /// A password is an arbitrary Unicode string.
        /// It is case sensitive, and may be empty.
        /// The value of the password entry is the password obfuscated
        /// with the following algorithm:
        /// 1. Let P be the UTF-8 encoding of the password.
        /// 2. Let N be the size of P in bytes.
        /// 3. Create a byte buffer B of size max(N+1, 128).
        /// 4. Copy P followed by a 0 into the beginning of B; fill the rest of B with random bytes.
        /// 5. Let H be a hash of host and username equal to the value of the Java expression:
        ///    (host+username).hashCode() % 256
        /// 6. XOR each element of B with H.
        /// 7. Base64-encode B and use the resulting string as the value of the entry.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="host"></param>
        /// <param name="username"></param>
        /// <returns></returns>
        private static string ObfuscatePassword(
           char[] password, string host, string username)
        {
            // 1. Let P be the UTF-8 encoding of the password.
            byte[] passUtf8Encoded = Encoding.UTF8.GetBytes(password);

            // 2. Let N be the size of P in bytes.
            int utf8EncodedLength = passUtf8Encoded.Length;

            // 3. Create a byte buffer B of size max(N+1, 128).
            byte[] paddedPassword =
               new byte[Math.Max(utf8EncodedLength + 1, 128)];

            // 4. Copy P followed by a 0 into the beginning of B;
            // fill the rest of B with random bytes.
            Array.Copy(passUtf8Encoded, paddedPassword, utf8EncodedLength);
            paddedPassword[utf8EncodedLength] = 0;
            if (paddedPassword.Length > utf8EncodedLength + 1)
            {
                Random random = new Random(DateTime.Now.Millisecond);
                byte[] pad =
                   new byte[paddedPassword.Length - (utf8EncodedLength + 1)];
                random.NextBytes(pad);
                Array.Copy(
                   pad, 0, paddedPassword, utf8EncodedLength + 1, pad.Length);
            }

            // 5. Let H be a hash of host and username...
            byte hash = (byte)(GetHashCode(host + username) % 256);

            // 6. XOR each element of B with H.
            for (int i = 0; i < paddedPassword.Length; i++)
            {
                paddedPassword[i] ^= hash;
            }

            // 7. Base64-encode B and use the resulting string as the value of the entry.
            string result = Convert.ToBase64String(paddedPassword);

            return result;
        }

        private static void SaveCredentialsDocument(
            XmlDocument credentialsXmlDocument,
            Stream credentialFile)
        {
            credentialFile.Position = 0;
            credentialFile.SetLength(0);
            credentialsXmlDocument.Save(credentialFile);
        }

        /// <summary>
        /// Un-obfuscates password obfuscated with the ObfuscatePassword method
        /// <seealso cref="ObfuscatePassword"/>
        /// </summary>
        private static char[] UnobfuscatePassword(
           string password, string host, string username)
        {
            byte[] paddedPasswordBytes = Convert.FromBase64String(password);

            byte hash = (byte)(GetHashCode(host + username) % 256);

            for (int i = 0; i < paddedPasswordBytes.Length; i++)
            {
                paddedPasswordBytes[i] ^= hash;
            }

            int passwordEndIndex = Array.IndexOf<byte>(paddedPasswordBytes, 0);

            if (passwordEndIndex < 0)
            {
                throw new FormatException(
                   "Invalid password format. " +
                   string.Format("Host: {0}, Username: {1}", host, username));
            }

            byte[] passwordBytes = new byte[passwordEndIndex];
            Array.Copy(paddedPasswordBytes, passwordBytes, passwordBytes.Length);

            char[] passChar = Encoding.UTF8.GetChars(passwordBytes);

            return passChar;
        }

        private static void ValidateCredentialsDocument(
                   XmlDocument credentialsXmlDocument)
        {
            bool valid = true;

            // Do we need to make more validation checks??
            // Maybe we should get a xml schema to validate against
            XmlDeclaration declaration =
               (XmlDeclaration)credentialsXmlDocument.FirstChild;
            valid &= declaration.Version.StartsWith("1.");
            valid &= declaration.Encoding == "UTF-8";

            valid &=
               credentialsXmlDocument.SelectSingleNode(CredentialsElementXPath) !=
                null;

            valid &=
               credentialsXmlDocument.SelectSingleNode(VersionElementXPath) !=
                null;

            if (!valid)
            {
                throw new XmlSchemaValidationException(
                   "The credentials .xml file is not well formed.");
            }
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Clean managed resources
            }

            // Clean unmanaged resources
            this.objectAlreadyDisposed = true;
        }

        /// <summary>
        /// Tries to open the credentials file using the specified file sharing.
        /// </summary>
        /// <exception cref="TimeoutException">
        /// Thrown if the method cannot open the file in
        /// AcquireLockTimeoutSeconds seconds.
        /// </exception>
        private FileStream OpenFile(FileShare fileShare)
        {
            FileStream result;

            DateTime maxWaitTime =
               DateTime.Now.AddSeconds(AcquireLockTimeoutSeconds);

            while (true)
            {
                try
                {
                    if (DateTime.Now > maxWaitTime)
                    {
                        throw new TimeoutException(
                           "Could not acquire access to credential file: " +
                           this.credentialFilePath +
                           ". Another process/thread has locked the file.");
                    }

                    result =
                       File.Open(
                          this.credentialFilePath,
                          FileMode.Open,
                          FileAccess.ReadWrite,
                          fileShare);

                    break;
                }
                catch (UnauthorizedAccessException)
                {
                    // Wait for a while and try to lock the file again
                    Thread.Sleep(AcquireLockSleepIntervalMilliseconds);
                }
            }

            return result;
        }
    }
}