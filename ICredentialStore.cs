﻿//---------------------------------------------------------------
//  <copyright file="ICredentialStore.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
//  </copyright>
//
//  <summary>
//  Credential store interface.
//  </summary>
//
//  History:     14-Feb-2018   pelotla     Created
//----------------------------------------------------------------

using System.Collections.Generic;

namespace VMware.Security.CredentialStore
{
    /// <summary>
    /// A credential store.
    /// <para />
    /// For each method with a <code>host</code> parameter, the host may be
    /// specified as a DNS domain name, an <code>IPv4</code> address, or an <code>IPv6</code>
    /// address.
    /// When looking up a username or password, the host must be specified in
    /// the same manner (DNS, <code>IPv4</code>, or <code>IPv6</code>) as when it was stored.
    /// <para />
    /// Each method that reads from or updates the store acquires a lock on the
    /// store for the duration of the method call, blocking if necessary to do
    /// so. Any attempt to acquire a conflicting lock (by this process or
    /// another process) will block.
    /// <para />
    /// Passwords are stored as char[] instead of strings to allow immediately
    /// erasing them when no longer needed. To erase a password, overwrite the
    /// char array contents before releasing it for garbage collection.
    /// <seealso cref="CredentialStoreFactory"/>
    /// </summary>
    public interface ICredentialStore
    {
        /// <summary>
        /// Gets the password for a given host and username.
        /// </summary>
        /// <param name="host">Host name.</param>
        /// <param name="username">User name.</param>
        /// <returns>The password, or <code>null</code> if none is found.
        /// </returns>
        char[] GetPassword(string host, string username);

        /// <summary>
        /// Stores the password for a given host and username. If a password
        /// already exists for that host and username, it is overwritten.
        /// </summary>
        /// <param name="friendlyName">Friendly name.</param>
        /// <param name="id">Credential id.</param>
        /// <param name="username">User name.</param>
        /// <param name="password">The password.</param>
        /// <returns><code>true</code> if a password for this host and username
        /// did not already exist.</returns>
        bool AddPassword(string friendlyName, string id, string username, char[] password);

        /// <summary>
        /// Removes the password for a given host and username. If no such
        /// password exists, this method has no effect.
        /// </summary>
        /// <param name="host">Host name.</param>
        /// <param name="username">User name.</param>
        /// <returns><code>true</code> if the password existed and was removed.
        /// </returns>
        bool RemovePassword(string host, string username);

        /// <summary>
        /// Removes all passwords.
        /// </summary>
        void ClearPasswords();

        /// <summary>
        /// Returns all hosts that have entries in the credential store.
        /// </summary>
        /// <returns>Host names.</returns>
        IEnumerable<string> GetFriendlyNames();

        /// <summary>
        /// Returns all usernames that have passwords stored for a given host.
        /// </summary>
        /// <param name="host">Host name.</param>
        /// <returns>The user names.</returns>
        IEnumerable<string> GetUsernames(string host);

        /// <summary>
        /// Closes this credential store and frees all resources associated with
        /// it. No further <code>ICredentialStore</code> methods may be invoked
        /// on this object.
        /// </summary>
        void Close();
    }
}