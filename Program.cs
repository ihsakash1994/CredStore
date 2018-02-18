using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VMware.Security.CredentialStore;

namespace ConsoleApp2
{
    /// <summary>
    /// Wrapper around the DR setup framework.
    /// </summary>
    public static class SetupHelper
    {
        /// <summary>
        /// ASR logging folder.
        /// </summary>
        private const string LogFolder = "ASRSetupLogs";

        /// <summary>
        /// Setup log file name.
        /// </summary>
        private static string LogFileName = "Onboarding-DRSetup.log";


        /// <summary>
        /// Initializes static members of the <see cref="SetupHelper" /> class.
        /// </summary>
        static SetupHelper()
        {
            LogFileName = "c";
        }

        public static void print()
        {
            Console.WriteLine(LogFileName);
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            CredentialStore x = CredentialStoreFactory.CreateCredentialStore() as CredentialStore;
            char[] pass = { 'p', 'a', 's', 's' };
            x.AddPassword("Cred-2", Guid.NewGuid().ToString(), "User", pass);
        }
    }
}
