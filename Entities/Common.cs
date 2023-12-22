using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using backend.Data;
using backend.Models;

namespace backend.Entities
{
    public class Common
    {
        private static EmployeeAPIDbContext dbContext;

        // Property with a private setter
        public static EmployeeAPIDbContext DbContext
        {
            get
            {
                if (dbContext == null)
                {
                    // Log an error or throw an exception if dbContext is null
                }
                return dbContext;
            }
            private set { dbContext = value; }
        }

        // A method to set the dbContext during application startup
        public static void Initialize(EmployeeAPIDbContext context)
        {
            if (dbContext == null)
            {
                dbContext = context;
            }
            // Optionally, log an error or throw an exception if dbContext is already set
        }

        // Other methods in your Common class

        public static LoginCred GetLoginCred(int empCode)
        {
            try
            {
                return DbContext.LoginCreds.SingleOrDefault(l => l.EmpCode == empCode);
            }
            catch (Exception ex)
            {
                // Handle the exception or log it
                Console.WriteLine($"Error in GetLoginCred: {ex.Message}");
                return null; // Or throw an exception if appropriate
            }
        }

        public static DateTime DateTimeNow()
        {
            return DateTime.Now;
        }

        public static bool PasswordMatch(string uPwd, string dbPwd, string dbSalt, int dbAlgo)
        {
            try
            {
                string hashedPassword = Hashsh(uPwd, dbSalt, dbAlgo);
                return hashedPassword.Equals(dbPwd);
            }
            catch (Exception ex)
            {
                // Handle the exception or log it
                Console.WriteLine($"Error in PasswordMatch: {ex.Message}");
                return false;
            }
        }

        private static string Hashsh(string toEncrypt, string mth, int typ)
        {
            byte[] keyArray;
            HashAlgorithm hash = GetHashAlgo(typ);
            byte[] plainTextWithSaltBytes = Encoding.UTF8.GetBytes(toEncrypt + mth);
            keyArray = hash.ComputeHash(plainTextWithSaltBytes);
            return Convert.ToBase64String(keyArray);
        }

        private static HashAlgorithm GetHashAlgo(int typ)
        {
            switch (typ)
            {
                case 1: return new SHA1Managed();
                case 2: return new SHA256Managed();
                case 3: return new SHA384Managed();
                case 4: return new SHA512Managed();
                default: return new MD5CryptoServiceProvider();
            }
        }
    }
}
