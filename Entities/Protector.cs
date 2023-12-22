using Microsoft.EntityFrameworkCore;
using backend.Data;
using static Azure.Core.HttpHeader;
using System.Security.Cryptography;
using System.Text;
using backend.Models;
using backend.HRMSSMS;

namespace backend.Entities
{
    public class Protector
    {
        public static bool SystemResetPassword(string usr)
        {
            int usrid = int.Parse(usr);
            try
            {
                // Provide the DbContextOptions parameter when creating the context
                var options = new DbContextOptionsBuilder<EmployeeAPIDbContext>()
                    .UseSqlServer("YourConnectionStringHere")
                    .Options;

                using (var dbcontext = new EmployeeAPIDbContext(options))
                {
                    var query = (from l in dbcontext.LoginCreds
                                 where l.EmpCode == usrid
                                 select l).First();

                    string pwd = GenerateRandomPassword();
                    string encPwd = Hashsh(pwd, query.Salt, (int)query.Algo);

                    LoginCred lCred = dbcontext.LoginCreds.Single(u => u.EmpCode == usrid);
                    lCred.loginattempts = (byte)0;
                    lCred.Password = encPwd;
                    lCred.isactive = 'R';
                    lCred.ModifiedOn = Common.DateTimeNow();

                    dbcontext.SaveChanges();

                    HRMSEmail.HRMSEmail.SendResetPasswordEmail(usr, pwd);

                    // Assuming GetUserFromDB is a static method in the Common class
                   

                    return true;
                }
            }
            catch (Exception ex)
            {
                // Handle the exception or log it
                return false;
            }
        }




        public static String GenerateRandomString(int pSize)
        {
            char[] chars = new char[36];
            chars = "A8BC4DEFG3HI5JK1LMNOPQ6RST9UV1WX0YZ7".ToCharArray();
            byte[] data = new byte[1];

            {
                RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider();
                crypto.GetNonZeroBytes(data);
                data = new byte[pSize - 1];
                crypto.GetNonZeroBytes(data);
                crypto = null;
            }
            StringBuilder result = new StringBuilder(pSize - 1);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            Random r = new Random();
            int rn = r.Next(0, 9);
            result.Append(rn);
            return result.ToString();
        }

        public static String GenerateRandomPassword()
        {
            String pwd = GenerateRandomString(10);
            return pwd;
        }

        public static String GenerateRandomOTP()
        {
            String strOpt = GenerateRandomString(4);
            return strOpt;
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


        private static string Hashsh(string toEncrypt, string mth, int typ)
        {
            byte[] keyArray;
            HashAlgorithm hash = GetHashAlgo(typ);
            byte[] plainTextWithSaltBytes = Encoding.UTF8.GetBytes(toEncrypt + mth);
            keyArray = hash.ComputeHash(plainTextWithSaltBytes);
            return Convert.ToBase64String(keyArray);
        }

        internal static String GenerateSaltKey(int maxSize)
        {
            char[] chars = new char[44];
            chars = "A8C@B4DEF3HI#G5JK1%LMNO!PQ6*RST9U$V1X^W0Y~Z7".ToCharArray();
            byte[] data = new byte[1];

            {
                RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider();
                crypto.GetNonZeroBytes(data);
                data = new byte[maxSize];
                crypto.GetNonZeroBytes(data);
                crypto = null;
            }
            StringBuilder result = new StringBuilder(maxSize);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }


        public static void CreatePasswordHash(ref LoginCred lc, String pwd)
        {
            // randomly generate type & salt.
            Random rnd = new Random();
            int rndInt = rnd.Next(1, 5);
            lc.Algo = (byte)rndInt;
            lc.Salt = GenerateSaltKey(16);
            lc.Password = Hashsh(pwd, lc.Salt, rndInt);
        }


        public static bool PasswordMatch(String uPwd, String dbPwd, String dbMth, short dbAlgo)
        {
            try
            {
                String hshd = Hashsh(uPwd, dbMth, dbAlgo);
                if (hshd.Equals(dbPwd))
                    return true;
                return false;   //Change this later.
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
                return false;
            }
        }

        public static String GeneratePwdSalt(ref LoginCred lc)
        {
            try
            {
                String pwd = Entities.Protector.GenerateRandomPassword();
                CreatePasswordHash(ref lc, pwd);
                return pwd;
            }
            catch (Exception ex)
            {
                return "";
            }
        }
    }
}