using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using System;
using System.Security.Cryptography;
using static NetCoreIdentityPasswordHasher.Program;

namespace NetCoreIdentityPasswordHasher
{
    class Program
    {
        static void Main(string[] args)
        {
            //Console.WriteLine("Enter A PAssword And Press Enter!");
            Console.WriteLine("Press Enter To Go!");
            string p = Console.ReadLine();

            UserDto u = new UserDto()
            {
                Id = 1,
                Email = "abc123@rom.com",
                Password = "rumple234"
            };

            CryptoEconoLite scrip = new CryptoEconoLite();

            scrip.HashPassword(u, u.Password);


            scrip.VerifyHashedPassword(u, "dbPass", u.Password);

            Console.WriteLine("Press Any Key To Exit");
            Console.ReadLine();
        }
    }

    public class CryptoEconoLite : IPasswordHasher<UserDto>
    {
        private readonly RandomNumberGenerator _rng;
        private PasswordHasherCompatibilityMode _compatibilityMode;
        //private pwdType _pwdType;

        //First PassThrough Will Always Encrypt With V3 On Plain Text
        public string HashPassword(UserDto u, string db, string p)
        {
            _compatibilityMode = VerifyHashedPassword(u, db, p);
            if (_compatibilityMode == PasswordHasherCompatibilityMode.IdentityV2)
            {
                return Convert.ToBase64String(HashPasswordV2(p, _rng));
            }
            else
            {
                return Convert.ToBase64String(HashPasswordV3(p, _rng));
            }
            //return "";
        }

        public virtual PasswordVerificationResult VerifyHashedPassword(UserDto u, string db, string p, RandomNumberGenerator rng)
        {
            // Convert the stored Base64 password to bytes
            byte[] decodedHashedPassword = Convert.FromBase64String(db);

            // The first byte indicates the format of the stored hash
            switch (decodedHashedPassword[0])
            {
                case 0x00:
                    if (VerifyHashedPasswordV2(decodedHashedPassword, p))
                    {
                        // This is an old password hash format - the caller needs to rehash if we're not running in an older compat mode.
                        return (_compatibilityMode == PasswordHasherCompatibilityMode.IdentityV3)
                            ? PasswordVerificationResult.SuccessRehashNeeded
                            : PasswordVerificationResult.Success;
                    }
                    else
                    {
                        return PasswordVerificationResult.Failed;
                    }

                case 0x01:
                    if (VerifyHashedPasswordV3(decodedHashedPassword, p))
                    {
                        return PasswordVerificationResult.Success;
                    }
                    else
                    {
                        return PasswordVerificationResult.Failed;
                    }

                default:
                    return PasswordVerificationResult.Failed; // call this plain text as in dev failure
            }
        }

        public PasswordHasherCompatibilityMode VerifyHashedPasswordV2(string db, string p)
        {
            byte[] old = HashPasswordV2(db, _rng);
            byte[] input = HashPasswordV2(p, _rng);
            if (old.Equals(input))
                return PasswordHasherCompatibilityMode.IdentityV2;
            else
                return PasswordHasherCompatibilityMode.IdentityV3;
        }

        public PasswordHasherCompatibilityMode VerifyHashedPasswordV3(string db, string p)
        {
            string V3new = HashPasswordV3(p, _rng);
            if (db.Equals(V3new))
                return PasswordHasherCompatibilityMode.IdentityV3;
            else
                return PasswordHasherCompatibilityMode.IdentityV2;
        }

        private static byte[] HashPasswordV2(string password, RandomNumberGenerator rng)
        {
            const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
            const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
            const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
            const int SaltSize = 128 / 8; // 128 bits

            // Produce a version 2 text hash.
            byte[] salt = new byte[SaltSize];
            rng.GetBytes(salt);
            byte[] subkey = KeyDerivation.Pbkdf2(password, salt, Pbkdf2Prf, Pbkdf2IterCount, Pbkdf2SubkeyLength);

            var outputBytes = new byte[1 + SaltSize + Pbkdf2SubkeyLength];
            outputBytes[0] = 0x00; // format marker
            Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, Pbkdf2SubkeyLength);
            return outputBytes;
        }

        private static byte[] HashPasswordV3(string password, RandomNumberGenerator rng)
        {
            const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
            const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
            const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
            const int SaltSize = 128 / 8; // 128 bits

            // Produce a version 2 text hash.
            byte[] salt = new byte[SaltSize];
            rng.GetBytes(salt);
            byte[] subkey = KeyDerivation.Pbkdf2(password, salt, Pbkdf2Prf, Pbkdf2IterCount, Pbkdf2SubkeyLength);

            var outputBytes = new byte[1 + SaltSize + Pbkdf2SubkeyLength];
            outputBytes[0] = 0x00; // format marker
            Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, Pbkdf2SubkeyLength);
            return outputBytes;
        }
    }

    public interface IPasswordHasher<TUser> where TUser : class
    {
        string HashPassword(TUser user, string password);

        PasswordVerificationResult VerifyHashedPassword(
            TUser user, string hashedPassword, string providedPassword);
    }

    public class UserDto
    {
        public int Id;

        public string Email;

        public string Password;

        public string FirstName;

        public string LastName;

        public string MiddleName;

        public string PhoneNumber;

        //public EnumTypeDto Level;

        //public ApiFileDto Image;

        public bool? IsTest;
    }

    //public enum pwdType
    //{
    //    PlainText,
    //    V2,
    //    V3
    //}
}
