using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NeoWalletDump
{
    class Program
    {
        public class Account
        {
            public byte[] PrivateKeyEncrypted { get; set; }
            public byte[] PublicKeyHash { get; set; }
        }

        public class Address
        {
            public byte[] ScriptHash { get; set; }
        }

        class Contract
        {
            public byte[] RawData { get; set; }
            public byte[] ScriptHash { get; set; }
            public byte[] PublicKeyHash { get; set; }
            public Account Account { get; set; }
            public Address Address { get; set; }
        }

        class Key
        {
            public string Name { get; set; }
            public byte[] Value { get; set; }
        }

        class WalletDataContext : DbContext
        {
            public DbSet<Account> Accounts { get; set; }
            public DbSet<Address> Addresses { get; set; }
            public DbSet<Contract> Contracts { get; set; }
            public DbSet<Key> Keys { get; set; }

            private readonly string filename;

            public WalletDataContext(string filename)
            {
                this.filename = filename;
            }

            protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
            {
                base.OnConfiguring(optionsBuilder);
                SqliteConnectionStringBuilder sb = new SqliteConnectionStringBuilder();
                sb.DataSource = filename;
                optionsBuilder.UseSqlite(sb.ToString());
            }

            protected override void OnModelCreating(ModelBuilder modelBuilder)
            {
                base.OnModelCreating(modelBuilder);
                modelBuilder.Entity<Account>().ToTable(nameof(Account));
                modelBuilder.Entity<Account>().HasKey(p => p.PublicKeyHash);
                modelBuilder.Entity<Account>().Property(p => p.PrivateKeyEncrypted).HasColumnType("VarBinary").HasMaxLength(96).IsRequired();
                modelBuilder.Entity<Account>().Property(p => p.PublicKeyHash).HasColumnType("Binary").HasMaxLength(20).IsRequired();
                modelBuilder.Entity<Address>().ToTable(nameof(Address));
                modelBuilder.Entity<Address>().HasKey(p => p.ScriptHash);
                modelBuilder.Entity<Address>().Property(p => p.ScriptHash).HasColumnType("Binary").HasMaxLength(20).IsRequired();
                modelBuilder.Entity<Contract>().ToTable(nameof(Contract));
                modelBuilder.Entity<Contract>().HasKey(p => p.ScriptHash);
                modelBuilder.Entity<Contract>().HasIndex(p => p.PublicKeyHash);
                modelBuilder.Entity<Contract>().HasOne(p => p.Account).WithMany().HasForeignKey(p => p.PublicKeyHash).OnDelete(DeleteBehavior.Cascade);
                modelBuilder.Entity<Contract>().HasOne(p => p.Address).WithMany().HasForeignKey(p => p.ScriptHash).OnDelete(DeleteBehavior.Cascade);
                modelBuilder.Entity<Contract>().Property(p => p.RawData).HasColumnType("VarBinary").IsRequired();
                modelBuilder.Entity<Contract>().Property(p => p.ScriptHash).HasColumnType("Binary").HasMaxLength(20).IsRequired();
                modelBuilder.Entity<Contract>().Property(p => p.PublicKeyHash).HasColumnType("Binary").HasMaxLength(20).IsRequired();
                modelBuilder.Entity<Key>().ToTable(nameof(Key));
                modelBuilder.Entity<Key>().HasKey(p => p.Name);
                modelBuilder.Entity<Key>().Property(p => p.Name).HasColumnType("VarChar").HasMaxLength(20).IsRequired();
                modelBuilder.Entity<Key>().Property(p => p.Value).HasColumnType("VarBinary").IsRequired();
            }
        }


        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: NeoWalletDump *.db3 wallet-password");
                Console.WriteLine("ex)NeoWalletDump foo.db3 Password1");
                return;
            }
            var db3Path = args[0];
            byte[] passwordKey = args[1].ToAesKey();

            SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_e_sqlite3());

            using (WalletDataContext ctx = new WalletDataContext(db3Path))
            {
                {
                    WriteTableName("Key");
                    var PasswordHash = ReadSqlitItem(ctx, "PasswordHash");
                    var IV = ReadSqlitItem(ctx, "IV");
                    var MasterKey = ReadSqlitItem(ctx, "MasterKey").AesDecrypt(passwordKey, IV);

                    DumpSqliteColumn(nameof(PasswordHash), PasswordHash);
                    DumpSqliteColumn(nameof(IV), IV);
                    DumpSqliteColumn(nameof(MasterKey), MasterKey);
                }
                {
                    WriteTableName("Account");
                    var PublicKeyHash = ctx.Accounts.SingleOrDefault().PublicKeyHash;
                    DumpSqliteColumn(nameof(PublicKeyHash), PublicKeyHash);
                    var PrivateKeyEncrypted = ctx.Accounts.SingleOrDefault().PrivateKeyEncrypted;
                    DumpSqliteColumn(nameof(PrivateKeyEncrypted), PrivateKeyEncrypted);
                }
                {
                    WriteTableName("Address");
                    var ScriptHash = ctx.Addresses.SingleOrDefault().ScriptHash;
                    DumpSqliteColumn(nameof(ScriptHash), ScriptHash);
                }
                {
                    WriteTableName("Contract");
                    var ScriptHash = ctx.Contracts.SingleOrDefault().ScriptHash;
                    DumpSqliteColumn(nameof(ScriptHash), ScriptHash);
                    var PublicKeyHash = ctx.Contracts.SingleOrDefault().PublicKeyHash;
                    DumpSqliteColumn(nameof(PublicKeyHash), PublicKeyHash);
                    var RawData = ctx.Contracts.SingleOrDefault().RawData;
                    DumpSqliteColumn(nameof(RawData), RawData);
                }
            }
        }

        private static void WriteTableName(string name)
        {
            Console.WriteLine($"<<{name} Table>>");
        }

        private static void DumpSqliteColumn(string name, byte[] bytes)
        {
            Console.WriteLine(name + ")");
            Console.WriteLine("Length:"+bytes.Length);
            var utf8 = Encoding.UTF8.GetString(bytes);
            Console.WriteLine("UTF8: " + utf8); // Todo: It doesn't work sometimes. Maybe because of control code such as BS in utf8
            var hex = BitConverter.ToString(bytes).Replace("-", string.Empty);
            Console.WriteLine("HEX: 0x" + hex);
            Console.WriteLine();
        }

        private static byte[] ReadSqlitItem(WalletDataContext ctx, string name)
        {
            byte[] ret = ctx.Keys.FirstOrDefault(p => p.Name == name)?.Value;
            //Console.WriteLine(name);
            //Console.WriteLine("BitConverter:" + BitConverter.ToString(ret));
            //Console.WriteLine("ASCII:" + Encoding.ASCII.GetString(ret));
            //Console.WriteLine();

            return ret;
        }
    }

    static public class Helper
    {
        public static byte[] ToAesKey(this string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] passwordHash = sha256.ComputeHash(passwordBytes);
                byte[] passwordHash2 = sha256.ComputeHash(passwordHash);
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
                Array.Clear(passwordHash, 0, passwordHash.Length);
                return passwordHash2;
            }
        }

        public static byte[] AesDecrypt(this byte[] data, byte[] key, byte[] iv)
        {
            if (data == null || key == null || iv == null) throw new ArgumentNullException();
            if (data.Length % 16 != 0 || key.Length != 32 || iv.Length != 16) throw new ArgumentException();
            using (Aes aes = Aes.Create())
            {
                aes.Padding = PaddingMode.None;
                using (ICryptoTransform decryptor = aes.CreateDecryptor(key, iv))
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public static byte[] AesEncrypt(this byte[] data, byte[] key, byte[] iv)
        {
            if (data == null || key == null || iv == null) throw new ArgumentNullException();
            if (data.Length % 16 != 0 || key.Length != 32 || iv.Length != 16) throw new ArgumentException();
            using (Aes aes = Aes.Create())
            {
                aes.Padding = PaddingMode.None;
                using (ICryptoTransform encryptor = aes.CreateEncryptor(key, iv))
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }
    }
}
