using System;
using System.Text;

namespace HashString {
    class Program {

        private static ulong GetHash(string s) {
            ulong num1 = 14695981039346656037;
            try {
                foreach (byte num2 in Encoding.UTF8.GetBytes(s)) {
                    num1 ^= (ulong)num2;
                    num1 *= 1099511628211UL;
                }
            } catch {
            }
            return num1 ^ 6605813339339102567UL;
        }

        static int Main(string[] args) {
            ulong stringHash;

            if (args.Length == 0 || args.Length > 1) {
                System.Console.WriteLine("HashString.exe [StringToHash]");
                return 1;
            }
            stringHash = GetHash(args[0]);

            Console.WriteLine($"The hash of {args[0]} is: {stringHash}");
            return 0;
        }
    }
}
