namespace FinalSecurity
{
    internal class Program
    {
        private static String all_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static String small_alphabet = "abcdefghijklmnopqrstuvwxyz";
        private static String capital_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static void Main(string[] args)
        {

            Console.WriteLine("Choose a Cipher:");
            Console.WriteLine("1. Caesar Cipher");
            Console.WriteLine("2. Vigenere Cipher");
            Console.WriteLine("3. Affine Cipher");


            Console.Write("Enter your choice (1 or 2 or 3): ");
            int choice = int.Parse(Console.ReadLine());

            switch (choice)
            {
                case 1:
                    CaesarCipher();
                    break;

                case 2:
                    VigenereCipher();
                    break;

                case 3:
                    AffineCipher();
                    break;

                default:
                    Console.WriteLine("Invalid choice. Please enter 1 or 2 or 3");
                    break;
            }
        }
        static void CaesarCipher()
        {
            Console.WriteLine("\nCeaser Cipher");

            Console.Write("Enter the text to encrypt: ");
            string plainText = Console.ReadLine();

            Console.Write("Enter the shift value (letter or integer): ");
            string inputKey = Console.ReadLine();

            int shift;
            if (int.TryParse(inputKey, out shift))
            {
                // If the inputKey is a valid integer, proceed with encryption
                string encryptedText = CaesarEncrypt(plainText, shift);
                string decryptedText = CaesarDecrypt(encryptedText, shift);

                Console.WriteLine($"Encrypted Text: {encryptedText}");
                Console.WriteLine($"Decrypted Text: {decryptedText}");
            }
            else if (inputKey.Length == 1 && char.IsLetter(inputKey[0]))
            {
                // If the inputKey is a single letter, convert it to its own number in the group from 0 to 25
                int letterShift;
                if (char.IsUpper(inputKey[0]))
                {
                    letterShift = inputKey[0] - 'A';
                }
                else
                {
                    letterShift = inputKey[0] - 'a';
                }
                string encryptedText = CaesarEncrypt(plainText, letterShift);
                string decryptedText = CaesarDecrypt(encryptedText, letterShift);

                Console.WriteLine($"Encrypted Text: {encryptedText}");
                Console.WriteLine($"Decrypted Text: {decryptedText}");
            }
            else
            {
                Console.WriteLine("Invalid key. Please enter a valid letter or integer key.");
            }
        }

        static void VigenereCipher()
        {
            Console.WriteLine("\nVigenere Cipher");

            Console.Write("Enter the plaintext: ");
            string vigenerePlaintext = Console.ReadLine();
            Console.Write("Enter the key (must be letter): ");
            string vigenereKey = Console.ReadLine();

            string vigenereCiphertext = EncryptVigenere(vigenerePlaintext, vigenereKey);
            string vigenereDecryptedText = DecryptVigenere(vigenereCiphertext, vigenereKey);
            //string vigenereDecryptedText = DecryptVigenere(vigenerePlaintext, vigenereKey);

            Console.WriteLine($"\nPlaintext: {vigenerePlaintext}");
            Console.WriteLine($"Key: {vigenereKey}");
            Console.WriteLine($"Encrypted Text: {vigenereCiphertext}");
            Console.WriteLine($"Decrypted Text: {vigenereDecryptedText}");
        }

        static void AffineCipher()
        {
            Console.WriteLine("\nAffine Cipher");

            Console.Write("Enter the plaintext: ");
            string plainText = Console.ReadLine().ToUpper();

            Console.Write("Enter the value for 'a': ");
            int a = int.Parse(Console.ReadLine());

            Console.Write("Enter the value for 'b': ");
            int b = int.Parse(Console.ReadLine());

            if (GCD(a, 26) == 1)
            {
                //ModuloInverse
                Console.WriteLine("mod = " + ModuloInverse(a, 26));
                Console.WriteLine($"The gcd = {GCD(a, 26)}, so the affine cipher can work");
                string cipherText = AffineEncrypt(plainText, a, b);
                string decryptedText = AffineDecrypt(cipherText, a, b);

                Console.WriteLine("\nEncrypted Text: " + cipherText);
                Console.WriteLine("Decrypted Text: " + decryptedText);
            }
            else
            {
                Console.WriteLine($"The gcd = {GCD(a, 26)}, so the affine cipher can't work (gcd must = 1)");
            }
        }

        //_________________________________methods for encrypt and decrypt_________________________________

        //ceaser:
        //war
        static string CaesarEncrypt(string text, int shift)
        {
            char[] result = text.ToCharArray();

            for (int i = 0; i < result.Length; i++)
            {
                if (char.IsLetter(result[i]))
                {
                    char baseChar = char.IsUpper(result[i]) ? 'A' : 'a';
                    // Adjust the calculation to handle negative shifts
                    result[i] = (char)((result[i] - baseChar + shift + 26) % 26 + baseChar);//i
                }
            }

            return new string(result);
        }

        static string CaesarDecrypt(string text, int shift)
        {
            // Decryption is essentially encryption with the opposite shift
            return CaesarEncrypt(text, 26 - shift);
        }

        //**********************************************************************************************************************************************

        //veginere:
        static string EncryptVigenere(string plaintext, string key)
        {
            char[] allAlpha = all_alphabet.ToCharArray();
            char[] sAlpha = small_alphabet.ToCharArray();
            char[] cAlpha = capital_alphabet.ToCharArray();
            char[] encryptedText = plaintext.ToCharArray();
            //use it to make the length of key== plaintext , and then use forloop to convert the letters of plaintext to key
            char[] keyArr = plaintext.ToCharArray();

          
        
                       int j = 0;
            // when length of key less than plaintext
            for (int i = 0; i < plaintext.Length; i++)
            {
                if (i >= key.Length)
                {
                    keyArr[i] = key[j];
                    j++;
                }
                else
                {
                    keyArr[i] = key[i];
                }
            }

            for (int i = 0; i < plaintext.Length; i++)
            {
                // Ignore non-alphabetic characters
                if (!char.IsLetter(plaintext[i]))
                {
                    encryptedText[i] = plaintext[i];
                    continue;
                }

                int shift;
                if (char.IsUpper(encryptedText[i]) && char.IsUpper(keyArr[i]))  // plaintext and key are upper
                {
                    shift = keyArr[i] - 'A';
                    encryptedText[i] = cAlpha[(plaintext[i] - 'A' + shift) % 26];
                }

                else if (char.IsLower(encryptedText[i]) && char.IsLower(keyArr[i]))  // plaintext and key are lower
                {
                    shift = keyArr[i] - 'a';
                    encryptedText[i] = sAlpha[(plaintext[i] - 'a' + shift) % 26];
                }
                else  // plaintext and key are mix (upper and lower)
                {
                    shift = keyArr[i] - 'a';
                    encryptedText[i] = allAlpha[(plaintext[i] - 'A' + shift + 26) % 52];
                }

            }

            return new string(encryptedText);
        }

        static string DecryptVigenere(string ciphertext, string key)
        {
            char[] allAlpha = all_alphabet.ToCharArray();
            char[] sAlpha = small_alphabet.ToCharArray();
            char[] cAlpha = capital_alphabet.ToCharArray();
            char[] decryptedText = ciphertext.ToCharArray();
            //use it to make the length of key==ciphertext , and then use forloop to convert the letters of ciphertext to key
            char[] keyArr = ciphertext.ToCharArray();

            int j = 0;
            // when length of key less than ciphertext
            for (int i = 0; i < ciphertext.Length; i++)
            {
                if (i >= key.Length)
                {
                    keyArr[i] = key[j];
                    j++;
                }
                else
                {
                    keyArr[i] = key[i];
                }
            }

            int capital = 0; // counter for capital litters in ciphertext
            int small = 0;  // counter for small litters in ciphertext

            for (int i = 0; i < ciphertext.Length; i++)
            {
                if (char.IsUpper(decryptedText[i])) capital++;
                else small++;
            }

            for (int i = 0; i < ciphertext.Length; i++)
            {
                // Ignore non-alphabetic characters
                if (!char.IsLetter(ciphertext[i]))
                {
                    decryptedText[i] = ciphertext[i];
                    continue;
                }

                int shift;
                if (char.IsUpper(decryptedText[i]))  // ciphertext upper
                {
                    if (char.IsUpper(keyArr[i]))  // key upper
                    {
                        shift = keyArr[i] - 'A';
                        if (small == 0) // it means : all letters in ciphertext are cpitals
                        {
                            decryptedText[i] = cAlpha[(ciphertext[i] - 'A' - shift + 26) % 26]; // here I add 26 because the result of Subtraction can be negative
                        }
                        else  // it means : letters in ciphertext are cpitals and small
                        {
                            decryptedText[i] = allAlpha[(ciphertext[i] - 'A' - shift + 52) % 52]; // here I add 52 because the result of Subtraction can be negative 
                        }
                    }
                    else  // key lower
                    {
                        shift = keyArr[i] - 'a';
                        decryptedText[i] = allAlpha[(ciphertext[i] - 'A' - shift + 26 + 52) % 52]; // here I add 52 because the result of Subtraction can be negative
                    }

                }

                else  // ciphertext lower
                {
                    if (char.IsLower(keyArr[i]))  // key lower
                    {
                        shift = keyArr[i] - 'a';
                        if (capital == 0) // it means : all letters in ciphertext are small
                        {
                            decryptedText[i] = sAlpha[(ciphertext[i] - 'a' - shift + 26) % 26]; // here I add 26 because the result of Subtraction can be negative  
                        }
                        else  // it means : letters in ciphertext are cpitals and small
                        {
                            decryptedText[i] = allAlpha[(ciphertext[i] - 'a' - shift + 52) % 52]; // here I add 52 because the result of Subtraction can be negative
                        }
                    }
                    else  // key upper
                    {
                        shift = keyArr[i] - 'A';
                        decryptedText[i] = allAlpha[(ciphertext[i] - 'a' - shift + 26 + 52) % 52]; // here I add 52 because the result of Subtraction can be negative
                    }

                }
            }

            return new string(decryptedText);
        }

        //**********************************************************************************************************************************************

        //affine:
        static int GCD(int a, int n)
        {
            if (a == 0)
            {
                return n;
            }
            return GCD(n % a, a);
        }

        static int ModuloInverse(int a, int m)
        {
            a = a % m;
            for (int x = 1; x < m; x++)
                if ((a * x) % m == 1)
                    return x;
            return 1;
        }

        static string AffineEncrypt(string plainText, int a, int b)
        {
            string cipherText = "";
            foreach (char character in plainText)
            {
                if (char.IsLetter(character))
                {
                    int x = char.IsUpper(character) ? 'A' : 'a';

                    //The result is then cast to char and added to the cipherText
                    cipherText += (char)(((a * (character - x) + b) % 26) + x);
                }
                //Non-letter Characters:
                else
                {
                    //directly appended to the cipherText without any encryption.
                    cipherText += character;
                }
            }
            return cipherText;
        }

        static string AffineDecrypt(string cipherText, int a, int b)
        {
            int aInverse = ModuloInverse(a, 26);
            string plainText = "";
            foreach (char character in cipherText)
            {
                if (char.IsLetter(character))
                {
                    // it determines the base character('A' or 'a') based on the case of the character.
                    int x = char.IsUpper(character) ? 'A' : 'a';
                    int result = aInverse * (character - x - b + 26) % 26;
                    plainText += (char)(result + x);
                }
                else
                {
                    plainText += character;
                }
            }
            return plainText;
        }
    }
}


   