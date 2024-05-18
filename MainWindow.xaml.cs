using System.Text;
using System.Windows;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Windows.Input;
using System.Windows.Controls;

namespace AES_Project
{
    public partial class MainWindow : Window
    {
        private const string FilePath = "C:\\Users\\batuh\\source\\repos\\AES_Project\\DataStorage\\password.txt";
        static readonly char[] asciiChars = Enumerable.Range(0x20, 0x7E - 0x20 + 1).Select(i => (char)i).ToArray();
        public string FoundSalt;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void PlaceHolder(object sender, MouseButtonEventArgs e)
        {
            TextBox textBox = (TextBox)sender;

            if (textBox.Text == "")
            {
                textBox.Text = textBox.Tag.ToString();
            }
            else if (textBox.Text == textBox.Tag.ToString())
            {
                textBox.Text = "";
            }

        }


        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string inputText = InputTextBox.Text;
            string salt = SaltTextBox.Text;

            if (string.IsNullOrEmpty(inputText) || string.IsNullOrEmpty(salt))
            {
                MessageBox.Show("Please enter both text and salt.");
                return;
            }

            if (SaltTextBox.Text.Length > 3)
            {
                MessageBox.Show("Salt must be less then 3 characters.");
                return;
            }

            string encryptedText = AesEncryption.Encrypt(inputText, salt);
            Save_File(encryptedText);
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(ThreadsTextBox.Text, out int maxThreads))
            {
                MessageBox.Show("Please enter a valid number for threads.");
                return;
            }

            if(maxThreads<=0 || maxThreads > Environment.ProcessorCount * 2 - 1)
            {
                MessageBox.Show($"Please enter a valid number for threads. between 0 and {Environment.ProcessorCount*2-1}");
                return;
            }

            string encryptedText = Get_File();
            var stopwatch = Stopwatch.StartNew();
            List<string> decryptionResults = BruteAttack(encryptedText, maxThreads);
            stopwatch.Stop();

            CorrectDecription.Text = FoundSalt;

            TimerText.Text = stopwatch.Elapsed.TotalSeconds.ToString();

            DisplayResults(decryptionResults, stopwatch.Elapsed.TotalSeconds);
        }

        public void Save_File(string input)
        {
            File.WriteAllText(FilePath, input);
            MessageBox.Show("Text encrypted and saved to file.");
        }

        public string Get_File()
        {
            return File.ReadAllText(FilePath);
        }

        private void DisplayResults(List<string> results, double elapsedSeconds)
        {
            if (results.Count > 0)
            {
                StringBuilder resultBuilder = new StringBuilder();
                foreach (var result in results)
                {
                    resultBuilder.AppendLine(result);
                }

                DecryptionResultTextBlock.Text = resultBuilder.ToString();
            }
            else
            {
                DecryptionResultTextBlock.Text = "Decryption failed. No valid salts found.";
            }
        }

        public List<string> BruteAttack(string encryptedText, int maxThreads)
        {
            var results = new ConcurrentBag<string>();
            var cts = new CancellationTokenSource();
            var token = cts.Token;
            string passentered = InputTextBox.Text;

            // Function to generate strings of a specific length
            void GenerateStringsOfLength(int length, char[] buffer, int pos, CancellationToken token)
            {

                if (token.IsCancellationRequested)
                {
                    return;
                }

                if (pos == length)
                {

                    try
                    {
                        string salt = new string(buffer);
                        string decrypted = AesEncryption.Decrypt(encryptedText, salt);
                        if (decrypted != null)
                        {
                            results.Add($"Salt:{salt} Decrypted:{decrypted}");

                            if (decrypted.Contains(passentered))
                            {
                                FoundSalt = $"Salt:{salt} Decrypted:{decrypted}";
                                token.ThrowIfCancellationRequested();
                                return;
                            }
                        }
                    }
                    catch
                    {
                        // Decryption failed, continue
                    }
                    return;
                }

                foreach (var c in asciiChars)
                {
                    if (token.IsCancellationRequested)
                    {
                        return;
                    }

                    buffer[pos] = c;
                    GenerateStringsOfLength(length, buffer, pos + 1, token);
                }
            }

            try
            {
                // Use Parallel.For with a specified degree of parallelism and cancellation token
                Parallel.For(1, 4, new ParallelOptions { MaxDegreeOfParallelism = maxThreads, CancellationToken = token }, i =>
                {
                    var buffer = new char[i];
                    GenerateStringsOfLength(i, buffer, 0, token);
                });

                // Parallel.For handles waiting for all tasks to complete or until cancellation is requested
            }
            catch (OperationCanceledException)
            {
                results.Add("Operation was canceled.");
            }

            return results.ToList();
        }
    }
}
