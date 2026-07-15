using System;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

// Minimal C# client for the OffBloxExec DLL.
// Connects to the named pipe, streams anything you type as a script, and
// prints status/result messages the DLL sends back.
//
//   dotnet run                 -> interactive: type a line, press Enter to run
//   dotnet run -- script.lua   -> send a whole file as one script, then exit
class Program
{
    const string PipeName = "OffBloxExec";

    static async Task<int> Main(string[] args)
    {
        using var pipe = new NamedPipeClientStream(".", PipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous);

        Console.Write($"Connecting to \\\\.\\pipe\\{PipeName} ... ");
        try { await pipe.ConnectAsync(5000); }
        catch (TimeoutException)
        {
            Console.WriteLine("timeout. Is OffBloxExec.dll injected and the server running?");
            return 1;
        }
        pipe.ReadMode = PipeTransmissionMode.Message;
        Console.WriteLine("connected.");

        // Background reader: print every message the DLL sends back.
        var cts = new CancellationTokenSource();
        _ = Task.Run(async () =>
        {
            var buf = new byte[1 << 16];
            while (!cts.IsCancellationRequested)
            {
                int n;
                try { n = await pipe.ReadAsync(buf, 0, buf.Length, cts.Token); }
                catch { break; }
                if (n <= 0) break;
                Console.WriteLine("  " + Encoding.UTF8.GetString(buf, 0, n));
            }
        });

        // One-shot file mode.
        if (args.Length > 0)
        {
            string code = System.IO.File.ReadAllText(args[0]);
            byte[] b = Encoding.UTF8.GetBytes(code);
            await pipe.WriteAsync(b, 0, b.Length);
            await pipe.FlushAsync();
            await Task.Delay(1500);   // give it a moment to run + reply
            return 0;
        }

        // Interactive mode.
        Console.WriteLine("Type Luau and press Enter (blank line quits):");
        string line;
        while ((line = Console.ReadLine()) != null)
        {
            if (line.Length == 0) break;
            byte[] b = Encoding.UTF8.GetBytes(line);
            await pipe.WriteAsync(b, 0, b.Length);
            await pipe.FlushAsync();
        }
        cts.Cancel();
        return 0;
    }
}
