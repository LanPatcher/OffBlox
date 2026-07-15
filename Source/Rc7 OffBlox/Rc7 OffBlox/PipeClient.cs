using System;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RC7UI
{
    // Stable, self-contained send. Each Execute opens its OWN short-lived
    // connection on a background thread, writes the script, reads any immediate
    // replies, then closes. Nothing is shared between calls, so there is never a
    // concurrent read+write on the same pipe (which is what crashed the old
    // persistent-reader design).
    public static class PipeClient
    {
        public static event Action<string> Output;

        public static void Send(string script)
        {
            Thread t = new Thread(() => Worker(script)) { IsBackground = true, Name = "RC7-Send" };
            t.Start();
        }

        static void Emit(string s) { Action<string> h = Output; if (h != null) h(s); }

        static void Worker(string script)
        {
            NamedPipeClientStream pipe = null;
            Task<int> pending = null;
            try
            {
                pipe = new NamedPipeClientStream(".", "OffBloxExec", PipeDirection.InOut, PipeOptions.Asynchronous);
                pipe.Connect(1500);
                try { pipe.ReadMode = PipeTransmissionMode.Message; } catch { }

                byte[] data = Encoding.UTF8.GetBytes(script);
                pipe.Write(data, 0, data.Length);
                pipe.Flush();
                Emit("> executed (" + data.Length + " bytes)");

                // read replies for a short window (write then read, same thread)
                byte[] buf = new byte[65536];
                DateTime end = DateTime.UtcNow.AddMilliseconds(800);
                while (DateTime.UtcNow < end && pipe.IsConnected)
                {
                    pending = pipe.ReadAsync(buf, 0, buf.Length);
                    if (!pending.Wait(250)) break;    // idle -> stop; dispose cancels it
                    int n = pending.Result; pending = null;
                    if (n <= 0) break;
                    string msg = Encoding.UTF8.GetString(buf, 0, n).TrimEnd();
                    if (msg.Length > 0) Emit(msg);
                }
            }
            catch (TimeoutException) { Emit("! not attached - launch OffBlox first"); }
            catch (Exception ex)     { Emit("! " + ex.Message); }
            finally
            {
                try { if (pipe != null) pipe.Dispose(); } catch { }
                if (pending != null) pending.ContinueWith(t => { var _ = t.Exception; }, TaskScheduler.Default);
            }
        }
    }
}
