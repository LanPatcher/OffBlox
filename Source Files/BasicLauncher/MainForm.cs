using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace OffBloxLauncher
{
    // Heavily simplified OffBlox launcher. Four tabs: Play, Host, Body, Appearance.
    // No DLL injection (handled automatically by the patched RobloxStudioBeta.exe),
    // no rbxmx files, no Roblox login. It only manages the settings files that the
    // patcher + HookedWebserver already consume, then launches Studio with args.
    public class MainForm : Form
    {
        // ---- Colors / theme ----
        private static readonly Color Bg     = Color.FromArgb(30, 30, 30);
        private static readonly Color Panel2 = Color.FromArgb(45, 45, 45);
        private static readonly Color Fg     = Color.White;
        private static readonly Color Accent = Color.FromArgb(0, 120, 215);

        // ---- Paths (everything is relative to the launcher exe, which sits at the
        //      OffBlox root next to Clients\ and Settings\) ----
        private static string Root { get { return AppDomain.CurrentDomain.BaseDirectory; } }
        private static string Pth(params string[] parts)
        {
            string p = Root;
            foreach (string s in parts) p = Path.Combine(p, s);
            return p;
        }
        private static string StudioExe   { get { return Pth("Clients", "OffBlox", "OffBlox.exe"); } }
        private static string StudioDir    { get { return Pth("Clients", "OffBlox"); } }
        private static string UsernameFile { get { return Pth("Clients", "OffBlox", "Username.txt"); } }
        private static string AppearFile   { get { return Pth("Clients", "OffBlox", "Appearence.ini"); } }
        private static string BodyColorsDir{ get { return Pth("Clients", "OffBlox", "BodyColors"); } }
        private static string IpFile       { get { return Pth("Settings", "ip.txt"); } }
        private static string ClientPortFile{ get { return Pth("Settings", "clientport.txt"); } }
        private static string HostPortFile { get { return Pth("Settings", "HostPort.txt"); } }
        private static string UniversesDir { get { return Pth("Clients", "OffBlox", "data", "universes"); } }
        private static string SavedDataDir { get { return Pth("Clients", "OffBlox", "data", "SavedData"); } }
        private static string ContentDir   { get { return Pth("Clients", "OffBlox", "content"); } }
        private static string SelectedWorldFile { get { return Pth("Settings", "SelectedWorld.txt"); } }
        // Marker that OffBlox has been launched at least once from this launcher.
        // Absent => first run => we confirm before launching (the first launch can
        // trigger a Windows security/UAC prompt).
        private static string LaunchedMarker     { get { return Pth("Settings", "firstrun.done"); } }

        // ---- Controls ----
        private TextBox txtUser, txtIp, txtClientPort, txtHostPort;
        private TextBox txtAppearance, txtAddId;
        private ListBox worldList;
        private TextBox worldSearch;
        private Label playStatus, hostStatus, bodyStatus, appStatus;

        // ---- Body color state ----
        private readonly string[] PartNames = { "Head", "Torso", "Left Arm", "Right Arm", "Left Leg", "Right Leg" };
        private readonly Dictionary<string, string> PartFile = new Dictionary<string, string>
        {
            { "Head", "HeadColor.txt" }, { "Torso", "TorsoColor.txt" },
            { "Left Arm", "LeftArmColor.txt" }, { "Right Arm", "RightArmColor.txt" },
            { "Left Leg", "LeftLegColor.txt" }, { "Right Leg", "RightLegColor.txt" },
        };
        private readonly Dictionary<string, Panel> PartPanel = new Dictionary<string, Panel>();
        private readonly Dictionary<string, string> PartColorName = new Dictionary<string, string>();
        private string selectedPart = "Head";

        // ---- World list backing store ----
        private class WorldEntry
        {
            public string Name, PlaceId, UniverseId, CreatorId;
            public override string ToString() { return Name; }
        }
        private readonly List<WorldEntry> allWorlds = new List<WorldEntry>();
        private const string WorldSearchHint = "Search worlds...";
        private bool suppressWorldSave = false;   // don't persist selection during a rebuild

        // ---- BrickColor palette (name + hex). Names match what the webserver's
        //      BrickColorToHex() understands, and the swatch shows the exact hex
        //      the engine will render. Default for anything unknown = medium grey.
        private static readonly string[][] PaletteRaw =
        {
            new[]{"White","f2f3f3"}, new[]{"Medium stone grey","a3a2a5"}, new[]{"Dark stone grey","635f62"},
            new[]{"Black","1b2a35"}, new[]{"Really black","111111"},
            new[]{"Pastel brown","ffcc99"}, new[]{"Light orange","eab892"}, new[]{"Nougat","cc8e69"},
            new[]{"Brick yellow","d7c59a"}, new[]{"Reddish brown","694028"}, new[]{"Brown","7c5c46"},
            new[]{"Cocoa","562424"},
            new[]{"Bright red","c4281c"}, new[]{"Really red","ff0000"}, new[]{"Crimson","790e1a"},
            new[]{"Salmon","ff9494"}, new[]{"Pink","ffc0cb"}, new[]{"Hot pink","ff00bf"},
            new[]{"Magenta","aa00aa"},
            new[]{"Bright orange","da8541"}, new[]{"Deep orange","ff6600"},
            new[]{"Bright yellow","f5cd30"}, new[]{"New yeller","ffff00"}, new[]{"Cool yellow","f0db4f"},
            new[]{"Bright green","4b974b"}, new[]{"Dark green","287f47"}, new[]{"Lime green","00ff00"},
            new[]{"Sea green","348e40"}, new[]{"Camo","3a7d15"},
            new[]{"Teal","008080"}, new[]{"Toothpaste","00ffff"}, new[]{"Bright blue","0d69ac"},
            new[]{"Navy blue","002060"}, new[]{"Really blue","0000ff"}, new[]{"Cyan","04afec"},
            new[]{"Pastel blue","80bbdb"}, new[]{"Steel blue","527cae"},
            new[]{"Bright violet","6b327c"}, new[]{"Royal purple","6225d1"}, new[]{"Lavender","8c5b9f"},
            new[]{"Purple","a64dd1"}, new[]{"Gold","dba640"},
        };
        private readonly Dictionary<string, Color> NameToColor =
            new Dictionary<string, Color>(StringComparer.OrdinalIgnoreCase);

        public MainForm()
        {
            foreach (string[] e in PaletteRaw) NameToColor[e[0]] = HexColor(e[1]);

            Text = "OffBlox";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(430, 470);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            BackColor = Bg;
            ForeColor = Fg;
            Font = new Font("Segoe UI", 9.5f);

            TabControl tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;
            tabs.Padding = new Point(14, 6);
            Controls.Add(tabs);

            tabs.TabPages.Add(BuildPlayTab());
            tabs.TabPages.Add(BuildHostTab());
            tabs.TabPages.Add(BuildBodyTab());
            tabs.TabPages.Add(BuildAppearanceTab());

            LoadAll();

            Shown += delegate { LoadWorlds(); };               // rebuild list once the handle exists
            FormClosing += delegate { SaveBodyColors(); SaveAppearance(); SaveTextSettings(); };
        }

        // ================= helpers =================
        private static Color HexColor(string h)
        {
            return Color.FromArgb(
                int.Parse(h.Substring(0, 2), NumberStyles.HexNumber),
                int.Parse(h.Substring(2, 2), NumberStyles.HexNumber),
                int.Parse(h.Substring(4, 2), NumberStyles.HexNumber));
        }
        private Color ColorForName(string name)
        {
            Color c;
            if (!string.IsNullOrEmpty(name) && NameToColor.TryGetValue(name.Trim(), out c)) return c;
            return HexColor("a3a2a5");
        }
        private static string ReadFileSafe(string path)
        {
            try { if (File.Exists(path)) return File.ReadAllText(path); } catch { }
            return "";
        }
        private static void WriteFileSafe(string path, string text)
        {
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(path, text);
            }
            catch { }
        }
        private static string OneLine(string s)
        {
            return (s ?? "").Replace("\r", "").Replace("\n", "").Trim();
        }

        // Decompress a gzip byte array (used for the gzip-stored SavedData places).
        private static byte[] GunzipBytes(byte[] gz)
        {
            using (var inp = new MemoryStream(gz))
            using (var gzs = new GZipStream(inp, CompressionMode.Decompress))
            using (var outp = new MemoryStream())
            {
                gzs.CopyTo(outp);
                return outp.ToArray();
            }
        }
        private static TextBox MakeBox()
        {
            TextBox t = new TextBox();
            t.BackColor = Panel2; t.ForeColor = Fg; t.BorderStyle = BorderStyle.FixedSingle;
            return t;
        }
        private static Label MakeLabel(string text, int x, int y)
        {
            Label l = new Label();
            l.Text = text; l.AutoSize = true; l.ForeColor = Fg;
            l.Location = new Point(x, y + 3);
            return l;
        }
        private Button MakeButton(string text, int x, int y, int w, int h)
        {
            Button b = new Button();
            b.Text = text; b.Location = new Point(x, y); b.Size = new Size(w, h);
            b.FlatStyle = FlatStyle.Flat; b.FlatAppearance.BorderSize = 0;
            b.BackColor = Accent; b.ForeColor = Fg;
            return b;
        }

        // ================= Play tab =================
        private TabPage BuildPlayTab()
        {
            TabPage tp = new TabPage("Play"); tp.BackColor = Bg; tp.ForeColor = Fg;

            tp.Controls.Add(MakeLabel("Username:", 18, 22));
            txtUser = MakeBox(); txtUser.Location = new Point(130, 20); txtUser.Width = 270;
            tp.Controls.Add(txtUser);

            tp.Controls.Add(MakeLabel("Server IP:", 18, 62));
            txtIp = MakeBox(); txtIp.Location = new Point(130, 60); txtIp.Width = 270;
            tp.Controls.Add(txtIp);

            tp.Controls.Add(MakeLabel("Port:", 18, 102));
            txtClientPort = MakeBox(); txtClientPort.Location = new Point(130, 100); txtClientPort.Width = 120;
            tp.Controls.Add(txtClientPort);

            Button play = MakeButton("Play", 130, 150, 270, 56);
            play.Font = new Font("Segoe UI", 14f, FontStyle.Bold);
            play.Click += delegate { DoPlay(); };
            tp.Controls.Add(play);

            playStatus = MakeLabel("", 18, 222); playStatus.MaximumSize = new Size(390, 0);
            tp.Controls.Add(playStatus);
            return tp;
        }

        // ================= Host tab =================
        private TabPage BuildHostTab()
        {
            TabPage tp = new TabPage("Host"); tp.BackColor = Bg; tp.ForeColor = Fg;

            tp.Controls.Add(MakeLabel("Host Port:", 18, 18));
            txtHostPort = MakeBox(); txtHostPort.Location = new Point(130, 16); txtHostPort.Width = 120;
            tp.Controls.Add(txtHostPort);

            worldSearch = MakeBox();
            worldSearch.Location = new Point(18, 52); worldSearch.Width = 384;
            worldSearch.Text = WorldSearchHint; worldSearch.ForeColor = Color.Silver;
            worldSearch.GotFocus += delegate
            {
                if (worldSearch.Text == WorldSearchHint) { worldSearch.Text = ""; worldSearch.ForeColor = Fg; }
            };
            worldSearch.LostFocus += delegate
            {
                if (worldSearch.Text.Length == 0) { worldSearch.Text = WorldSearchHint; worldSearch.ForeColor = Color.Silver; }
            };
            worldSearch.TextChanged += delegate { ApplyWorldFilter(); };
            tp.Controls.Add(worldSearch);

            worldList = new ListBox();
            worldList.Location = new Point(18, 84); worldList.Size = new Size(384, 200);
            worldList.BackColor = Panel2; worldList.ForeColor = Fg;
            worldList.BorderStyle = BorderStyle.FixedSingle;
            worldList.IntegralHeight = false;
            worldList.SelectedIndexChanged += delegate
            {
                if (suppressWorldSave) return;
                WorldEntry w = worldList.SelectedItem as WorldEntry;
                if (w != null) WriteFileSafe(SelectedWorldFile, w.UniverseId);
            };
            tp.Controls.Add(worldList);

            // Edit (left) + Host (right) side by side.
            Button edit = MakeButton("Edit", 18, 296, 186, 46);
            edit.BackColor = Color.FromArgb(70, 70, 70);
            edit.Font = new Font("Segoe UI", 12f, FontStyle.Bold);
            edit.Click += delegate { DoEdit(); };
            tp.Controls.Add(edit);

            Button host = MakeButton("Host", 216, 296, 186, 46);
            host.Font = new Font("Segoe UI", 12f, FontStyle.Bold);
            host.Click += delegate { DoHost(); };
            tp.Controls.Add(host);

            hostStatus = MakeLabel("", 18, 350); hostStatus.MaximumSize = new Size(390, 0);
            tp.Controls.Add(hostStatus);
            return tp;
        }

        // ================= Body tab =================
        private TabPage BuildBodyTab()
        {
            TabPage tp = new TabPage("Body"); tp.BackColor = Bg; tp.ForeColor = Fg;

            // Paper-doll avatar built from clickable panels. Layout (px) inside tab:
            //            [ Head ]
            //   [LArm] [ Torso ] [RArm]
            //          [LLeg][RLeg]
            int cx = 150;                       // torso centre-ish
            AddPart(tp, "Head",      cx + 18, 14, 40, 36);
            AddPart(tp, "Left Arm",  cx - 22, 56, 26, 70);
            AddPart(tp, "Torso",     cx + 6,  56, 64, 70);
            AddPart(tp, "Right Arm", cx + 76, 56, 26, 70);
            AddPart(tp, "Left Leg",  cx + 6,  132, 30, 64);
            AddPart(tp, "Right Leg", cx + 40, 132, 30, 64);

            bodyStatus = MakeLabel("Selected: Head", 18, 206);
            tp.Controls.Add(bodyStatus);

            // Palette grid
            Panel palette = new Panel();
            palette.Location = new Point(18, 232); palette.Size = new Size(390, 200);
            palette.AutoScroll = true; palette.BackColor = Bg;
            int sw = 30, gap = 4, perRow = 11, i = 0;
            foreach (string[] e in PaletteRaw)
            {
                string name = e[0];
                Panel s = new Panel();
                s.Size = new Size(sw, sw);
                s.Location = new Point((i % perRow) * (sw + gap), (i / perRow) * (sw + gap));
                s.BackColor = HexColor(e[1]);
                s.BorderStyle = BorderStyle.FixedSingle;
                s.Cursor = Cursors.Hand;
                ToolTip tip = new ToolTip(); tip.SetToolTip(s, name);
                s.Click += delegate { ApplyColorToSelected(name); };
                palette.Controls.Add(s);
                i++;
            }
            tp.Controls.Add(palette);
            return tp;
        }

        private void AddPart(TabPage tp, string part, int x, int y, int w, int h)
        {
            Panel p = new Panel();
            p.Location = new Point(x, y); p.Size = new Size(w, h);
            p.BackColor = HexColor("a3a2a5");
            p.Cursor = Cursors.Hand;
            p.Tag = part;
            p.Paint += delegate (object sender, PaintEventArgs e)
            {
                Panel pp = (Panel)sender;
                Color border = ((string)pp.Tag == selectedPart) ? Color.Gold : Color.FromArgb(20, 20, 20);
                using (Pen pen = new Pen(border, 3))
                    e.Graphics.DrawRectangle(pen, 1, 1, pp.Width - 3, pp.Height - 3);
            };
            p.Click += delegate
            {
                selectedPart = part;
                if (bodyStatus != null) bodyStatus.Text = "Selected: " + part;
                foreach (Panel bp in PartPanel.Values) bp.Invalidate();
            };
            PartPanel[part] = p;
            tp.Controls.Add(p);
        }

        private void ApplyColorToSelected(string brickName)
        {
            PartColorName[selectedPart] = brickName;
            PartPanel[selectedPart].BackColor = ColorForName(brickName);
            if (bodyStatus != null) bodyStatus.Text = "Selected: " + selectedPart + "  ->  " + brickName;
            SaveBodyColors();
        }

        // ================= Appearance tab =================
        private class Preset
        {
            public string Label; public string[] Ids; public bool Anim;
            public Preset(string label, bool anim, params string[] ids)
            { Label = label; Anim = anim; Ids = ids; }
        }

        private TabPage BuildAppearanceTab()
        {
            TabPage tp = new TabPage("Appearance"); tp.BackColor = Bg; tp.ForeColor = Fg;

            tp.Controls.Add(MakeLabel("Appearance asset list (one URL per line):", 14, 4));

            txtAppearance = new TextBox();
            txtAppearance.Location = new Point(14, 26); txtAppearance.Size = new Size(394, 116);
            txtAppearance.Multiline = true; txtAppearance.ScrollBars = ScrollBars.Vertical;
            txtAppearance.WordWrap = false;
            txtAppearance.BackColor = Panel2; txtAppearance.ForeColor = Fg;
            txtAppearance.BorderStyle = BorderStyle.FixedSingle;
            txtAppearance.Font = new Font("Consolas", 9f);
            tp.Controls.Add(txtAppearance);

            // ---- preset buttons (click to append the asset ids) ----
            FlowLayoutPanel flow = new FlowLayoutPanel();
            flow.Location = new Point(14, 148); flow.Size = new Size(394, 150);
            flow.BackColor = Bg; flow.AutoScroll = true; flow.WrapContents = true;
            flow.FlowDirection = FlowDirection.LeftToRight;

            AddSection(flow, "Base packages", new[]
            {
                new Preset("Woman", false, "86499666","86499716","86499698","86499753","86499793"),
            });
            AddSection(flow, "Clothing", new[]
            {
                new Preset("Monster Shirt", false, "129802039941402"),
                new Preset("Idylilac Pants", false, "123726090805165"),
                new Preset("Oakley Pants", false, "301811432"),
            });
            AddSection(flow, "Accessories", new[]
            {
                new Preset("Anime Hair", false, "128998214296166"),
                new Preset("Miku Head", false, "121707899033152"),
                new Preset("Black Wings", false, "105969766385542"),
                new Preset("Alien Necklace", false, "14702520072"),
                new Preset("Chainsaw", false, "82677510121383"),
            });
            AddSection(flow, "Animations", new[]
            {
                // idle, walk, run, jump, fall, climb (1111111-prefixed)
                new Preset("Default Anim Pack", true,
                    "837011741","658831143","658830056","619511974","658831500","658833139"),
            });
            AddSection(flow, "Emotes", new[]
            {
                new Preset("Bored", false, "5230661597"),
                new Preset("Sleep", false, "4689362868"),
                new Preset("Shy", false, "3576717965"),
                new Preset("Godlike", false, "3823158750"),
                new Preset("Curtsy", false, "4646306583"),
                new Preset("Lotus", false, "12507097350"),
            });
            tp.Controls.Add(flow);

            // ---- add-by-id + clear + save ----
            tp.Controls.Add(MakeLabel("Asset ID:", 14, 306));
            txtAddId = MakeBox(); txtAddId.Location = new Point(86, 304); txtAddId.Width = 120;
            tp.Controls.Add(txtAddId);

            Button add = MakeButton("Add", 214, 303, 84, 26);
            add.Click += delegate { AddAssetId(); };
            tp.Controls.Add(add);

            Button clear = MakeButton("Clear", 306, 303, 102, 26);
            clear.BackColor = Color.FromArgb(120, 60, 60);
            clear.Click += delegate { txtAppearance.Text = ""; appStatus.Text = "Cleared (not yet saved)."; };
            tp.Controls.Add(clear);

            Button save = MakeButton("Save Appearance", 14, 338, 394, 34);
            save.Click += delegate { SaveAppearance(); appStatus.Text = "Saved to Appearence.ini."; };
            tp.Controls.Add(save);

            appStatus = MakeLabel("", 14, 380); appStatus.MaximumSize = new Size(394, 0);
            tp.Controls.Add(appStatus);
            return tp;
        }

        private void AddSection(FlowLayoutPanel flow, string title, Preset[] items)
        {
            Label header = new Label();
            header.Text = title; header.AutoSize = false; header.Width = 384; header.Height = 18;
            header.ForeColor = Color.Silver; header.Font = new Font("Segoe UI", 8.5f, FontStyle.Bold);
            header.Margin = new Padding(0, 6, 0, 2);
            flow.Controls.Add(header);
            flow.SetFlowBreak(header, true);

            Button last = null;
            foreach (Preset p in items)
            {
                Preset cap = p;                       // capture per-iteration
                Button b = new Button();
                b.Text = p.Label; b.AutoSize = true;
                b.FlatStyle = FlatStyle.Flat; b.FlatAppearance.BorderSize = 0;
                b.BackColor = Panel2; b.ForeColor = Fg;
                b.Margin = new Padding(0, 0, 4, 4);
                b.Click += delegate { AppendAppearanceIds(cap.Ids, cap.Anim); };
                flow.Controls.Add(b);
                last = b;
            }
            if (last != null) flow.SetFlowBreak(last, true);
        }

        private void AppendAppearanceIds(string[] ids, bool anim)
        {
            string cur = txtAppearance.Text.TrimEnd();
            foreach (string raw in ids)
            {
                string id = (anim ? "1111111" : "") + raw;
                string url = "http://localhost/asset/?id=" + id;
                cur = (cur.Length == 0) ? url : cur + "\r\n;" + url;
            }
            txtAppearance.Text = cur;
            appStatus.Text = "Added " + ids.Length + " asset(s). Click Save Appearance to persist.";
        }

        private void AddAssetId()
        {
            string id = Regex.Replace(OneLine(txtAddId.Text), "[^0-9]", ""); // bare id or pasted url
            if (id.Length == 0) { appStatus.Text = "Enter a numeric asset id."; return; }
            AppendAppearanceIds(new[] { id }, false);
            txtAddId.Text = "";
        }

        // ================= load / save =================
        private void LoadAll()
        {
            txtUser.Text       = OneLine(ReadFileSafe(UsernameFile));
            txtIp.Text         = OneLine(ReadFileSafe(IpFile));
            txtClientPort.Text = OneLine(ReadFileSafe(ClientPortFile));
            txtHostPort.Text   = OneLine(ReadFileSafe(HostPortFile));
            if (txtIp.Text.Length == 0) txtIp.Text = "127.0.0.1";
            if (txtClientPort.Text.Length == 0) txtClientPort.Text = "25565";
            if (txtHostPort.Text.Length == 0) txtHostPort.Text = "25565";

            txtAppearance.Text = ReadFileSafe(AppearFile).Replace("\n", "\r\n").Replace("\r\r\n", "\r\n");

            foreach (string part in PartNames)
            {
                string name = OneLine(ReadFileSafe(Path.Combine(BodyColorsDir, PartFile[part])));
                if (name.Length == 0) name = "Medium stone grey";
                PartColorName[part] = name;
                if (PartPanel.ContainsKey(part)) PartPanel[part].BackColor = ColorForName(name);
            }
        }

        private void SaveTextSettings()
        {
            WriteFileSafe(UsernameFile,   OneLine(txtUser.Text));
            WriteFileSafe(IpFile,         OneLine(txtIp.Text));
            WriteFileSafe(ClientPortFile, OneLine(txtClientPort.Text));
            WriteFileSafe(HostPortFile,   OneLine(txtHostPort.Text));
        }

        private void SaveBodyColors()
        {
            foreach (string part in PartNames)
            {
                string name = PartColorName.ContainsKey(part) ? PartColorName[part] : "Medium stone grey";
                WriteFileSafe(Path.Combine(BodyColorsDir, PartFile[part]), name);
            }
        }

        private void SaveAppearance()
        {
            if (txtAppearance == null) return;
            // store with plain \n line endings (matches what the relay/webserver read)
            WriteFileSafe(AppearFile, txtAppearance.Text.Replace("\r\n", "\n").Trim());
        }

        // ================= launch =================
        private bool EnsureStudio()
        {
            if (File.Exists(StudioExe)) return true;
            MessageBox.Show("OffBlox.exe not found at:\n" + StudioExe +
                "\n\nPut this launcher in the OffBlox root (next to the Clients folder).",
                "Studio not found", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }

        private void DoPlay()
        {
            SaveTextSettings(); SaveBodyColors(); SaveAppearance();
            if (!EnsureStudio()) return;

            string ip = OneLine(txtIp.Text);
            string port = OneLine(txtClientPort.Text);
            if (ip.Length == 0) { playStatus.Text = "Enter a server IP."; return; }

            // Exact arg form the original launcher used (fix.ini == a single quote):
            //   ""-task StartClient -server "<ip>" -port <port>"
            const string q = "\"";
            string args = q + "\"-task StartClient -placeId 0 -universeId 0 "+ " -port " + port + " -server " + q + ip + q;
            Launch(args, "Joining " + ip + ":" + port + " ...", playStatus);
        }

        private void DoHost()
        {
            WorldEntry w = worldList != null ? worldList.SelectedItem as WorldEntry : null;
            if (w == null) { hostStatus.Text = "Select a world to host."; return; }

            SaveTextSettings(); SaveBodyColors(); SaveAppearance();
            if (!EnsureStudio()) return;

            string savedPlace = Path.Combine(SavedDataDir, w.PlaceId + ".rbxl");
            if (!File.Exists(savedPlace))
            {
                MessageBox.Show("\"" + w.Name + "\" has no published place file yet.\nPublish it once, then host.",
                    "Place not found", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            // SavedData places are stored gzip-compressed by the webserver, but
            // StartServer loads the place file directly off disk and can't read
            // gzip. Decompress to content\place.rbxl and host from THAT.
            string rawPlace = Path.Combine(ContentDir, "place.rbxl");
            try
            {
                if (!Directory.Exists(ContentDir)) Directory.CreateDirectory(ContentDir);
                byte[] bytes = File.ReadAllBytes(savedPlace);
                if (bytes.Length >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b)
                    bytes = GunzipBytes(bytes);
                File.WriteAllBytes(rawPlace, bytes);
                File.WriteAllBytes(Path.Combine(ContentDir, "1818"), bytes);

                // Also write to %LOCALAPPDATA%\Roblox\server.rbxl so any tools
                // watching that path pick up the current place automatically.
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string robloxAppData = Path.Combine(localAppData, "Roblox");
                if (!Directory.Exists(robloxAppData)) Directory.CreateDirectory(robloxAppData);
                File.WriteAllBytes(Path.Combine(robloxAppData, "server.rbxl"), bytes);
            }
            catch { }

            string port = OneLine(txtHostPort.Text);
            // -port stays the forwarded/host port. RbxTransport (the transport the
            // client uses) is pinned to it by the webserver's FInt overrides, and
            // the RobloxStudioPatcher bind() hook moves RakNet to -port+1 inside
            // the server so it doesn't collide on this port.
            const string q = "\"";
            string args = "-task StartServer"
                + " -placeId " + w.PlaceId
                + " -universeId " + w.UniverseId
                + " -port " + port
                + " -creatorId " + w.CreatorId
                + " -creatorType 0"
                + " -placeVersion 0"
                + " -numTestServerPlayersUponStartup 0"
                + " -parentPid " + Process.GetCurrentProcess().Id
                + " -parentSessionGuid " + Guid.NewGuid().ToString().ToUpper()
                + " -instanceId StudioServer";
            Launch(args, "Hosting \"" + w.Name + "\" on port " + port + " ...", hostStatus);
        }
        private void DoEdit()
        {
            WorldEntry w = worldList != null ? worldList.SelectedItem as WorldEntry : null;
            if (w == null) { hostStatus.Text = "Select a world to edit."; return; }

            SaveTextSettings(); SaveBodyColors(); SaveAppearance();
            if (!EnsureStudio()) return;

            // Edit by place id: Studio downloads the place from the webserver and
            // stays associated with the universe so saving/publishing overwrites
            // the right place.
            string args = "-task EditPlace"
                + " -placeId " + w.PlaceId
                + " -universeId " + w.UniverseId;
            Launch(args, "Editing \"" + w.Name + "\" ...", hostStatus);
        }

        private static bool HasLaunchedBefore()
        {
            try { return File.Exists(LaunchedMarker); } catch { return false; }
        }
        private static void MarkLaunched()
        {
            WriteFileSafe(LaunchedMarker, DateTime.Now.ToString("o"));
        }

        private void Launch(string args, string status, Label statusLabel)
        {
            // First-ever launch: Windows may show a security (UAC) prompt because
            // OffBlox.exe asks to elevate. If the user dismisses it, Process.Start
            // throws Win32 error 1223 ("The operation was canceled by the user"),
            // which used to surface as a confusing failure. So on the first run we
            // confirm up front, and we handle a declined prompt gracefully.
            if (!HasLaunchedBefore())
            {
                DialogResult r = MessageBox.Show(
                    "This looks like the first time you're launching OffBlox.\n\n" +
                    "Windows may show a security prompt - choose \"Yes\" on it to let " +
                    "OffBlox start.\n\nLaunch OffBlox now?",
                    "First launch", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (r != DialogResult.Yes)
                {
                    if (statusLabel != null) statusLabel.Text = "Launch cancelled.";
                    return;
                }
            }

            try
            {
                Process p = new Process();
                p.StartInfo.FileName = StudioExe;
                p.StartInfo.WorkingDirectory = StudioDir;
                p.StartInfo.Arguments = args;
                p.StartInfo.UseShellExecute = true;   // allows OffBlox.exe to auto-elevate
                p.Start();
                MarkLaunched();
                if (statusLabel != null) statusLabel.Text = status;
            }
            catch (System.ComponentModel.Win32Exception wex)
            {
                // 1223 == ERROR_CANCELLED: the user dismissed the Windows security
                // prompt. Not a real failure - tell them how to proceed.
                if (wex.NativeErrorCode == 1223)
                {
                    if (statusLabel != null)
                        statusLabel.Text = "Launch cancelled at the Windows prompt. " +
                                           "Click again and choose \"Yes\" to allow it.";
                }
                else if (statusLabel != null)
                {
                    statusLabel.Text = "Launch failed: " + wex.Message;
                }
            }
            catch (Exception ex)
            {
                if (statusLabel != null) statusLabel.Text = "Launch failed: " + ex.Message;
            }
        }

        // ================= worlds =================
        private static string JsonNumber(string json, string key)
        {
            Match m = Regex.Match(json, "\"" + key + "\"\\s*:\\s*\"?(-?\\d+)\"?");
            return m.Success ? m.Groups[1].Value : "";
        }
        private static string JsonStr(string json, string key)
        {
            Match m = Regex.Match(json, "\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            return m.Success ? m.Groups[1].Value : "";
        }

        private void LoadWorlds()
        {
            if (worldList == null) return;
            allWorlds.Clear();
            try
            {
                if (Directory.Exists(UniversesDir))
                {
                    foreach (string f in Directory.GetFiles(UniversesDir, "*.json"))
                    {
                        try
                        {
                            string j = File.ReadAllText(f);
                            string name = JsonStr(j, "name");
                            string universeId = JsonNumber(j, "universeId");
                            if (universeId.Length == 0) universeId = JsonNumber(j, "id");
                            string placeId = JsonNumber(j, "rootPlaceId");
                            if (placeId.Length == 0) placeId = universeId;
                            string creatorId = JsonNumber(j, "creatorTargetId");
                            if (name.Length == 0) name = Path.GetFileNameWithoutExtension(f);
                            allWorlds.Add(new WorldEntry
                            {
                                Name = name, PlaceId = placeId,
                                UniverseId = universeId, CreatorId = creatorId
                            });
                        }
                        catch { }
                    }
                }
            }
            catch { }
            allWorlds.Sort(delegate (WorldEntry a, WorldEntry b)
            { return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });
            ApplyWorldFilter();
        }

        private void ApplyWorldFilter()
        {
            if (worldList == null) return;
            string q = (worldSearch != null) ? worldSearch.Text.Trim() : "";
            if (q == WorldSearchHint) q = "";

            // Prefer the choice saved from last session, else whatever is highlighted.
            string wantId = OneLine(ReadFileSafe(SelectedWorldFile));
            WorldEntry cur = worldList.SelectedItem as WorldEntry;
            if (wantId.Length == 0 && cur != null) wantId = cur.UniverseId;

            suppressWorldSave = true;
            worldList.BeginUpdate();
            worldList.Items.Clear();
            int selectIdx = -1;
            foreach (WorldEntry w in allWorlds)
            {
                if (q.Length > 0 && w.Name.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0) continue;
                int idx = worldList.Items.Add(w);
                if (wantId.Length > 0 && w.UniverseId == wantId) selectIdx = idx;
            }
            if (selectIdx < 0 && worldList.Items.Count > 0) selectIdx = 0;
            if (selectIdx >= 0) worldList.SelectedIndex = selectIdx;
            worldList.EndUpdate();
            suppressWorldSave = false;
        }
    }
}
