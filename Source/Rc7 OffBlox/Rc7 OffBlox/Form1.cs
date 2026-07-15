using RC7UI;

namespace Rc7_OffBlox
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Text & Lua Files (*.txt;*.lua)|*.txt;*.lua|All Files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string filePath = openFileDialog.FileName;

                // Read all text from file
                string content = File.ReadAllText(filePath);

                // Set textbox text
                textBox1.Text = content;
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            PipeClient.Output += OnPipeOutput;
        }

        void OnPipeOutput(string msg)
        {
            try { if (!IsDisposed) BeginInvoke((Action)(() => Status(msg.TrimEnd()))); }
            catch { }
        }
        void Status(string text)
        {
            textBox2.Text = textBox2.Text + text + "\n";
        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                string code = textBox1.Text;
                if (string.IsNullOrWhiteSpace(code)) return;
                PipeClient.Send(code);   // fully async + self-contained; can't block/crash the UI
            }
            catch (Exception ex) { Status("! execute error: " + ex.Message); }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            textBox1.Text = "";
        }

        private void pictureBox2_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog saveFileDialog = new SaveFileDialog())
            {
                saveFileDialog.Filter = "Lua Files (*.lua)|*.lua|Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
                saveFileDialog.DefaultExt = "lua";
                saveFileDialog.AddExtension = true;

                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    File.WriteAllText(saveFileDialog.FileName, textBox1.Text);
                }
            }
        }

        private void pictureBox1_Click(object sender, EventArgs e)
        {

        }
    }
}
