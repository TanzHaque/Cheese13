// FakeWinForms.cs - stand-ins for the few WinForms classes that lib\Gui.ps1 uses, so that the window's PowerShell code
// (what every button does, how the list is filled, what the dialogs ask) can be RUN on a machine without Windows.
//
// They keep the values you set (Text, Checked, Items ...) and run the event handlers when the test says "click"; nothing is drawn.
// They are not the real thing: layout, painting, fonts, DPI, focus and the real message loop can only be tried on Windows
// (Start-Hardening.ps1 -GuiSelfTest does that part on the real box). Tests\Test-GuiApi.ps1 checks every name used in Gui.ps1 against
// the real WinForms, so these classes only need what Gui.ps1 uses. The numbers of the enums are the real ones.
//
// FakeLab.Stage is the remote control: the test says what "the person" does when a dialog or a message box opens.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;

namespace FakeLab
{
    // the real System.Drawing.ContentAlignment lives in an assembly that is not always there; the numbers are the real ones
    public enum ContentAlignment { TopLeft = 1, TopCenter = 2, TopRight = 4, MiddleLeft = 16, MiddleCenter = 32, MiddleRight = 64, BottomLeft = 256, BottomCenter = 512, BottomRight = 1024 }

    public static class Stage
    {
        // a dialog was opened with ShowDialog(owner): act as the person (press buttons, type), then return the answer
        public static Func<System.Windows.Forms.Form, System.Windows.Forms.DialogResult> OnDialog;
        // a message box was opened: title, text, buttons -> the button the person presses
        public static Func<string, string, System.Windows.Forms.MessageBoxButtons, System.Windows.Forms.DialogResult> OnMessage;
        // the main window was opened with ShowDialog() and no owner: click around, then return (the window is closed afterwards)
        public static Action<System.Windows.Forms.Form> OnMainForm;

        public static List<string> Messages = new List<string>();     // "title | text" of every message box
        public static List<string> Dialogs = new List<string>();      // the title of every dialog and window that was shown
        public static int DoEventsCalls;

        public static void Reset()
        {
            OnDialog = null; OnMessage = null; OnMainForm = null;
            Messages.Clear(); Dialogs.Clear(); DoEventsCalls = 0;
        }
    }
}

namespace System.Windows.Forms
{
    // ---------------------------------------------------------------- enums
    public enum DialogResult { None = 0, OK = 1, Cancel = 2, Abort = 3, Retry = 4, Ignore = 5, Yes = 6, No = 7 }
    public enum MessageBoxButtons { OK = 0, OKCancel = 1, AbortRetryIgnore = 2, YesNoCancel = 3, YesNo = 4, RetryCancel = 5 }
    public enum MessageBoxIcon { None = 0, Hand = 16, Error = 16, Stop = 16, Question = 32, Exclamation = 48, Warning = 48, Asterisk = 64, Information = 64 }
    public enum MessageBoxDefaultButton { Button1 = 0, Button2 = 256, Button3 = 512 }
    [Flags] public enum AnchorStyles { None = 0, Top = 1, Bottom = 2, Left = 4, Right = 8 }
    public enum DockStyle { None = 0, Top = 1, Bottom = 2, Left = 3, Right = 4, Fill = 5 }
    public enum AutoSizeMode { GrowOnly = 0, GrowAndShrink = 1 }
    public enum FlowDirection { LeftToRight = 0, TopDown = 1, RightToLeft = 2, BottomUp = 3 }
    public enum View { LargeIcon = 0, Details = 1, SmallIcon = 2, List = 3, Tile = 4 }
    public enum ScrollBars { None = 0, Horizontal = 1, Vertical = 2, Both = 3 }
    public enum SizeType { AutoSize = 0, Absolute = 1, Percent = 2 }
    public enum FormStartPosition { Manual = 0, CenterScreen = 1, WindowsDefaultLocation = 2, WindowsDefaultBounds = 3, CenterParent = 4 }
    public enum FormBorderStyle { None = 0, FixedSingle = 1, Fixed3D = 2, FixedDialog = 3, Sizable = 4, FixedToolWindow = 5, SizableToolWindow = 6 }
    public enum ComboBoxStyle { Simple = 0, DropDown = 1, DropDownList = 2 }
    public enum CloseReason { None = 0, WindowsShutDown = 1, MdiFormClosing = 2, UserClosing = 3, TaskManagerClosing = 4, FormOwnerClosing = 5, ApplicationExitCall = 6 }

    // ---------------------------------------------------------------- small value types
    public interface IWin32Window { IntPtr Handle { get; } }

    public struct Padding
    {
        int l, t, r, b;
        public Padding(int all) { l = all; t = all; r = all; b = all; }
        public Padding(int left, int top, int right, int bottom) { l = left; t = top; r = right; b = bottom; }
        public int Left { get { return l; } set { l = value; } }
        public int Top { get { return t; } set { t = value; } }
        public int Right { get { return r; } set { r = value; } }
        public int Bottom { get { return b; } set { b = value; } }
        public int All { get { return l; } }
    }

    public class Cursor
    {
        public string Name;
        public Cursor(string name) { Name = name; }
        public override string ToString() { return Name; }
    }

    public static class Cursors
    {
        public static readonly Cursor Default = new Cursor("Default");
        public static readonly Cursor WaitCursor = new Cursor("WaitCursor");
    }

    public class Screen
    {
        public static Screen PrimaryScreen { get { return new Screen(); } }
        public Rectangle WorkingArea { get { return new Rectangle(0, 0, 1920, 1040); } }
    }

    public static class Application
    {
        public static void EnableVisualStyles() { }
        public static void DoEvents() { FakeLab.Stage.DoEventsCalls++; }
    }

    public static class MessageBox
    {
        static DialogResult Ask(string text, string caption, MessageBoxButtons buttons)
        {
            FakeLab.Stage.Messages.Add(caption + " | " + text);
            // with nobody to ask, a question is answered No (the safe answer) and a notice is acknowledged
            DialogResult answer = DialogResult.OK;
            if (buttons == MessageBoxButtons.YesNo || buttons == MessageBoxButtons.YesNoCancel) answer = DialogResult.No;
            if (FakeLab.Stage.OnMessage != null) answer = FakeLab.Stage.OnMessage(caption, text, buttons);
            return answer;
        }
        public static DialogResult Show(string text, string caption, MessageBoxButtons buttons, MessageBoxIcon icon) { return Ask(text, caption, buttons); }
        public static DialogResult Show(IWin32Window owner, string text, string caption, MessageBoxButtons buttons, MessageBoxIcon icon) { return Ask(text, caption, buttons); }
        public static DialogResult Show(IWin32Window owner, string text, string caption, MessageBoxButtons buttons, MessageBoxIcon icon, MessageBoxDefaultButton defaultButton) { return Ask(text, caption, buttons); }
    }

    // ---------------------------------------------------------------- the base of every control
    public class Control : IDisposable, IWin32Window
    {
        string text = "";

        public Control()
        {
            Controls = new ControlCollection(this);
            Enabled = true; Visible = true; TabStop = true;
            BackColor = Color.Empty; ForeColor = Color.Empty;
        }

        public string Text
        {
            get { return text; }
            set
            {
                string v = (value == null) ? "" : value;
                if (v == text) return;
                text = v;
                if (TextChanged != null) TextChanged(this, EventArgs.Empty);
            }
        }
        public bool Enabled { get; set; }
        public bool Visible { get; set; }
        public bool AutoSize { get; set; }
        public bool TabStop { get; set; }
        public DockStyle Dock { get; set; }
        public AnchorStyles Anchor { get; set; }
        public object Font { get; set; }                  // the real type is System.Drawing.Font, which cannot be made on Linux
        public Color BackColor { get; set; }
        public Color ForeColor { get; set; }
        public Padding Margin { get; set; }
        public Padding Padding { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public Size Size { get; set; }
        public Size ClientSize { get; set; }
        public Size MinimumSize { get; set; }
        public Size MaximumSize { get; set; }
        public Cursor Cursor { get; set; }
        public object Tag { get; set; }
        public Control Parent { get; set; }
        public ControlCollection Controls { get; private set; }
        public bool IsDisposed { get; private set; }
        public IntPtr Handle { get { return IntPtr.Zero; } }

        public event EventHandler TextChanged;
        public event EventHandler Click;
        public event EventHandler SizeChanged;

        public virtual void Dispose() { IsDisposed = true; }

        // for the tests (not in the real class): a control is usable only when it and every control around it are enabled and visible
        public bool CanUse
        {
            get
            {
                for (Control c = this; c != null; c = c.Parent) if (!c.Enabled || !c.Visible) return false;
                return true;
            }
        }
        public void RaiseSizeChanged() { if (SizeChanged != null) SizeChanged(this, EventArgs.Empty); }
        protected void RaiseClick() { if (Click != null) Click(this, EventArgs.Empty); }
        public Form FindForm()
        {
            Control c = this;
            while (c != null && !(c is Form)) c = c.Parent;
            return c as Form;
        }

        public class ControlCollection : IEnumerable
        {
            readonly Control owner;
            readonly List<Control> list = new List<Control>();
            public ControlCollection(Control owner) { this.owner = owner; }
            public void Add(Control c) { c.Parent = owner; list.Add(c); }
            public void Add(Control c, int column, int row) { Add(c); }
            public int Count { get { return list.Count; } }
            public Control this[int index] { get { return list[index]; } }
            public bool Contains(Control c) { return list.Contains(c); }
            public IEnumerator GetEnumerator() { return list.GetEnumerator(); }
        }
    }

    // ---------------------------------------------------------------- simple controls
    public class Label : Control { }

    public class Button : Control
    {
        public DialogResult DialogResult { get; set; }
        public AutoSizeMode AutoSizeMode { get; set; }

        // what a click does: the handlers run, then a button with a DialogResult closes its dialog
        public void PerformClick()
        {
            if (!CanUse) return;
            RaiseClick();
            if (DialogResult != DialogResult.None)
            {
                Form f = FindForm();
                if (f != null) f.CloseWith(DialogResult);
            }
        }
    }

    public class CheckBox : Control
    {
        bool isChecked;
        public bool Checked
        {
            get { return isChecked; }
            set
            {
                if (isChecked == value) return;
                isChecked = value;
                if (CheckedChanged != null) CheckedChanged(this, EventArgs.Empty);
            }
        }
        public event EventHandler CheckedChanged;
        public void PerformClick()
        {
            if (!CanUse) return;
            Checked = !Checked;
            RaiseClick();
        }
    }

    public class TextBox : Control
    {
        public bool Multiline { get; set; }
        public bool ReadOnly { get; set; }
        public bool WordWrap { get; set; }
        public bool UseSystemPasswordChar { get; set; }
        public ScrollBars ScrollBars { get; set; }
        public int TextLength { get { return Text.Length; } }
        public void AppendText(string s) { Text = Text + s; }
        public void Clear() { Text = ""; }
    }

    public class ComboBox : Control
    {
        int selected = -1;
        public ComboBox() { Items = new ObjectCollection(); }
        public ComboBoxStyle DropDownStyle { get; set; }
        public ObjectCollection Items { get; private set; }
        public int SelectedIndex
        {
            get { return selected; }
            set
            {
                if (selected == value) return;
                selected = value;
                if (SelectedIndexChanged != null) SelectedIndexChanged(this, EventArgs.Empty);
            }
        }
        public object SelectedItem { get { return (selected >= 0 && selected < Items.Count) ? Items[selected] : null; } }
        public event EventHandler SelectedIndexChanged;

        public class ObjectCollection : IEnumerable
        {
            readonly List<object> list = new List<object>();
            public int Add(object item) { list.Add(item); return list.Count - 1; }
            public int Count { get { return list.Count; } }
            public object this[int index] { get { return list[index]; } }
            public IEnumerator GetEnumerator() { return list.GetEnumerator(); }
        }
    }

    // ---------------------------------------------------------------- layout panels
    public class FlowLayoutPanel : Control
    {
        public bool WrapContents { get; set; }
        public FlowDirection FlowDirection { get; set; }
        public AutoSizeMode AutoSizeMode { get; set; }
    }

    public abstract class TableLayoutStyle { public SizeType SizeType { get; set; } }
    public class ColumnStyle : TableLayoutStyle
    {
        public float Width { get; set; }
        public ColumnStyle(SizeType type, float width) { SizeType = type; Width = width; }
    }
    public class RowStyle : TableLayoutStyle
    {
        public float Height { get; set; }
        public RowStyle(SizeType type, float height) { SizeType = type; Height = height; }
    }
    public class TableLayoutStyleCollection : IEnumerable
    {
        readonly List<TableLayoutStyle> list = new List<TableLayoutStyle>();
        public int Add(TableLayoutStyle style) { list.Add(style); return list.Count - 1; }
        public int Count { get { return list.Count; } }
        public TableLayoutStyle this[int index] { get { return list[index]; } }
        public IEnumerator GetEnumerator() { return list.GetEnumerator(); }
    }
    public class TableLayoutPanel : Control
    {
        public TableLayoutPanel() { ColumnStyles = new TableLayoutStyleCollection(); RowStyles = new TableLayoutStyleCollection(); }
        public int ColumnCount { get; set; }
        public int RowCount { get; set; }
        public TableLayoutStyleCollection ColumnStyles { get; private set; }
        public TableLayoutStyleCollection RowStyles { get; private set; }
    }

    // ---------------------------------------------------------------- the list
    public class ColumnHeader
    {
        public string Text { get; set; }
        public int Width { get; set; }
    }

    public class ListViewItem
    {
        internal bool selected;
        internal ListView owner;
        public ListViewItem() : this("") { }
        public ListViewItem(string text) { SubItems = new ListViewSubItemCollection(); SubItems.Add(text); }
        public string Text { get { return SubItems[0].Text; } set { SubItems[0].Text = value; } }
        public object Tag { get; set; }
        public bool Checked { get; set; }
        public Color BackColor { get; set; }
        public Color ForeColor { get; set; }
        public ListViewSubItemCollection SubItems { get; private set; }
        public bool Selected
        {
            get { return selected; }
            set
            {
                if (selected == value) return;
                selected = value;
                if (owner != null) owner.SelectionChanged(this);
            }
        }
        public void EnsureVisible() { }

        public class ListViewSubItem { public string Text { get; set; } }
        public class ListViewSubItemCollection : IEnumerable
        {
            readonly List<ListViewSubItem> list = new List<ListViewSubItem>();
            public ListViewSubItem Add(string text) { ListViewSubItem s = new ListViewSubItem(); s.Text = text; list.Add(s); return s; }
            public int Count { get { return list.Count; } }
            public ListViewSubItem this[int index] { get { return list[index]; } }
            public IEnumerator GetEnumerator() { return list.GetEnumerator(); }
        }
    }

    public class ListView : Control
    {
        public ListView()
        {
            Items = new ListViewItemCollection(this);
            Columns = new ColumnHeaderCollection();
            MultiSelect = true;
            ClientSize = new Size(1000, 400);
        }
        public View View { get; set; }
        public bool CheckBoxes { get; set; }
        public bool FullRowSelect { get; set; }
        public bool MultiSelect { get; set; }
        public bool HideSelection { get; set; }
        public bool GridLines { get; set; }
        public ListViewItemCollection Items { get; private set; }
        public ColumnHeaderCollection Columns { get; private set; }
        public int UpdateDepth { get; private set; }
        public int UpdateCalls { get; private set; }
        public SelectedListViewItemCollection SelectedItems
        {
            get
            {
                SelectedListViewItemCollection s = new SelectedListViewItemCollection();
                foreach (ListViewItem item in Items) if (item.selected) s.AddItem(item);
                return s;
            }
        }
        public void BeginUpdate() { UpdateDepth++; UpdateCalls++; }
        public void EndUpdate() { UpdateDepth--; }
        public event EventHandler SelectedIndexChanged;

        internal void SelectionChanged(ListViewItem changed)
        {
            if (!MultiSelect && changed.selected)
                foreach (ListViewItem item in Items) if (!object.ReferenceEquals(item, changed)) item.selected = false;
            if (SelectedIndexChanged != null) SelectedIndexChanged(this, EventArgs.Empty);
        }

        public class ListViewItemCollection : IEnumerable
        {
            readonly ListView owner;
            readonly List<ListViewItem> list = new List<ListViewItem>();
            public ListViewItemCollection(ListView owner) { this.owner = owner; }
            public ListViewItem Add(ListViewItem item) { item.owner = owner; list.Add(item); return item; }
            public void Clear()
            {
                bool hadSelection = false;
                foreach (ListViewItem item in list) { if (item.selected) hadSelection = true; item.selected = false; item.owner = null; }
                list.Clear();
                if (hadSelection && owner.SelectedIndexChanged != null) owner.SelectedIndexChanged(owner, EventArgs.Empty);
            }
            public int Count { get { return list.Count; } }
            public ListViewItem this[int index] { get { return list[index]; } }
            public IEnumerator GetEnumerator() { return list.ToArray().GetEnumerator(); }
        }

        public class SelectedListViewItemCollection : IEnumerable
        {
            readonly List<ListViewItem> list = new List<ListViewItem>();
            internal void AddItem(ListViewItem item) { list.Add(item); }
            public int Count { get { return list.Count; } }
            public ListViewItem this[int index] { get { return list[index]; } }
            public IEnumerator GetEnumerator() { return list.GetEnumerator(); }
        }

        public class ColumnHeaderCollection : IEnumerable
        {
            readonly List<ColumnHeader> list = new List<ColumnHeader>();
            public ColumnHeader Add(string text) { return Add(text, 60); }
            public ColumnHeader Add(string text, int width)
            {
                ColumnHeader h = new ColumnHeader(); h.Text = text; h.Width = width; list.Add(h); return h;
            }
            public int Count { get { return list.Count; } }
            public ColumnHeader this[int index] { get { return list[index]; } }
            public IEnumerator GetEnumerator() { return list.GetEnumerator(); }
        }
    }

    // ---------------------------------------------------------------- status bar, tool tip, timer
    public abstract class ToolStripItem { public string Text { get; set; } }
    public class ToolStripStatusLabel : ToolStripItem
    {
        public bool Spring { get; set; }
        public FakeLab.ContentAlignment TextAlign { get; set; }
    }
    public class ToolStripItemCollection : IEnumerable
    {
        readonly List<ToolStripItem> list = new List<ToolStripItem>();
        public int Add(ToolStripItem item) { list.Add(item); return list.Count - 1; }
        public int Count { get { return list.Count; } }
        public ToolStripItem this[int index] { get { return list[index]; } }
        public IEnumerator GetEnumerator() { return list.GetEnumerator(); }
    }
    public class StatusStrip : Control
    {
        public StatusStrip() { Items = new ToolStripItemCollection(); }
        public ToolStripItemCollection Items { get; private set; }
    }

    public class ToolTip : IDisposable
    {
        readonly Dictionary<Control, string> tips = new Dictionary<Control, string>();
        public void SetToolTip(Control control, string caption) { tips[control] = caption; }
        public string GetToolTip(Control control) { string s; return tips.TryGetValue(control, out s) ? s : ""; }
        public void Dispose() { }
    }

    public class Timer : IDisposable
    {
        public int Interval { get; set; }
        public bool Enabled { get; set; }
        public bool IsDisposed { get; private set; }
        public event EventHandler Tick;
        public void Start() { Enabled = true; }
        public void Stop() { Enabled = false; }
        public void Dispose() { Enabled = false; IsDisposed = true; }
        public void PerformTick() { if (Tick != null) Tick(this, EventArgs.Empty); }      // for the tests
    }

    // ---------------------------------------------------------------- forms
    public delegate void FormClosingEventHandler(object sender, FormClosingEventArgs e);

    public class FormClosingEventArgs : CancelEventArgs
    {
        public CloseReason CloseReason { get; private set; }
        public FormClosingEventArgs(CloseReason closeReason, bool cancel) : base(cancel) { CloseReason = closeReason; }
    }

    public class Form : Control
    {
        public Form() { ClientSize = new Size(1000, 700); }
        public FormStartPosition StartPosition { get; set; }
        public FormBorderStyle FormBorderStyle { get; set; }
        public bool MaximizeBox { get; set; }
        public bool MinimizeBox { get; set; }
        public bool ShowInTaskbar { get; set; }
        public Button AcceptButton { get; set; }
        public Button CancelButton { get; set; }
        public DialogResult DialogResult { get; set; }
        public bool IsClosed { get; private set; }
        public int ClosingCanceled { get; private set; }     // how many times a FormClosing handler said "stay open" (for the tests)
        public event EventHandler Shown;
        public event FormClosingEventHandler FormClosing;

        public DialogResult ShowDialog() { return Run(true); }
        public DialogResult ShowDialog(IWin32Window owner) { return Run(false); }

        DialogResult Run(bool isMainWindow)
        {
            IsClosed = false;
            DialogResult = DialogResult.None;
            FakeLab.Stage.Dialogs.Add(Text);
            if (Shown != null) Shown(this, EventArgs.Empty);
            if (isMainWindow)
            {
                // the main window: the test clicks around, then the window is closed like the X button would
                if (FakeLab.Stage.OnMainForm != null) FakeLab.Stage.OnMainForm(this);
                if (!IsClosed) TryClose();
                return DialogResult;
            }
            DialogResult answer = DialogResult.Cancel;
            if (FakeLab.Stage.OnDialog != null) answer = FakeLab.Stage.OnDialog(this);
            DialogResult = answer;
            IsClosed = true;
            return answer;
        }

        // the X button: the FormClosing handlers may say "stay open". Returns true when the window closed.
        public bool TryClose()
        {
            FormClosingEventArgs e = new FormClosingEventArgs(CloseReason.UserClosing, false);
            if (FormClosing != null) FormClosing(this, e);
            if (e.Cancel) { ClosingCanceled++; return false; }
            IsClosed = true;
            return true;
        }

        public void Close() { TryClose(); }
        internal void CloseWith(DialogResult result) { DialogResult = result; IsClosed = true; }
    }
}
