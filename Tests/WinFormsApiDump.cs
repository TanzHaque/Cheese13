// WinFormsApiDump.cs - writes down the public members of the WinForms / Drawing types the window uses, read from the
// .NET assemblies with reflection (on the sandbox: Mono's copies, which have the same public names as .NET Framework 4.x).
// The result (winforms-api.txt) is what Tests\Test-GuiApi.ps1 checks lib\Gui.ps1 against. You never need to run this on Windows.
//
//   mcs -out:WinFormsApiDump.exe WinFormsApiDump.cs
//   mono WinFormsApiDump.exe winforms-types.txt winforms-api.txt
//
// winforms-types.txt = one full type name per line (nested types with a plus: System.Windows.Forms.Control+ControlCollection).
// Every type named there is dumped, and so is every WinForms / Drawing type that one of their properties, methods or events returns
// (one level deep), so that a chain like  $form.Controls.Add(...)  can be followed.
//
// Line format (tab separated):
//   TYPE  fullname  basetype  kind(class|struct|enum|interface|delegate)
//   P     name  type  RW|R|W  declaringtype        property
//   I     name  type  paramtypes  declaringtype     indexer
//   M     name  returntype  paramtypes  S|empty  declaringtype     method (one line per overload; S = static)
//   E     name  handlertype  declaringtype          event
//   F     name  type  S|I  declaringtype            field (S = static / const, I = instance)
//   C     paramtypes                                constructor (one line per overload)
//   ENUM  flags|plain  underlyingtype                    (first line after the TYPE line of an enum)
//   V     name  number                              enum value
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

public static class WinFormsApiDump
{
    static Assembly forms;
    static Assembly drawing;
    static SortedDictionary<string, Type> done = new SortedDictionary<string, Type>(StringComparer.Ordinal);

    static Type Find(string name)
    {
        Type t = forms.GetType(name, false);
        if (t == null) t = drawing.GetType(name, false);
        return t;
    }

    static bool Interesting(Type t)
    {
        while (t != null && (t.IsArray || t.IsByRef)) t = t.GetElementType();
        if (t == null || t.FullName == null) return false;
        return t.FullName.StartsWith("System.Windows.Forms") || t.FullName.StartsWith("System.Drawing");
    }

    static string Name(Type t)
    {
        return t.FullName != null ? t.FullName : t.Name;
    }

    static string Params(ParameterInfo[] ps)
    {
        List<string> l = new List<string>();
        foreach (ParameterInfo p in ps) l.Add(Name(p.ParameterType));
        return string.Join(",", l.ToArray());
    }

    static string Kind(Type t)
    {
        if (t.IsEnum) return "enum";
        if (typeof(Delegate).IsAssignableFrom(t)) return "delegate";
        if (t.IsInterface) return "interface";
        if (t.IsValueType) return "struct";
        return "class";
    }

    static void Dump(Type t, StreamWriter w, List<Type> next, bool follow)
    {
        w.WriteLine("TYPE\t" + Name(t) + "\t" + (t.BaseType != null ? Name(t.BaseType) : "") + "\t" + Kind(t));
        if (t.IsEnum)
        {
            bool flags = t.GetCustomAttributes(typeof(FlagsAttribute), false).Length > 0;
            w.WriteLine("ENUM\t" + (flags ? "flags" : "plain") + "\t" + Enum.GetUnderlyingType(t).Name);
            foreach (string n in Enum.GetNames(t)) w.WriteLine("V\t" + n + "\t" + Convert.ToInt64(Enum.Parse(t, n)));
            return;
        }
        BindingFlags f = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.FlattenHierarchy;
        foreach (ConstructorInfo c in t.GetConstructors(BindingFlags.Public | BindingFlags.Instance))
            w.WriteLine("C\t" + Params(c.GetParameters()));
        foreach (PropertyInfo p in t.GetProperties(f))
        {
            ParameterInfo[] idx = p.GetIndexParameters();
            if (idx.Length > 0) { w.WriteLine("I\t" + p.Name + "\t" + Name(p.PropertyType) + "\t" + Params(idx) + "\t" + Name(p.DeclaringType)); continue; }
            string rw = (p.CanRead ? "R" : "") + (p.CanWrite ? "W" : "");
            w.WriteLine("P\t" + p.Name + "\t" + Name(p.PropertyType) + "\t" + rw + "\t" + Name(p.DeclaringType));
            if (follow && Interesting(p.PropertyType)) next.Add(p.PropertyType);
        }
        foreach (MethodInfo m in t.GetMethods(f))
        {
            if (m.IsSpecialName) continue;                         // get_X, set_X, add_X, remove_X, operators
            w.WriteLine("M\t" + m.Name + "\t" + Name(m.ReturnType) + "\t" + Params(m.GetParameters()) + "\t" + (m.IsStatic ? "S" : "") + "\t" + Name(m.DeclaringType));
            if (follow && Interesting(m.ReturnType)) next.Add(m.ReturnType);
        }
        foreach (EventInfo e in t.GetEvents(f))
            w.WriteLine("E\t" + e.Name + "\t" + Name(e.EventHandlerType) + "\t" + Name(e.DeclaringType));
        foreach (FieldInfo fi in t.GetFields(f))
            w.WriteLine("F\t" + fi.Name + "\t" + Name(fi.FieldType) + "\t" + (fi.IsStatic ? "S" : "I") + "\t" + Name(fi.DeclaringType));
    }

    public static int Main(string[] args)
    {
        if (args.Length < 2) { Console.Error.WriteLine("usage: WinFormsApiDump types.txt out.txt"); return 2; }
        forms = Assembly.Load("System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
        drawing = Assembly.Load("System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
        List<Type> roots = new List<Type>();
        foreach (string line in File.ReadAllLines(args[0]))
        {
            string n = line.Trim();
            if (n.Length == 0 || n.StartsWith("#")) continue;
            Type t = Find(n);
            if (t == null) { Console.Error.WriteLine("NOT FOUND: " + n); return 1; }
            roots.Add(t);
        }
        List<Type> second = new List<Type>();
        using (StreamWriter w = new StreamWriter(args[1], false, new UTF8Encoding(false)))
        {
            w.NewLine = "\n";
            w.WriteLine("# generated by WinFormsApiDump.cs from " + forms.GetName().Version + " of System.Windows.Forms; do not edit");
            foreach (Type t in roots)
            {
                if (done.ContainsKey(Name(t))) continue;
                done[Name(t)] = t;
                Dump(t, w, second, true);
            }
            // one more level: the types the roots hand out (listed fully, but their own results are not followed again)
            List<Type> third = new List<Type>();
            foreach (Type t in second)
            {
                Type u = t;
                while (u.IsArray || u.IsByRef) u = u.GetElementType();
                if (done.ContainsKey(Name(u))) continue;
                done[Name(u)] = u;
                Dump(u, w, third, false);
            }
        }
        Console.WriteLine("types written: " + done.Count);
        return 0;
    }
}
