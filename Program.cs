//proof of concept using NTFS stream feature for hidden purpose,
//based on powershell sdk, system.managment.automation, .net 7.0
//inspired from https://www.youtube.com/watch?v=BSFQAvDENTY
//and https://owasp.org/www-community/attacks/Windows_alternate_data_stream

using System.Management.Automation;

const string ASTRIX = "*";

const string COMMAND_GET_ITEM = "Get-Item";
const string COMMAND_SET_CONTENT = "Set-Content";
const string COMMAND_GET_CONTENT = "Get-Content";
const string COMMAND_REMOVE_ITEM = "Remove-Item";

const string PARAMETER_PATH = "Path";
const string PARAMETER_VALUE = "Value";
const string PARAMETER_STREAM = "Stream";
const string MICROSOFT_DEFAULT_STREAM = ":$DATA";

ConsoleColor previousColor = Console.ForegroundColor;
Console.ForegroundColor = ConsoleColor.Blue;

#region Methods
void title()
{

    Console.WriteLine(@"    )         (     (         (           (                   *    ");
    Console.WriteLine(@" ( /(   *   ) )\ )  )\ )      )\ )  *   ) )\ )       (      (  `   ");
    Console.WriteLine(@" )\())` )  /((()/( (()/(     (()/(` )  /((()/( (     )\     )\))(  ");
    Console.WriteLine(@"((_)\  ( )(_))/(_)) /(_))___  /(_))( )(_))/(_)))\ ((((_)(  ((_)()\ ");
    Console.WriteLine(@" _((_)(_(_())(_))_|(_)) |___|(_)) (_(_())(_)) ((_) )\ _ )\ (_()((_)");
    Console.WriteLine(@"| \| ||_   _|| |_  / __|     / __||_   _|| _ \| __|(_)_\(_)|  \/  |");
    Console.WriteLine(@"| .` |  | |  | __| \__ \     \__ \  | |  |   /| _|  / _ \  | |\/| |");
    Console.WriteLine(@"|_|\_|  |_|  |_|   |___/     |___/  |_|  |_|_\|___|/_/ \_\ |_|  |_|");
    Console.WriteLine(@"-------------------------------------------------------------------");
    Console.WriteLine(@" NTFS-ALTERNATIVE-STREAM, www.rudenetworks.com, beta 0.45          ");
}
void helper()
{
    Console.WriteLine(@" NtfsAStream.exe <commands> <file> <*payload>                      ");
    Console.WriteLine();
    Console.WriteLine(@" Commands: ");
    Console.WriteLine(@" Get-Item: Detect Alternative $DATA stream.");
    Console.WriteLine(@" Set-Content: set content for alternative $DATA stream.");
    Console.WriteLine(@" Get-Content: get content from alternative $DATA stream.");
    Console.WriteLine(@" Remote-Item: remove stream from source.");
    Console.WriteLine();
    Console.WriteLine(@" Examples: ");
    Console.WriteLine(@" NtfsAStream.exe Get-Item <file>");
    Console.WriteLine(@" NtfsAStream.exe Set-Content <file> <section> <string>");
    Console.WriteLine(@" NtfsAStream.exe Get-Content <file> <section>");
    Console.WriteLine(@" NtfsaStream.exe Remove-Item <file> <section>");
}

string readMwSection(string file, string section)
{

    PowerShell ps = PowerShell.Create();
    string data = string.Empty;
    ps.AddCommand(COMMAND_GET_CONTENT).AddParameter(PARAMETER_PATH, string.Format("{0}:{1}", file, section));
    System.Collections.ObjectModel.Collection<PSObject> collection = ps.Invoke();

    if (collection.Count != 0)
    {
        data = collection.First().ToString();
    }

    return data;
}

string[] streamFeatureDetection(string file)
{

    PowerShell ps = PowerShell.Create();
    ps.AddCommand(COMMAND_GET_ITEM).AddParameter(PARAMETER_PATH, file).AddParameter(PARAMETER_STREAM, ASTRIX);
    System.Collections.ObjectModel.Collection<PSObject> collection = ps.Invoke();

    List<string> list = new List<string>();
    if (collection.Count != 0)
    {
        for (int i = 0; i < collection.Count; i++)
        {
            string? detectedCollection = collection[i].Properties[name: PARAMETER_STREAM].Value.ToString();
            if (detectedCollection != null)
            {
                list.Add(detectedCollection.ToString());
            }
        }

    }

    return list.ToArray();

}

void writeMwSection(string file, string section, string data)
{
    PowerShell ps = PowerShell.Create();
    ps.AddCommand(COMMAND_SET_CONTENT).AddParameter(PARAMETER_PATH, file).AddParameter(PARAMETER_STREAM, section).AddParameter(PARAMETER_VALUE, data);
    ps.Invoke();
}

void removeItem(string file, string section)
{

    PowerShell ps = PowerShell.Create();
    ps.AddCommand(COMMAND_REMOVE_ITEM).AddParameter(PARAMETER_PATH, file).AddParameter(PARAMETER_STREAM, section);
    ps.Invoke();
}

#endregion


try
{
    title();

    if (args.Length < 2)
    {
        helper();
    }
    else
    {

        if (args[0] == COMMAND_GET_ITEM)
        {
            string file = args[1];
            string[] sections = streamFeatureDetection(file);
            if (sections.Length != 0)
            {
                Console.WriteLine(string.Format(" Detect {0} Streams:", sections.Length));

                if (sections.Length > 1)
                {
                    Console.WriteLine(string.Format(" Potential Threat: Alternative Streams Detected", sections.Length));
                }

                for (int i = 0; i < sections.Length; i++)
                {
                    if (sections[i] == MICROSOFT_DEFAULT_STREAM)
                    {
                        Console.WriteLine(string.Format(" Detect Default Stream {0}.", sections[i]));
                    }
                    else
                    {
                        Console.WriteLine(string.Format(" Detect Alternative Stream {0}.", sections[i]));
                    }
                }
            }
            else
            {
                Console.WriteLine(" No Stream Detected");
            }
        }
        else if (args[0] == COMMAND_GET_CONTENT)
        {
            string file = args[1];
            string section = args[2];

            string data = readMwSection(file, section);
            Console.WriteLine(String.Format("{0}:{1}", section, data));
        }
        else if (args[0] == COMMAND_REMOVE_ITEM)
        {
            string file = args[1];
            string section = args[2];

            removeItem(file, section);

        }
        else if (args[0] == COMMAND_SET_CONTENT)
        {
            if (args.Length < 3)
            {
                helper();
            }
            else
            {
                string file = args[1];
                string section = args[2];
                string data = args[3];

                writeMwSection(file, section, data);
                Console.WriteLine(String.Format("Write {0} Complete", section));
            }
        }
        else
        {
            helper();
        }
    }
}
catch (Exception ex)
{
    Console.WriteLine(ex.ToString());
}
finally
{
    Console.ForegroundColor = previousColor;
}

