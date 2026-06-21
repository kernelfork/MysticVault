using System.Configuration;
using System.Data;
using System.Windows;

namespace MysticVault
{
    public partial class App : System.Windows.Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            AntiDebug.Initialize();
        }
    }

}
