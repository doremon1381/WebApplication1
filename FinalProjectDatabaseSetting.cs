namespace WebApplication1.Services
{
    public interface IFinalProjectDatabaseSetting
    {
        public string ConnectionString { get; set; }
        public string DatabaseName { get; set; }
    }

    public class FinalProjectDatabaseSetting : IFinalProjectDatabaseSetting
    {
        public string ConnectionString { get; set; } = string.Empty;
        public string DatabaseName { get; set; } = string.Empty;
    }
}
