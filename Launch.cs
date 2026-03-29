using DNS;
using log4net.Config;

BasicConfigurator.Configure();

var server = new DNSServer(53);
        
server.WaitForShutdown();
