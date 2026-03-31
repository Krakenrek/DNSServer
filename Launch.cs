using DNS;
using log4net.Config;

//Load basic configuration for logger
//I don't really know much about this library
BasicConfigurator.Configure();

//Create instance of DNSServer.
//This starts background listen thread
var server = new DNSServer(54);

//Lock main thread, so that our program will
//continue to listen to packets in background
server.WaitForShutdown();
