
#include "Plugin.h"

namespace plugin { namespace Demo_Rot13 { Plugin plugin; } }

using namespace plugin::Demo_Rot13;

plugin::Configuration Plugin::Configure()
	{
	plugin::Configuration config;
	config.name = "Demo::Rot13";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
