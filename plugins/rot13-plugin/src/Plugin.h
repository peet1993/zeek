
#ifndef BRO_PLUGIN_DEMO_ROT13
#define BRO_PLUGIN_DEMO_ROT13

#include <plugin/Plugin.h>

namespace plugin {
namespace Demo_Rot13 {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
