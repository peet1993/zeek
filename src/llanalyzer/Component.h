// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_COMPONENT_H
#define ANALYZER_COMPONENT_H

#include "Tag.h"

#include "plugin/Component.h"
#include "plugin/TaggedComponent.h"

#include "../zeek-config.h"
#include "../util.h"

namespace llanalyzer {

class Analyzer;

class Component : public plugin::Component,
                  public plugin::TaggedComponent<llanalyzer::Tag> {
public:
	typedef Analyzer* (*factory_callback)();

	Component(const std::string& name, factory_callback factory, Tag::subtype_t subtype = 0, bool enabled = true);
	~Component() override;

	/**
	 * Initialization function. This function has to be called before any
	 * plugin component functionality is used; it is used to add the
	 * plugin component to the list of components and to initialize tags
	 */
	void Initialize() override;

	/**
	 * Returns the analyzer's factory function.
	 */
	factory_callback Factory() const {
	    return factory;
	}

	/**
	 * Returns true if the analyzer is currently enabled and hence
	 * available for use.
	 */
	bool Enabled() const {
	    return enabled;
	}

	/**
	 * Enables or disables this analyzer.
	 *
	 * @param arg_enabled True to enabled, false to disable.
	 *
	 */
	void SetEnabled(bool arg_enabled) {
	    enabled = arg_enabled;
	}

protected:
	/**
	  * Overriden from plugin::Component.
	  */
	void DoDescribe(ODesc* d) const override;

private:
	factory_callback factory;	// The analyzer's factory callback.
	bool enabled;	// True if the analyzer is enabled.
};

}

#endif
