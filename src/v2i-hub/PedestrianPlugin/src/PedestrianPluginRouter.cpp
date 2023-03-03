//==========================================================================
// Name        : PedestrianPlugin.cpp
// Author      : FHWA Saxton Transportation Operations Laboratory  
// Version     :
// Copyright   : Copyright (c) 2019 FHWA Saxton Transportation Operations Laboratory. All rights reserved.
// Description : Pedestrian Plugin
//==========================================================================

#include "include/PedestrianPluginRouter.hpp"

namespace PedestrianPluginAPI
{

/**
 * Construct a new PedestrianPlugin with the given name.
 *
 */
PedestrianPluginRouter::PedestrianPluginRouter() : OpenAPI::OAIApiRouter()
{
	std::cout << "In pedestrian plugin API router constructor" << std::endl;

	handler = QSharedPointer<PedestrianPluginHandler>::create();
	if (handler != nullptr)
	{
		setOAIDefaultApiHandler(handler);
	}
}

std::string PedestrianPluginRouter::getPsm() {
	return handler->getPsmXML();
}

}