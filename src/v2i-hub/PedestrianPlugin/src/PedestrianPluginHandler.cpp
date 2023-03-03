//==========================================================================
// Name        : PedestrianPlugin.cpp
// Author      : FHWA Saxton Transportation Operations Laboratory  
// Version     :
// Copyright   : Copyright (c) 2019 FHWA Saxton Transportation Operations Laboratory. All rights reserved.
// Description : Pedestrian Plugin
//==========================================================================
#include "include/PedestrianPluginHandler.hpp"

namespace PedestrianPluginAPI
{

/**
 * Construct a new PedestrianPlugin with the given name.
 *
 */
PedestrianPluginHandler::PedestrianPluginHandler() : OpenAPI::OAIDefaultApiHandler()
{
	std::cout << "In pedestrian plugin API handler constructor" << std::endl;
}


void PedestrianPluginHandler::sendXMLPost(OpenAPI::OAIPsm oai_psm) {
	psmXML = oai_psm.asJson().toStdString();
	std::cout << "as json: " << psmXML << std::endl;

}

std::string PedestrianPluginHandler::getPsmXML() {
	return psmXML;
}

}