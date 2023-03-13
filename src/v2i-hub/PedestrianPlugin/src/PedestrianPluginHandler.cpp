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


void PedestrianPluginHandler::psmPost(OpenAPI::OAIPsm oai_psm) {
	psmXML = oai_psm.asJson().toStdString();
	
	auto reqObj = qobject_cast<OpenAPI::OAIDefaultApiRequest *>(sender());
	if (reqObj != nullptr)
	{	
		//get raw socket and set psm xml
		reqObj->psmPostResponse();
	}

}

std::string PedestrianPluginHandler::getPsmXML() {
	return psmXML;
}

}