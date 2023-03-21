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


void PedestrianPluginHandler::psmPost(OpenAPI::OAIPersonalSafetyMessage oai_personal_safety_message) {
	QString test = oai_personal_safety_message.asJson();
	qDebug() << "psmXML: " << test;

	auto reqObj = qobject_cast<OpenAPI::OAIDefaultApiRequest *>(sender());
	if (reqObj != nullptr)
	{	
		reqObj->psmPostResponse();
	}

}

void PedestrianPluginHandler::setPsmXML(std::string psm) {
	psmXML = psm;
}

std::string PedestrianPluginHandler::getPsmXML() {
	return psmXML;
}

}