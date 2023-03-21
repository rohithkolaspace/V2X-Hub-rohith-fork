//==========================================================================
// Name        : PedestrianPlugin.cpp
// Author      : FHWA Saxton Transportation Operations Laboratory  
// Version     :
// Copyright   : Copyright (c) 2019 FHWA Saxton Transportation Operations Laboratory. All rights reserved.
// Description : Pedestrian Plugin
//==========================================================================
#pragma once
#include <string.h>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QHostAddress>
#include <QRegExp>
#include <QStringList>
#include <QSharedPointer>
#include <QObject>

#ifdef __linux__
#include <signal.h>
#include <unistd.h>
#endif
#include <queue>

#include <pedestrian_plugin_server_api_lib/OAIApiRouter.h>
#include <pedestrian_plugin_server_api_lib/OAIDefaultApiHandler.h>
#include <pedestrian_plugin_server_api_lib/OAIDefaultApiRequest.h>
#include <pedestrian_plugin_server_api_lib/OAIPersonalSafetyMessage.h>
#include <iostream>
#include <QString>

namespace PedestrianPluginAPI
{

/**
 * This plugin is an example to demonstrate the capabilities of a TMX plugin.
 */
class PedestrianPluginHandler: public OpenAPI::OAIDefaultApiHandler
{
public:
	PedestrianPluginHandler();
	
	std::string psmXML;

	// Virtual method override.
	void psmPost(OpenAPI::OAIPersonalSafetyMessage oai_personal_safety_message);
	
	void setPsmXML(std::string psm);
	std::string getPsmXML();

};

};

