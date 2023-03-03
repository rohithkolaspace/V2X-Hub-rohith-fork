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
#include <iostream>
#include "PedestrianPluginHandler.hpp"

namespace PedestrianPluginAPI
{

/**
 * This plugin is an example to demonstrate the capabilities of a TMX plugin.
 */
class PedestrianPluginRouter: public OpenAPI::OAIApiRouter
{
public:
	PedestrianPluginRouter();

	std::string psm;
	QSharedPointer<PedestrianPluginHandler> handler;

	std::string getPsm();

};

}

