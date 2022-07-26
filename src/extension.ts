import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import {Config, DownloadURLs, HighlightTypes, InferenceModes, InformationLevels} from './config';

// const axios = require('axios');
const fs = require('fs');
const Path = require('path');
const fsa = require('fs/promises');
// const formdata = require('form-data');
// const extract = require('extract-zip');
// const parser = require('xml2js');

var config:Config;

export function activate(context: vscode.ExtensionContext) {
	
	let disposable = vscode.commands.registerCommand('aibughunter.helloWorld', () => {
		vscode.window.showInformationMessage('Hello World from AIBugHunter!');
	});

	intialiseConfig();
	
	context.subscriptions.push(disposable);
}

export function deactivate() {}


/**
 * Initialises global configuration from VS Code user configuration
 */
function intialiseConfig(){

	const vsconfig = vscode.workspace.getConfiguration('AiBugHunter');

	config = {
		inferenceMode: vsconfig.inference.inferenceMode,
		gpu: vsconfig.inference.EnableGPU,
		inferenceURL: vsconfig.inference.inferenceServerURL,
		informationLevel: vsconfig.diagnostics.informationLevel,
		showDescription: vsconfig.diagnostics.showDescription,
		highlightType: vsconfig.diagnostics.highlightSeverityType,
		maxLines: vsconfig.diagnostics.maxNumberOfLines,
		delay: vsconfig.diagnostics.delayBeforeAnalysis,
		modelPath: vsconfig.model.downloadLocation,
		// lineModelURL: DownloadURLs.lineModel,
		// sevModelURL: DownloadURLs.sevModel,
		// cweModelURL: DownloadURLs.cweModel,
		cwePath: vsconfig.cWE.downloadLocation,
		// cweURL: DownloadURLs.cweList
	};
}