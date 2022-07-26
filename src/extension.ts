import { rejects } from 'assert';
import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import {Config, DebugTypes, DownloadURLs, HighlightTypes, InferenceModes, InformationLevels} from './config';

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const fsa = require('fs/promises');
// const formdata = require('form-data');
// const extract = require('extract-zip');
// const parser = require('xml2js');

var config:Config;

export function activate(context: vscode.ExtensionContext) {
	
	let disposable = vscode.commands.registerCommand('aibughunter.helloWorld', () => {
		vscode.window.showInformationMessage('Hello World from AIBugHunter!');
	});

	debugMessage(DebugTypes.info, "Extension activated");

	intialiseConfig();

	debugMessage(DebugTypes.info, "Config loaded, checking model presence");

	modelInit().then(() => {
		debugMessage(DebugTypes.info, "Model successfully loaded");
	}
	).catch(err => {
		debugMessage(DebugTypes.error, err);
		// console.log(err);
	}
	);


	
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

/**
 * Check if the model is downloaded and download if not
 */
 async function modelInit(){
	const lineModelPath = path.resolve(__dirname,config.modelPath, 'line_model.onnx');
	const sevModelPath = path.resolve(__dirname,config.modelPath, 'sev_model.onnx');
	const cweModelPath = path.resolve(__dirname,config.modelPath, 'cwe_model.onnx');

	var downloads = [];

	if(!fs.existsSync(lineModelPath)){
		debugMessage(DebugTypes.info, "line_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(lineModelPath), DownloadURLs.lineModel));
	}
	
	if(!fs.existsSync(sevModelPath)){
		debugMessage(DebugTypes.info, "sve_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(sevModelPath), DownloadURLs.sevModel));
	}

	if(!fs.existsSync(cweModelPath)){
		debugMessage(DebugTypes.info, "cwe_model not found, downloading...");
		// downloads.push(downloadEngine(fs.createWriteStream(cweModelPath), DownloadURLs.cweModel));
	}

	await Promise.all(downloads).then(() => {	
		debugMessage(DebugTypes.info, "All missing models downloaded");	
		return Promise.resolve();
	}
	).catch(err => {
		debugMessage(DebugTypes.error, "Error occured while downloading models");
		return Promise.reject(err);
	}
	);
}

/**
 * Downloads stream from specified URL then writes to file
 * @param writer Stream to write to
 * @param url Download URL
 * @returns Promise that resolves when download is complete
 */
async function downloadEngine(writer:any, url: string){

	const response = await axios({
		method: 'GET',
		url: url,
		responseType: 'stream'
	});
	
	response.data.pipe(writer);

	return new Promise((resolve, reject) => {
		writer.on('finish', resolve);
		writer.on('error', reject);
	});
}

/**
 * Print formatted debug message to console
 * @param type Type of message to log (Info, Error)
 * @param message Message to display
 */
function debugMessage(type:string, message:string){
	// Print with ISO date
	console.log("[" + type + "] [" + new Date().toISOString() + "] " + message);
}