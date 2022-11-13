import { rejects, strict } from 'assert';
import { copyFileSync } from 'fs';
import { EventEmitter } from 'stream';
import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import { MessageChannel } from 'worker_threads';
import {DebugTypes, HighlightTypes, InferenceModes, InfoLevels, ProgressStages, DiagnosticInformation} from './config';
import { stdin } from 'process';

// import class from files
import { LocalInference, RemoteInference } from './inference';
import { debugMessage, downloadEngine, Progress, progressHandler } from './common';

// modules
export const axios = require('axios');
export const fs = require('fs');
export const path = require('path');
export const fsa = require('fs/promises');
// const formdata = require('form-data');
export const extract = require('extract-zip');
export const parser = require('xml2js');
export const dotenv = require('dotenv').config({ path: path.join(__dirname, '..', 'resources' , 'config') });

// export let config:DocumentConfig;
export let inferenceMode: LocalInference | RemoteInference;

const parentDir = path.resolve(__dirname, '..');
export const progressEmitter = new Progress();
let statusBarItem: vscode.StatusBarItem;
let busy = false;

export let config: Config;

// Implement Config as a class (fake singleton)
export class Config {

	inferenceMode: InferenceModes = InferenceModes.local;
	useCUDA: boolean = false;
	infoLevel: InfoLevels = InfoLevels.fluent;
	customDiagInfos: DiagnosticInformation | undefined;
	showDescription: boolean = true;
	diagnosticSeverity: vscode.DiagnosticSeverity = vscode.DiagnosticSeverity.Error;
	maxIndicatorLines: number = 1;
	typeWaitDelay: number = 1500;

	downloadPaths: {[key: string]: string} = {
		"lineModel": ".",
		"sevModel": ".",
		"cweModel": ".",
		"cweXMLZip": ".",
	};

	cweXMLFile: string = path.join(__dirname, ".." , "resources", "cwec_v4.8.xml");

	subDir: string = ".";
	localInferenceResDir: string = "./local";

	inferenceURLs: {[key: string]: string} = {
		onPremise: "http://localhost:5000",
		cloud: "https://0.0.0.0:5000", // Cloud inference not supported yet
	};

	// Endpoints as nested dictionaries
	endpoints: {[key: string]: {[key: string ]: string}} = {
		line:{
			cpu: "/api/v1/cpu/predict",
			gpu: "/api/v1/gpu/predict",
		},
		cwe:{
			cpu: "/api/v1/cwe/cpu/predict",
			gpu: "/api/v1/cwe/gpu/predict",
		},
		sev:{
			cpu: "/api/v1/sev/cpu/predict",
			gpu: "/api/v1/sev/gpu/predict",
		}
	};

	downloadURLs: {[key: string]: string | undefined} = {
		lineModel: "",
		sevModel: "",
		cweModel: "",
		cweXML: "",
		inferencePack: ""
	};

	constructor(){
		this.loadConfig();
	}

	loadConfig(){
		const vsConfig = vscode.workspace.getConfiguration("AiBugHunter");

		this.inferenceMode = vsConfig.inference.inferenceMode;
		this.useCUDA = vsConfig.inference.useCUDA;
		this.infoLevel = vsConfig.diagnostics.informationLevel;
		this.customDiagInfos = vsConfig.diagnostics.customDiagnosticInformation;
		this.showDescription = vsConfig.diagnostics.showDescription;
		this.maxIndicatorLines = vsConfig.diagnostics.maxNumberOfLines;
		this.typeWaitDelay = vsConfig.diagnostics.delayBeforeAnalysis;
		// Removed ability to specify download location for now
		// Everything should be downloaded to the extension directory and in the resources folder
		// this.downloadPaths.lineModel = vsConfig.model.downloadLocation;
		// this.downloadPaths.sevModel = vsConfig.model.downloadLocation;
		// this.downloadPaths.cweModel = vsConfig.model.downloadLocation;
		// this.downloadPaths.cweXML = vsConfig.cwe.downloadLocation;
		// this.subDir = vsConfig.resources.subDirectory;
		this.inferenceURLs.onPremise = vsConfig.inference.inferenceServerURL;

		switch(vsConfig.diagnostics.highlightSeverityType){
			case "Error": this.diagnosticSeverity = vscode.DiagnosticSeverity.Error; break;
			case "Warning": this.diagnosticSeverity = vscode.DiagnosticSeverity.Warning; break;
			case "Information": this.diagnosticSeverity = vscode.DiagnosticSeverity.Information; break;
			case "Hint": this.diagnosticSeverity = vscode.DiagnosticSeverity.Hint; break;
		}

		this.downloadURLs.lineModel = process.env.LINE_MODEL_URL;
		this.downloadURLs.sevModel = process.env.SEV_MODEL_URL;
		this.downloadURLs.cweModel = process.env.CWE_MODEL_URL;
		this.downloadURLs.cweXML = process.env.CWE_XML_URL;
		this.downloadURLs.inferencePack = process.env.INFERENCE_PACK_URL;
	}

}

export async function activate(context: vscode.ExtensionContext) {

	debugMessage(DebugTypes.info, "Extension initialised");

	config = new Config();

	const diagnosticCollection = vscode.languages.createDiagnosticCollection('AIBugHunter');
	context.subscriptions.push(diagnosticCollection);

	progressEmitter.on('init', async (stage:ProgressStages) =>{

		progressHandler(stage);

		switch(stage){
			case ProgressStages.extensionInitStart:
				// Download models and CWE list if not found
				await init();
				break;
			case ProgressStages.analysisStart:
				statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
				statusBarItem.text = "AIBugHunter: Ready";
				statusBarItem.show();
				break;
		}
	});

	progressEmitter.emit('init', ProgressStages.extensionInitStart);

	// When user changes settings
	vscode.workspace.onDidChangeConfiguration((e) => {
		debugMessage(DebugTypes.info, "Configuration Changed");
		config.loadConfig();
		progressEmitter.emit('init', ProgressStages.extensionInitStart);
	});

	// When user changes document
	vscode.window.onDidChangeActiveTextEditor((e) => {
		debugMessage(DebugTypes.info, "Active text editor changed");
		if(e?.document.languageId === 'cpp'){
			progressEmitter.emit('init', ProgressStages.extensionInitStart);
		}
	});

	// Manually restart analysis
	const restart = 'aibughunter.restart';
	const restartCommand = vscode.commands.registerCommand(restart, () => {
		debugMessage(DebugTypes.info, "Restarting extension");
		progressEmitter.emit('init', ProgressStages.extensionInitStart);
	}
	);
	context.subscriptions.push(restartCommand);
	statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
	statusBarItem.command = restart;
	statusBarItem.text = 'Restart AIBugHunter';
	statusBarItem.name = 'AIBugHunter';
	statusBarItem.tooltip = 'Click to reinitialise AIBugHunter';
	statusBarItem.show();
	context.subscriptions.push(statusBarItem);
}


/**
 * Initialises the extension by downloading the models and CWE list if not found on locally
 * @returns Promise that resolves when models and CWE list are loaded, rejects if error occurs
 */
 async function init() {
	var start = new Date().getTime();

	debugMessage(DebugTypes.info, "Config loaded, checking model and CWE list presence");

	var downloadCandidates = [downloadCWEXML()];

	downloadCandidates.push(downloadModels());

	// if(config.inferenceMode === InferenceModes.local){
	// 	downloadCandidates.push(localInit());
	// }

	await Promise.all(downloadCandidates).then(() => {
		var end = new Date().getTime();
		debugMessage(DebugTypes.info, "Initialisation took " + (end - start) + "ms");
		debugMessage(DebugTypes.info, "Model and CWE list successfully loaded");
		progressEmitter.emit('end', ProgressStages.extensionInitEnd);
		return Promise.resolve();
	}
	).catch(err => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);
}

/**
 * Checks for presence of cwe list zip/xml file and downloads if not present
 * @returns Promise that resolves when CWE list is loaded
 */
async function downloadCWEXML() {

	progressEmitter.emit('update', ProgressStages.downloadCWEXMLStart);

	// const zipDownloadDir = (config.downloadPaths.cweXML === ".") ? parentDir + "/" + config.downloadPaths.cweXML : config.downloadPaths.cweXML;
	const zipDownloadDir = parentDir + "/resources";
	// const zipPath = path.resolve(zipDownloadDir, config.subDir, 'cwec_latest.xml.zip');
	const zipPath = path.resolve(zipDownloadDir, 'cwec_latest.xml.zip');
	// const extractTarget = path.resolve(zipDownloadDir, config.subDir);
	const extractTarget = path.resolve(zipDownloadDir);

	// Create subdirectory if specified and doesn't exist
	// if (config.subDir && !fs.existsSync(extractTarget)) {
	// 	fs.mkdirSync(path.join(zipDownloadDir, config.subDir), (err: any) => {
	// 		if (err) {
	// 			return console.error(err);
	// 		}
	// 		debugMessage(DebugTypes.info, "Directory created successfully at " + extractTarget);
	// 	}
	// 	);
	// }

	var files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));

	// Download if no xml file found
	if (!fs.existsSync(zipPath) || files.length === 0) { // If zip file doesn't exist or no xml files found
		debugMessage(DebugTypes.info, "cwec_latest.xml.zip not found, downloading...");
		await downloadEngine(fs.createWriteStream(zipPath), config.downloadURLs.cweXML).then(() => {
			debugMessage(DebugTypes.info, "cwec_latest.xml.zip downloaded");
		}
		).catch(err => {
			debugMessage(DebugTypes.error, "Error occured while downloading cwec_latest.xml.zip");
			return Promise.reject(err);
		}
		);
	} else if (files.length > 0) { // If xml file found
		debugMessage(DebugTypes.info, "xml file already exists, skipping download...");
		files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));
		// config.cweXMLFile = path.resolve(zipDownloadDir, config.subDir, files[0]);
		config.cweXMLFile = path.resolve(zipDownloadDir, files[0]);
		return Promise.resolve();
	};

	// Extract zip file
	debugMessage(DebugTypes.info, "Extracting cwec_latest.xml.zip");

	await extract(zipPath, { dir: extractTarget }).then(() => {
		debugMessage(DebugTypes.info, "cwec_latest.xml.zip extracted at " + extractTarget.toString());
		files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));
		// config.cweXMLFile = path.resolve(zipDownloadDir, config.subDir, files[0]);
		config.cweXMLFile = path.resolve(zipDownloadDir, files[0]);
		return Promise.resolve();
	}
	).catch((err: any) => {
		debugMessage(DebugTypes.error, "Error occured while extracting cwec_latest.xml.zip");
		return Promise.reject(err);
	}
	);
}

/**
 * Check if the model is downloaded and download if not
 */
 async function downloadModels(){

	progressEmitter.emit('update', ProgressStages.downloadModelStart);

	// const modelPath = (config.downloadPaths.lineModel === ".")? parentDir + "/" + config.downloadPaths.lineMode: config.downloadPaths.lineMode;

	let modelPath = parentDir + "/resources/local-inference/models";

	if(!fs.existsSync(path.join(modelPath))){
		fs.mkdirSync(path.join(modelPath), (err: any) => {
			if (err) {
				return console.error(err);
			}
			debugMessage(DebugTypes.info, "Directory created successfully at " + (path.join(modelPath)));
		}
		);
	}

	// const lineModelPath = path.resolve(modelPath, config.resSubDir,'line_model.onnx');
	const lineModelPath = path.resolve(modelPath, 'line_model.onnx');
	// const sevModelPath = path.resolve(modelPath,config.resSubDir ,'sev_model.onnx');
	const sevModelPath = path.resolve(modelPath, 'sev_model.onnx');
	// const cweModelPath = path.resolve(modelPath,config.resSubDir ,'cwe_model.onnx');
	const cweModelPath = path.resolve(modelPath, 'cwe_model.onnx');

	// const localInferenceData = path.resolve(modelPath, config.resSubDir, 'local-inference-data.zip');
	const localInferenceData = path.resolve(modelPath, 'local-inference-data.zip');

	// Create subdirectory if specified and doesn't exist
	// if(config.resSubDir && !fs.existsSync(path.join(modelPath, config.resSubDir))){
	// 	fs.mkdirSync(path.join(modelPath, config.resSubDir), (err: any) => {
	// 		if (err) {
	// 			return console.error(err);
	// 		}
	// 		debugMessage(DebugTypes.info, "Directory created successfully at " + (path.join(modelPath, config.resSubDir)));
	// 	}
	// 	);
	// }

	var downloads = [];

	// const extractTarget = path.resolve(modelPath, config.resSubDir);
	const extractTarget = path.resolve(modelPath);

	if(!fs.existsSync(lineModelPath)){
		debugMessage(DebugTypes.info, "line_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(lineModelPath), config.downloadURLs.lineModel));
	} else {
		debugMessage(DebugTypes.info, "line_model found at " + lineModelPath + ", skipping download...");
	}
	
	if(!fs.existsSync(sevModelPath)){
		debugMessage(DebugTypes.info, "sve_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(sevModelPath), config.downloadURLs.sevModel));
	} else {
		debugMessage(DebugTypes.info, "sev_model found at " + sevModelPath + ", skipping download...");
	}

	if(!fs.existsSync(cweModelPath)){
		debugMessage(DebugTypes.info, "cwe_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(cweModelPath), config.downloadURLs.cweModel));
	} else {
		debugMessage(DebugTypes.info, "cwe_model found at " + cweModelPath + ", skipping download...");
	}

	await Promise.all(downloads).then(() => {	
		debugMessage(DebugTypes.info, "Completed model initialization");
		progressEmitter.emit('update', ProgressStages.downloadModelEnd);
		return Promise.resolve();
	}
	).catch(err => {
		debugMessage(DebugTypes.error, "Error occured while downloading models");
		return Promise.reject(err);
	}
	);
}


export function deactivate() {}

// Implement all above in class
export class VulDiagnostic {

	targetDocument: vscode.TextDocument | undefined;
	// Ignore construction of diagnostic to prevent multiple diagnostics for same vulnerability (When another prediction model request is made before the first one is finished)
	ignore: boolean = false;

	constructor(targetDocument: vscode.TextDocument | undefined){
		this.targetDocument = targetDocument;
	}

	// Init, inference, and construct is implemented in this class
}


// If there was another request made before the first one, it needs to verify if the request is to the same part of the code
// If rescanning the entire document, simply ignore the previous request
// Need to implement system to determine the modified function of the code with error handling (if function not found, scan entire document or ignore)

// All necessary files should be kept in resources folder (src folder will not be included in the extension package)
// The max fielzie of the extension is 25mb hence we till need method to download the model files and store them in the assets folder
// CWE XML file and local inference script can be included directly in the assets folder