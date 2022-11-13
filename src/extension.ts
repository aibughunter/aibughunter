import { rejects, strict } from 'assert';
import { copyFileSync } from 'fs';
import { EventEmitter } from 'stream';
import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import { MessageChannel } from 'worker_threads';
import {DebugTypes, HighlightTypes, InferenceModes, InfoLevels, ProgressStages, DiagnosticInformation, FunctionsListType} from './config';
import { stdin } from 'process';

// import class from files
import { LocalInference, RemoteInference } from './inference';
import { debugMessage, downloadEngine, Progress, progressHandler, removeBlankLines, removeComments } from './common';

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
// export let inferenceMode: LocalInference | RemoteInference;

const parentDir = path.resolve(__dirname, '..');
export const progressEmitter = new Progress();
let statusBarItem: vscode.StatusBarItem;
let lock = false;

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

	// Array of class instances
	let diagnosticsQueue: VulDiagnostic[] = [];

	progressEmitter.on('init', async (stage:ProgressStages) =>{

		progressHandler(stage);

		switch(stage){
			case ProgressStages.extensionInitStart:
				// Download models and CWE list if not found

				if(!lock){
					lock = true;

					let hasError = true;
					while(hasError){
						await init().then(() => {
							hasError = false;
						}
						).catch(err => {
							debugMessage(DebugTypes.error, err);
							debugMessage(DebugTypes.info, "Error occured during initialisation. Retrying...");
						}
						);
					}
					lock = false;
				} else {
					debugMessage(DebugTypes.info, "Extension initialisation already in progress");
				}
				progressEmitter.emit('init', ProgressStages.extensionInitEnd);
				progressEmitter.emit('init', ProgressStages.analysisStart);
				break;
			case ProgressStages.analysisStart:

				if (!lock){
					if (vscode.window.activeTextEditor?.document){
						if (diagnosticsQueue.length > 0){
							diagnosticsQueue.forEach(element => {
								element.ignore = true;
							});
						}
						const vulDiagnostic = new VulDiagnostic(vscode.window.activeTextEditor?.document);
						diagnosticsQueue.push(vulDiagnostic);
						await vulDiagnostic.analysisSequence();

						console.log(vulDiagnostic.functionsList);

					} else {
						debugMessage(DebugTypes.info, "No active text editor");
						progressEmitter.emit('end', ProgressStages.noDocument);
						break;
					}
				} else{
					debugMessage(DebugTypes.info, "Analysis already in progress");
				}
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

	var downloadCandidates = [downloadCWEXML(), downloadModels()];

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
	
	// functionsList: { [key: string]: Array<string | Array<number> | vscode.Range> } = {
	// 	functions: [],
	// 	vulnFunctions: [],
	// 	shift: [],
	// 	range: [],
	// };

	functionsList: FunctionsListType = {
		functions: [],
		vulnFunctions: [],
		shift: [],
		range: [],
	};

	predictions: { [key: string]: any } = {
		'line': [],
		sev: [],
		cwe: [],
	};

	constructor(targetDocument?: vscode.TextDocument){
		if (targetDocument) {
			this.targetDocument = targetDocument;
		}
	}

	// extractFunctions, inference, and construct is implemented in this class

	async analysisSequence(){

		await this.extractFunctions().then(() => {
			debugMessage(DebugTypes.info, "Finished extracting functions");
		}
		).catch(err => {
			debugMessage(DebugTypes.error, err);
			return Promise.reject(err);
		}
		);

		await this.inferenceSequence().then(() => {
			debugMessage(DebugTypes.info, "Finished extracting functions");
		}
		).catch(err => {
			debugMessage(DebugTypes.error, err);
			return Promise.reject(err);
		}
		);
	}

	/**
	 * Extracts lists of functions from the current editor using DocumentSymbolProvider
	 * @returns Promise that rejects on error and resolves on success
	 */
	async extractFunctions(){
		
		// Exit if document is undefined or invalid
		const uri = vscode.window.activeTextEditor?.document.uri;
		if (!this.targetDocument || uri === undefined) {
			debugMessage(DebugTypes.error, "No document found");
			return Promise.reject("No document found");
		}

		var text = this.targetDocument.getText();
		var lines = text.split(/\r?\n/);

		if(lines.length === 0){
			debugMessage(DebugTypes.error, "Empty document");
			return Promise.reject("Empty document");
		}
		// ---
		
		// Extract functions from document
		debugMessage(DebugTypes.info, "Getting Symbols");
		progressEmitter.emit('update', ProgressStages.fetchSymbolStart);

		let symbols: vscode.DocumentSymbol[] = [];

		var attempts = 0;

		let start = new Date().getTime();
		var period = new Date().getTime();
		while (symbols === undefined || period - start < 3000) {
			symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>('vscode.executeDocumentSymbolProvider', uri);
			if (symbols !== undefined) {
				break;
			}
			period = new Date().getTime();
		}

		let end = new Date().getTime();

		if (symbols === undefined) {
			debugMessage(DebugTypes.error, "No symbols found after 3 seconds");
			return Promise.reject("No symbols found");
		} else {
			debugMessage(DebugTypes.info, "Found " + symbols.length + " symbols in " + (end - start) + " ms");
		}

		symbols.forEach(element => {
			if (element.kind === vscode.SymbolKind.Function) {

				// Formatting functions before storing
				var block: string = "";
				for (var i = element.range.start.line; i <= element.range.end.line; i++) {
					// Remove whitespace at the start of the line
					block += lines[i].replace(/^\s+/g, "");
					// block += lines[i];
					if (i !== element.range.end.line) {
						block += "\n";
					}
				}

				block = removeComments(block);
				const result = removeBlankLines(block);

				// Remove all "\n" characters
				// console.log(result[0].replace(/\n/g, ""));

				this.functionsList.functions.push(result[0]);
				this.functionsList.shift.push(result[1]);
				this.functionsList.range.push(element.range);
			}
		});
	}

	/**
	 * Entry point for vulnerability analysis
	 * Contains three steps:
	 * 1. Extract functions from the current editor
	 * 2. Send list of functions to the inference engine to get vulnerability information and store it in predictions object
	 * 3. Collect vulnerable functions only and send them to CWE and Severity inference engines and store it in predictions object
	 * @param document TextDocument to extract text/function from
	 * @returns 
	 */

	async inferenceSequence() {

		if (this.targetDocument?.getText() === "") {
			debugMessage(DebugTypes.error, "Document is empty, aborting analysis");
			return Promise.reject("Document is empty, aborting analysis");
		}

		var start = new Date().getTime();

		let inferenceEngine;

		switch(config.inferenceMode){
			case InferenceModes.local: inferenceEngine = new LocalInference(this); break;
			case InferenceModes.onpremise:inferenceEngine = new RemoteInference(this);break;
			case InferenceModes.cloud:inferenceEngine = new RemoteInference(this);break;
			default:inferenceEngine = new LocalInference(this);break;
		}

		progressEmitter.emit('update', ProgressStages.inferenceLineStart);

		await inferenceEngine.line(this.functionsList.functions).then(() => {
			debugMessage(DebugTypes.info, "Line vulnerabilities retrieved");

			this.predictions.line.batch_vul_pred.forEach((element: any, i: number) => {
				if (element === 1) {
					this.functionsList.vulnFunctions.push(this.functionsList.functions[i]);
				}
			});
		}
		).catch((err: string) => {
			debugMessage(DebugTypes.error, err);
			return Promise.reject(err);
		}
		);

		progressEmitter.emit('update', ProgressStages.inferenceCweStart);
		progressEmitter.emit('update', ProgressStages.inferenceSevStart);

		if (this.functionsList.vulnFunctions.length === 0) {
			debugMessage(DebugTypes.info, "No vulnerabilities found");
		} else {

			await Promise.all([
				inferenceEngine.cwe(this.functionsList.vulnFunctions),
				inferenceEngine.sev(this.functionsList.vulnFunctions)
			]).then(() => {
				debugMessage(DebugTypes.info, "CWE type and severity score retrieved");
			}
			).catch((err: string) => {
				debugMessage(DebugTypes.error, err);
				return Promise.reject(err);
			}
			);
		}

		progressEmitter.emit('end', ProgressStages.predictionEnd);

		var end = new Date().getTime();

		debugMessage(DebugTypes.info, "All inference completed in " + (end - start) + "ms");

		return Promise.resolve();
	}


}


// If there was another request made before the first one, it needs to verify if the request is to the same part of the code
// If rescanning the entire document, simply ignore the previous request
// Need to implement system to determine the modified function of the code with error handling (if function not found, scan entire document or ignore)

// All necessary files should be kept in resources folder (src folder will not be included in the extension package)
// The max fielzie of the extension is 25mb hence we till need method to download the model files and store them in the assets folder
// CWE XML file and local inference script can be included directly in the assets folder