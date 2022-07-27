import { rejects } from 'assert';
import { EventEmitter } from 'stream';
import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import {Config, DebugTypes, DownloadURLs, HighlightTypes, InferenceModes, InformationLevels, ProgressStages} from './config';

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const fsa = require('fs/promises');
// const formdata = require('form-data');
const extract = require('extract-zip');
// const parser = require('xml2js');

var config:Config;


class Progress extends EventEmitter{
	constructor(){
		super();
	}

	init(stage:ProgressStages){
		this.emit('init', stage);
	}

	update(stage:ProgressStages){
		this.emit('update', stage);
	}

	end(stage:ProgressStages){
		this.emit('end', stage);
	}
}

const progressEmitter = new Progress();

export async function activate(context: vscode.ExtensionContext) {
	
	let disposable = vscode.commands.registerCommand('aibughunter.helloWorld', () => {
		vscode.window.showInformationMessage('Hello World from AIBugHunter!');
	});

	debugMessage(DebugTypes.info, "Extension activated");

	progressEmitter.on('init', (stage:ProgressStages) => {
		progressHandler(stage);
	}
	);

	progressEmitter.emit('init', ProgressStages.extInit);

	var noerror = false;

	while(!noerror){
		await init().then(() => {
			noerror = true;
		}
		).catch(err => {
			debugMessage(DebugTypes.error, err);
			debugMessage(DebugTypes.info, "Error occured during initialisation. Retrying...");
		}
		);
	}

	progressEmitter.emit('end', ProgressStages.extInitEnd);

	debugMessage(DebugTypes.info, "Extension initialised");
	vscode.window.showInformationMessage('AIBugHunter: Extension Initialised!');
	
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
		modelDir: vsconfig.model.downloadLocation,
		cweDir: vsconfig.cwe.downloadLocation,
		resSubDir: vsconfig.resources.subDirectory,
	};
}

/**
 * Check if the model is downloaded and download if not
 */
 async function modelInit(){

	const modelPath = (config.modelDir === ".")? __dirname + "/" + config.modelDir: config.modelDir;

	const lineModelPath = config.lineModelPath = path.resolve(modelPath, config.resSubDir,'line_model.onnx');
	const sevModelPath = config.sevModelPath = path.resolve(modelPath,config.resSubDir ,'sev_model.onnx');
	const cweModelPath = config.cweModelPath = path.resolve(modelPath,config.resSubDir ,'cwe_model.onnx');

	if(config.resSubDir && !fs.existsSync(path.join(modelPath, config.resSubDir))){
		fs.mkdirSync(path.join(modelPath, config.resSubDir), (err: any) => {
			if (err) {
				return console.error(err);
			}
			debugMessage(DebugTypes.info, "Directory created successfully at " + (path.join(modelPath, config.resSubDir)));
		}
		);
	}

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
		downloads.push(downloadEngine(fs.createWriteStream(cweModelPath), DownloadURLs.cweModel));
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
 * Checks for presence of cwe list zip/xml file and downloads if not present
 * @returns Promise that resolves when CWE list is loaded
 */
async function cweListInit() {

	const zipPath = (config.cweDir === ".")? __dirname + "/" + config.cweDir: config.cweDir;

	const cwePath  = path.resolve(zipPath, config.resSubDir,'cwec_latest.xml.zip');

	const extractTarget = path.resolve(zipPath, config.resSubDir);

	// Create subdirectory if specified and doesn't exist
	if(config.resSubDir && !fs.existsSync(extractTarget)){
		fs.mkdirSync(path.join(zipPath, config.resSubDir), (err: any) => {
			if (err) {
				return console.error(err);
			}
			debugMessage(DebugTypes.info, "Directory created successfully at " + extractTarget);
		}
		);
	}

	var files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));

	if(!fs.existsSync(cwePath) || files.length === 0){ // If zip file doesn't exist or no xml files found in subdirectory
		debugMessage(DebugTypes.info, "cwec_latest.xml.zip not found, downloading...");
		await downloadEngine(fs.createWriteStream(cwePath), DownloadURLs.cweList).then(() => {
			debugMessage(DebugTypes.info, "cwec_latest.xml.zip downloaded");
		}
		).catch(err => {
			debugMessage(DebugTypes.error, "Error occured while downloading cwec_latest.xml.zip");
			return Promise.reject(err);
		}
		);
	} else if (files.length > 0) { // If xml file found in subdirectory
		debugMessage(DebugTypes.info, "xml file already exists, skipping download...");
		files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));
		config.xmlPath = path.resolve(zipPath, config.resSubDir, files[0]);
		return Promise.resolve();
	};

	debugMessage(DebugTypes.info, "Extracting cwec_latest.xml.zip");

	await extract(cwePath, {dir: extractTarget}).then(() => {
		debugMessage(DebugTypes.info, "cwec_latest.xml.zip extracted at " + extractTarget.toString());
		files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));
		config.xmlPath = path.resolve(zipPath, config.resSubDir, files[0]);
		return Promise.resolve();
	}
	).catch((err: any) => {
		debugMessage(DebugTypes.error, "Error occured while extracting cwec_latest.xml.zip");
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
	console.log("[" + type + "] [" + new Date().toISOString() + "] " + message);
}


/**
 * Initialises the extension by downloading the models and CWE list if not found on locally
 * @returns Promise that resolves when models and CWE list are loaded, rejects if error occurs
 */
async function init() {

	var start = new Date().getTime();

	intialiseConfig();

	debugMessage(DebugTypes.info, "Config loaded, checking model and CWE list presence");

	// await modelInit().then(() => {
	// 	debugMessage(DebugTypes.info, "Model successfully loaded");
	// }
	// ).catch(err => {
	// 	debugMessage(DebugTypes.error, err);
	// 	return Promise.reject(err);
	// }
	// );

	// await cweListInit().then(() => {
	// 	debugMessage(DebugTypes.info, "CWE list successfully loaded");
	// }
	// ).catch(err => {
	// 	debugMessage(DebugTypes.error, err);
	// 	return Promise.reject(err);
	// }
	// );

	
	await Promise.all([
		modelInit(),
		cweListInit()
	]).then(() => {
		var end = new Date().getTime();
		debugMessage(DebugTypes.info, "Initialisation took " + (end - start) + "ms");
		debugMessage(DebugTypes.info, "Model and CWE list successfully loaded");
		return Promise.resolve();
	}
	).catch(err => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);
}

/**
 * Creates a new progress bar when init is emitted from ProgressEmitter, and handle events until 'end' is emitted
 * @param stage Stages in the progress
 */

async function progressHandler(stage: ProgressStages){
	await vscode.window.withProgress({
		location: vscode.ProgressLocation.Window,
		title: "AIBugHunter",
		cancellable: true
	}, (progress, token) => {

		token.onCancellationRequested(() => {
			console.log("User canceled the long running operation");
		});

		switch(stage){
			case ProgressStages.extInit: progress.report({ message: "Initialisation - Downloading models and CWE List...", increment: 0}); break;
			case ProgressStages.analysis: progress.report({ message: "Starting analysis...", increment: 0}); break;
		}
		
		progressEmitter.on('update', (stage: ProgressStages) =>{
			switch(stage){
				case ProgressStages.symbol: progress.report({message: "Getting symbols...", increment:10}); break;
				case ProgressStages.line: progress.report({message:"Detecting vulnerabilities...", increment: 20}); break;
				case ProgressStages.cwe: progress.report({message: "Identifying CWEs...", increment: 50}); break;
				case ProgressStages.sev: progress.report({message: "Getting severity scores...", increment: 70}); break;
			}
		});

		const promise = new Promise<void>(resolve => {
			progressEmitter.on('end', (stage:ProgressStages) => {
				switch(stage){
					case ProgressStages.extInitEnd: progress.report({message: "Initialisation complete", increment: 100}); break;
					case ProgressStages.analysisEnd: progress.report({message: "Analysis complete", increment: 100}); break;
					case ProgressStages.error: progress.report({message: "Error occured - Terminating...", increment: 100}); break;
				}
				setTimeout(() => {
					resolve();
				}, 2000);
			});
		});

		return promise;
	});
}