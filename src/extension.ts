import { rejects } from 'assert';
import { copyFileSync } from 'fs';
import { EventEmitter } from 'stream';
import { robertaProcessing } from 'tokenizers/bindings/post-processors';
import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import { MessageChannel } from 'worker_threads';
import {Config, DebugTypes, GlobalURLs, Functions, HighlightTypes, InferenceModes, InformationLevels, Predictions, ProgressStages, remoteInferenceURLs} from './config';
import { PythonShell } from 'python-shell';
import { stdin } from 'process';

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const fsa = require('fs/promises');
// const formdata = require('form-data');
const extract = require('extract-zip');
const parser = require('xml2js');



let config:Config;
let predictions:Predictions;
let functionSymbols: Functions;
let inferenceMode: LocalInference | RemoteInference;

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

	debugMessage(DebugTypes.info, "Extension initialised");
	vscode.window.showInformationMessage('AIBugHunter: Extension Initialised!');
	// Initial analysis after initialisation, may wrap this in extInitend event


	const diagnosticCollection = vscode.languages.createDiagnosticCollection('AIBugHunter');
	context.subscriptions.push(diagnosticCollection);

	context.subscriptions.push(
		vscode.languages.registerCodeActionsProvider('cpp', new RepairCodeAction(), {
			providedCodeActionKinds: RepairCodeAction.providedCodeActionKinds
		})
	);

	/**
	 * Any init event will be handled here
	 * If extInit, then initialise extension (download necessary files, etc)
	 * If analysis, then start analysis of active document
	 * @param stage Stage of progress
	 */

	progressEmitter.on('init', async (stage:ProgressStages) => {

		const activeDocument = vscode.window.activeTextEditor?.document ?? undefined;

		progressHandler(stage);

		switch(stage){
			case ProgressStages.extInit:
				let noerror = false;

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
				debugMessage(DebugTypes.info, "Running initial analysis");
				progressEmitter.emit('init', ProgressStages.inferenceStart);
				break;
			case ProgressStages.inferenceStart:
				if(activeDocument){
					inferenceEngine(activeDocument).then(() => {

						progressEmitter.emit('end', ProgressStages.predictionEnd);

						debugMessage(DebugTypes.info, "Starting diagnostic construction");

						constructDiagnostics(activeDocument, diagnosticCollection);
					}
					).catch(err => {
						debugMessage(DebugTypes.error, err);
						debugMessage(DebugTypes.error, "Analysis failed");
						progressEmitter.end(ProgressStages.error);
					}
					);
					break;
				}else{
					debugMessage(DebugTypes.error, "No active document");
					progressEmitter.emit('end', ProgressStages.nodoc);
				}
		}
	}
	);

	console.log(inferenceMode);

	progressEmitter.emit('init', ProgressStages.extInit);

	let pause: NodeJS.Timeout;

	vscode.workspace.onDidChangeTextDocument((e) =>{

		if(e.contentChanges.length > 0){

			clearTimeout(pause);

			pause = setTimeout(() => {
				debugMessage(DebugTypes.info, "Typing stopped for " + config.delay + "ms");
				
				progressEmitter.emit('init', ProgressStages.extInit);

			}, config.delay);
	
		}
	});

	// Reinitialise interfaces on configuration modification
	vscode.workspace.onDidChangeConfiguration((e) => {
		debugMessage(DebugTypes.info, "Configuration Changed");
		progressEmitter.emit('init', ProgressStages.extInit);
	});

	// vscode.workspace.onDidOpenTextDocument((e) => {
	// 	debugMessage(DebugTypes.info, "Document opened");
	// 	console.log(e);
	// 	// if(e?.document.languageId === 'cpp'){
	// 	// 	interfaceInit();
	// 	// 	progressEmitter.emit('init', ProgressStages.analysis);
	// 	// }
	// }
	// );

	vscode.window.onDidChangeActiveTextEditor((e) => {
		debugMessage(DebugTypes.info, "Active text editor changed");
		if(e?.document.languageId === 'cpp'){
			progressEmitter.emit('init', ProgressStages.extInit);
		}
	});




	// context.subscriptions.push(disposable);
}


export function deactivate() {}


/**
 * Initialises global configuration from VS Code user configuration
 */
function interfaceInit(){

	const vsconfig = vscode.workspace.getConfiguration('AiBugHunter');

	config = {
		inferenceMode: vsconfig.inference.inferenceMode,
		gpu: vsconfig.inference.EnableGPU,
		onPremiseInferenceURL: vsconfig.inference.inferenceServerURL,
		informationLevel: vsconfig.diagnostics.informationLevel,
		showDescription: vsconfig.diagnostics.showDescription,
		maxLines: vsconfig.diagnostics.maxNumberOfLines,
		delay: vsconfig.diagnostics.delayBeforeAnalysis,
		modelDir: vsconfig.model.downloadLocation,
		cweDir: vsconfig.cwe.downloadLocation,
		resSubDir: vsconfig.resources.subDirectory,
	};

	switch(vsconfig.diagnostics.highlightSeverityType){
		case "Error": config.diagnosticSeverity = vscode.DiagnosticSeverity.Error; break;
		case "Warning": config.diagnosticSeverity = vscode.DiagnosticSeverity.Warning; break;
		case "Information": config.diagnosticSeverity = vscode.DiagnosticSeverity.Information; break;
		case "Hint": config.diagnosticSeverity = vscode.DiagnosticSeverity.Hint; break;
	}

	predictions = {
		line: Object(),
		sev: Object(),
		cwe: Object()
	};

	functionSymbols = {
		functions: Array<string>(),
		vulnFunctions: Array<string>(),
		shift: Array<Array<number>>(),
		range: Array<vscode.Range>()
	};

	switch(config.inferenceMode){
		case InferenceModes.local:inferenceMode = new LocalInference();break; 
		case InferenceModes.onpremise:inferenceMode = new RemoteInference();break;
		case InferenceModes.cloud:inferenceMode = new RemoteInference();break;
		default:inferenceMode = new LocalInference();break;
	}
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
		downloads.push(downloadEngine(fs.createWriteStream(lineModelPath), GlobalURLs.lineModel));
	} else {
		debugMessage(DebugTypes.info, "line_model found at " + lineModelPath + ", skipping download...");
	}
	
	if(!fs.existsSync(sevModelPath)){
		debugMessage(DebugTypes.info, "sve_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(sevModelPath), GlobalURLs.sevModel));
	} else {
		debugMessage(DebugTypes.info, "sev_model found at " + sevModelPath + ", skipping download...");
	}

	if(!fs.existsSync(cweModelPath)){
		debugMessage(DebugTypes.info, "cwe_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(cweModelPath), GlobalURLs.cweModel));
	} else {
		debugMessage(DebugTypes.info, "cwe_model found at " + cweModelPath + ", skipping download...");
	}

	await Promise.all(downloads).then(() => {	
		debugMessage(DebugTypes.info, "Completed model initialization");	
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
		await downloadEngine(fs.createWriteStream(cwePath), GlobalURLs.cweList).then(() => {
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

	interfaceInit();

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

	var candidates = [cweListInit()];

	if(config.inferenceMode === InferenceModes.local){
		candidates.push(modelInit());
	}

	console.log(candidates);

	await Promise.all(candidates).then(() => {
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
			debugMessage(DebugTypes.info, "User canceled the running operation");
		});

		switch(stage){
			case ProgressStages.extInit: progress.report({ message: "Initialisation - Downloading models and CWE List...", increment: 0}); break;
			case ProgressStages.inferenceStart: progress.report({ message: "Starting analysis...", increment: 0}); break;
		}
		
		progressEmitter.on('update', (stage: ProgressStages) =>{
			switch(stage){
				case ProgressStages.symbol: progress.report({message: "Getting symbols...", increment:10}); break;
				case ProgressStages.line: progress.report({message:"Detecting vulnerabilities...", increment: 20}); break;
				case ProgressStages.cwe: progress.report({message: "Identifying CWEs...", increment: 50}); break;
				case ProgressStages.sev: progress.report({message: "Getting severity scores...", increment: 70}); break;
				case ProgressStages.predictionEnd: progress.report({message: "Prediction complete", increment: 75}); break;
				case ProgressStages.descSearch: progress.report({message: "Searching CWE descriptions in XML...", increment: 80}); break;
				case ProgressStages.diagnostic: progress.report({message: "Constructing diagnostic collection...", increment: 90}); break;
			}
		});

		const promise = new Promise<void>(resolve => {
			progressEmitter.on('end', (stage:ProgressStages) => {
				switch(stage){
					case ProgressStages.extInitEnd: progress.report({message: "Initialisation complete", increment: 100}); break;
					case ProgressStages.error: progress.report({message: "Error occured. Terminating...", increment: 100}); break;
					case ProgressStages.nodoc: progress.report({message: "No document found. Skipping...", increment: 100}); break;
					case ProgressStages.inferenceEnd: progress.report({message: "Analysis complete", increment: 100}); break;
				}
				setTimeout(() => {
					resolve();
				}, 2000);
			});
		});

		return promise;
	});
}



export class LocalInference{
	public async line(list: Array<string>): Promise<any>{

		debugMessage(DebugTypes.info, "Starting line inference");

		const shell = new PythonShell('/home/wren/Documents/DevProjects/AIBugHunter/local-inference/deploy.py', {mode:'text', args: ["line", (config.gpu ? "True" : "False")]});

		debugMessage(DebugTypes.info, "Sending data to python script");
		let start = new Date().getTime();
		shell.send(JSON.stringify(list));


		return new Promise((resolve, reject) => {
			shell.on('message', async (message: any) => {
				console.log(message);
				let end = new Date().getTime();
				debugMessage(DebugTypes.info, "Received response from python script in " + (end - start) + "ms");
				predictions.line = JSON.parse(message);
				resolve(JSON.parse(message));
			}
			);

			shell.end((err: any) => {
				if(err){
					reject(err);
				}
			}	
			);
		});
	}

	public async cwe(list: Array<string>): Promise<any>{
		debugMessage(DebugTypes.info, "Starting CWE prediction");

		const shell = new PythonShell('/home/wren/Documents/DevProjects/AIBugHunter/local-inference/deploy.py', {mode:'text', args: ["cwe", (config.gpu ? "True" : "False")]});

		debugMessage(DebugTypes.info, "Sending data to python script");
		let start = new Date().getTime();
		shell.send(JSON.stringify(list));

		return new Promise((resolve, reject) => {
			shell.on('message', async (message: any) => {
				let end = new Date().getTime();
				debugMessage(DebugTypes.info, "Received response from python script in " + (end - start) + "ms");
				predictions.cwe = JSON.parse(message);
				resolve(JSON.parse(message));
			}
			);

			shell.end((err: any) => {
				if(err){
					reject(err);
				}
			}	
			);
		});
	}

	public async sev(list: Array<string>): Promise<any>{
		debugMessage(DebugTypes.info, "Starting severity prediction");

		const shell = new PythonShell('/home/wren/Documents/DevProjects/AIBugHunter/local-inference/deploy.py', {mode:'text', args: ["sev", (config.gpu ? "True" : "False")]});

		debugMessage(DebugTypes.info, "Sending data to python script");
		let start = new Date().getTime();
		shell.send(JSON.stringify(list));
		
		return new Promise((resolve, reject) => {
			shell.on('message', async (message: any) => {
				let end = new Date().getTime();
				debugMessage(DebugTypes.info, "Received response from python script in " + (end - start) + "ms");
				predictions.sev = JSON.parse(message);
				resolve(JSON.parse(message));
			}
			);

			shell.end((err: any) => {
				if(err){
					reject(err);
				}
			}	
			);
		});
	}
}


export class RemoteInference{

	/**
	 * Takes a list of all functions in the document, sends them to the remote inference engine and returns the results
	 * @param list List of functions to analyse
	 * @returns Promise that resolves when successfully received results, rejects if error occurs
	 */
	public async line(list: Array<string>): Promise<any>{

		let jsonObject = JSON.stringify(list);
		var signal = new AbortController;
		signal.abort;
		var start = new Date().getTime();
		
		debugMessage(DebugTypes.info, "Sending line detection request to " + ((config.inferenceMode === InferenceModes.onpremise)? config.onPremiseInferenceURL : remoteInferenceURLs.cloudInferenceURL) + ((config.gpu)? remoteInferenceURLs.endpoints.line.gpu : remoteInferenceURLs.endpoints.line.cpu));
		progressEmitter.emit('update', ProgressStages.line);

		await axios({
			method: "post",
			url: ((config.inferenceMode === InferenceModes.onpremise)? config.onPremiseInferenceURL : remoteInferenceURLs.cloudInferenceURL) + ((config.gpu)? "/api/v1/gpu/predict" : "/api/v1/cpu/predict"),
			data: jsonObject,
			signal: signal.signal,
			headers: { "Content-Type":"application/json"},
		  })
			.then(async function (response: any) {
				var end = new Date().getTime();
				var diffInSeconds = (end - start) / 1000;

				predictions.line = response.data;

				debugMessage(DebugTypes.info, "Received response from model in " + diffInSeconds + " seconds");
				return Promise.resolve(response.data);
			})
			.catch(function (err: any) {
				debugMessage(DebugTypes.error, err);
				return Promise.reject(err);
			});
	}


	/**
	 * Takes a list of vulnerable functions, sends them to remote inference engine for inference, then stores the list of CWE results in the predictions.cwe object
	 * @param list List of functions to be analysed
	 * @returns Promise that resolves when successfully received response from model, rejects if error occurs
	 */
	public async cwe(list: Array<string>): Promise<any>{
		let jsonObject = JSON.stringify(list);
		var signal = new AbortController;
		signal.abort;
		var start = new Date().getTime();

		debugMessage(DebugTypes.info, "Sending CWE detection request to " + ((config.inferenceMode === InferenceModes.onpremise)? config.onPremiseInferenceURL : remoteInferenceURLs.cloudInferenceURL) + ((config.gpu)? remoteInferenceURLs.endpoints.cwe.gpu : remoteInferenceURLs.endpoints.cwe.cpu));
		progressEmitter.emit('update', ProgressStages.cwe);
		await axios({
			method: "post",
			url: ((config.inferenceMode === InferenceModes.onpremise)? config.onPremiseInferenceURL : remoteInferenceURLs.cloudInferenceURL) + ((config.gpu)? "/api/v1/gpu/cwe" : "/api/v1/cpu/cwe"),
			data: jsonObject,
			signal: signal.signal,
			headers: { "Content-Type":"application/json"},
		})
			.then(function (response: any) {
				var end = new Date().getTime();
				var diffInSeconds = (end - start) / 1000;

				debugMessage(DebugTypes.info, "Received response from model in " + diffInSeconds + " seconds");
				predictions.cwe = response.data;

				return Promise.resolve(response.data);
			})
			.catch(function (response: any) {
				debugMessage(DebugTypes.error, response);
				return Promise.reject(response);
			});

	}

	/**
	 * Takes a list of vulnerable functions, sends them to remote inference engine, then stores the list of severity results in the predictions.sev object 
	 * @param list List of functions to be analysed (Only vulnerable functions are analysed)
	 * @returns Promise that resolves when successfully received response from model, rejects if error occurs
	 */
	public async sev(list: Array<string>): Promise<any>{

		let jsonObject = JSON.stringify(list);
		var signal = new AbortController;
		signal.abort;
		var start = new Date().getTime();

		debugMessage(DebugTypes.info, "Sending security score request to " + ((config.inferenceMode === InferenceModes.onpremise)? config.onPremiseInferenceURL : remoteInferenceURLs.cloudInferenceURL) + ((config.gpu)? remoteInferenceURLs.endpoints.sev.gpu : remoteInferenceURLs.endpoints.sev.cpu));
		progressEmitter.emit('update', ProgressStages.sev);

		await axios({
			method: "post",
			url: ((config.inferenceMode === InferenceModes.onpremise)? config.onPremiseInferenceURL : remoteInferenceURLs.cloudInferenceURL) + ((config.gpu)? "/api/v1/gpu/sev" : "/api/v1/cpu/sev"),
			data: jsonObject,
			signal: signal.signal,
			headers: { "Content-Type":"application/json"},
			})
			.then(function (response: any) {
				var end = new Date().getTime();
				var diffInSeconds = (end - start) / 1000;

				debugMessage(DebugTypes.info, "Received response from model in " + diffInSeconds + " seconds");
				predictions.sev = response.data;

				return Promise.resolve(response.data);
			})
			.catch(function (response: any) {
				debugMessage(DebugTypes.error, response);
				return Promise.reject(response);
			});
	}
}

/**
 * Extract list of functions from the current editor using DocumentSymbolProvider
 * @returns Promise that rejects on error
 */
async function extractFunctions(document:vscode.TextDocument){

	// var editor = vscode.window.activeTextEditor;

	// if(editor === undefined){
	// 	debugMessage(DebugTypes.error, "No editor found");
	// 	return Promise.reject("No editor found");
	// }

	var text = document.getText();
	var lines = text.split("\n");

	if(lines.length === 0){
		debugMessage(DebugTypes.error, "Empty document");
		return Promise.reject("Empty document");
	}

	const uri = vscode.window.activeTextEditor?.document.uri;

	if(uri === undefined){
		debugMessage(DebugTypes.error, "No document found");
		return Promise.reject("No document found");
	}

	debugMessage(DebugTypes.info, "Getting Symbols");
	progressEmitter.emit('update', ProgressStages.symbol);

	// Attempt to get symbols from the current document 3 times, if it fails, then reject
	// This is to avoid the edge case where the DocumentSymbolProvider is not yet ready when the initial analysis is requested


	let symbols: vscode.DocumentSymbol[] = [];

	var attempts = 0;

	  let start = new Date().getTime();
	  var period = new Date().getTime();
	  while(symbols === undefined || period - start < 3000){
		symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>('vscode.executeDocumentSymbolProvider', uri);
		if(symbols !== undefined){
			break;
		}
		period = new Date().getTime();
	  }

	let end = new Date().getTime();

	if(symbols === undefined){
		debugMessage(DebugTypes.error, "No symbols found after 3 seconds");
		return Promise.reject("No symbols found");
	} else{
		debugMessage(DebugTypes.info, "Found " + symbols.length + " symbols in " + (end - start) + " ms");
	}

	symbols.forEach(element => {
		if(element.kind === vscode.SymbolKind.Function){

			// Formatting functions before storing
			var block: string = "";
			for(var i = element.range.start.line; i <= element.range.end.line; i++){
				block += lines[i];
				if(i !== element.range.end.line){
					block += "\n";
				}
			}

			block = removeComments(block);

			const result = removeBlankLines(block);

			functionSymbols.functions.push(result[0]);
			functionSymbols.shift.push(result[1]);
			functionSymbols.range.push(element.range);
			
		}
	});
}

/**
 * Remove comments from the given string
 * @param text Text to remove comments from
 * @returns Text without comments
 */
function removeComments(text:string): string{

	let cleanText = text;
	let newline = "\n";

	// For Block Comments (/* */)
	let pattern = /\/\*[^]*?\*\//g; 
	let matches = text.matchAll(pattern);
	

	for (const match of matches) {

		var start = match.index ? match.index : 0; // Starting index of the match
		let length = match.length + match[0].length-1; // Length of the match
		let end = start + length; // Ending index of the match

		let lineStart = text.substring(0, match.index).split("\n").length;
		let lineEnd = text.substring(0, end).split("\n").length;
		let diff = lineEnd - lineStart;

		// console.log("Line: " + lineStart + " To " + lineEnd);

		cleanText = cleanText.replace(match[0], newline.repeat(diff));
	}

	// For line comments (//)
	pattern =/\/\/.*/g; 
	matches = text.matchAll(pattern);
	for (const match of matches) {

		var start = match.index ? match.index : 0; // Starting index of the match
		let length = match.length + match[0].length-1; // Length of the match
		let end = start + length; // Ending index of the match

		let lineStart = text.substring(0, match.index).split("\n").length;
		let lineEnd = text.substring(0, end).split("\n").length;
		let diff = lineEnd - lineStart;

		cleanText = cleanText.replace(match[0], newline.repeat(diff));
	}

	return cleanText;
}

/**
 * Remove blank lines from the given string
 * @param text Text to remove blank lines from
 * @returns Text without blank lines
 */
function removeBlankLines(text:string): [string,number[]]{

	let lines = text.split("\n");
	let newLines = [];
	let shiftMap = [];
	for (let i = 0; i < lines.length; i++) {
		if (!lines[i].replace(/^\s+/g, '').length) { // If line is empty, remove and record the line affected
			shiftMap.push(i);
		} else {
			newLines.push(lines[i]);
		}
	}
	return [newLines.join("\n"), shiftMap];
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

async function inferenceEngine(document: vscode.TextDocument){

	if(document.getText() === ""){
		debugMessage(DebugTypes.error, "Document is empty, aborting analysis");
		return Promise.reject("Document is empty, aborting analysis");
	}

	await extractFunctions(document).then(() => {
		debugMessage(DebugTypes.info, "Finished extracting functions");
	}
	).catch(err => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);

	var start = new Date().getTime();

	progressEmitter.emit('update', ProgressStages.line);

	await inferenceMode.line(functionSymbols.functions).then(() => {
		debugMessage(DebugTypes.info, "Line vulnerabilities retrieved");

		predictions.line.batch_vul_pred.forEach((element: any, i: number) => {
			if(element === 1){
				functionSymbols.vulnFunctions.push(functionSymbols.functions[i]);
			}
		});
	}
	).catch((err: string) => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);

	progressEmitter.emit('update', ProgressStages.cwe);

	// await inferenceMode.cwe(functionSymbols.vulnFunctions).then(() => {
	// 	debugMessage(DebugTypes.info, "CWE type retrieved");
	// }
	// ).catch((err: string) => {
	// 	debugMessage(DebugTypes.error, err);
	// 	return Promise.reject(err);
	// }
	// );

	progressEmitter.emit('update', ProgressStages.sev);

	// await inferenceMode.sev(functionSymbols.vulnFunctions).then(() => {
	// 	debugMessage(DebugTypes.info, "Severity score retrieved");	}
	// ).catch((err: string) => {
	// 	debugMessage(DebugTypes.error, err);
	// 	return Promise.reject(err);
	// }
	// );

	await Promise.all([
		inferenceMode.cwe(functionSymbols.vulnFunctions),
		inferenceMode.sev(functionSymbols.vulnFunctions)
	]).then(() => {
		debugMessage(DebugTypes.info, "CWE type and severity score retrieved");
	}
	).catch((err: string) => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);


	progressEmitter.emit('end', ProgressStages.inferenceStart);

	var end = new Date().getTime();

	debugMessage(DebugTypes.info, "All inference completed in " + (end - start) + "ms");

	return Promise.resolve();
}

/**
 * Takes all the predictions results and constructs diagnostics for each vulnerable function
 * @param doc TextDocument to display diagnostic collection in
 * @param diagnosticCollection DiagnosticCollection to set diagnostics for
 */
async function constructDiagnostics(doc: vscode.TextDocument | undefined, diagnosticCollection: vscode.DiagnosticCollection){

	if(doc === undefined){
		debugMessage(DebugTypes.error, "No document found to construct diagnostics");
		return 1;
	}

	let vulCount = 0;
	let diagnostics: vscode.Diagnostic[] = [];

	let cweList: any[] = [];

	predictions.line.batch_vul_pred.forEach((element: any, i: number) => {
		if(element === 1){
			cweList.push([predictions.cwe.cwe_type[vulCount], predictions.cwe.cwe_id[vulCount].substring(4)]);
			vulCount++;
		}
	});

	await getCWEData(cweList);

	vulCount = 0;

	progressEmitter.emit('update', ProgressStages.diagnostic);

	functionSymbols.range.forEach((value: any, i: number) => {
		if(predictions.line.batch_vul_pred[i] === 1){
			debugMessage(DebugTypes.info, "Constructing diagnostic for function: " + i);

			
			// functionSymbols.* contains all functions
			// predictions.line contains all functions
			// predictions.cwe and predictions.sev contain only vulnerable functions

			const cweID = predictions.cwe.cwe_id[vulCount];
			const cweIDProb = predictions.cwe.cwe_id_prob[vulCount];
			const cweType = predictions.cwe.cwe_type[vulCount];
			const cweTypeProb = predictions.cwe.cwe_type_prob[vulCount];

			let cweDescription = predictions.cwe.descriptions[vulCount];
			const cweName = predictions.cwe.names[vulCount];

			const sevScore = predictions.sev.batch_sev_score[vulCount];
			const sevClass = predictions.sev.batch_sev_class[vulCount];

			const lineScores = predictions.line.batch_line_scores[i];
			
			let lineScoreShiftMapped: number[][] = [];

			functionSymbols.shift[i].forEach((element:number) =>{
				lineScores.splice(element, 0, 0);
			});

			let lineStart = functionSymbols.range[i].start.line;

			lineScores.forEach((element: number) => {
				lineScoreShiftMapped.push([lineStart, element]);
				lineStart++;
			});

			// Sort by prediction score
			lineScoreShiftMapped.sort((a: number[], b: number[]) => {
				return b[1] - a[1];
			}
			);

			const url = "https://cwe.mitre.org/data/definitions/" + cweID.substring(4) + ".html";

			for(var i = 0; i < config.maxLines; i++){
				
				const vulnLine = lineScoreShiftMapped[i][0];

				const lines = doc?.getText().split("\n") ?? [];

				let line = doc?.lineAt(vulnLine);

				let diagMessage = "";

				cweDescription = predictions.cwe.descriptions[vulCount];


				switch(config.informationLevel){
					case InformationLevels.core: {
						// diagMessage = "Line: " + (vulnLine+1) + " | Severity: " + sevScore.toString().match(/^\d+(?:\.\d{0,2})?/) + " | CWE: " + cweID.substring(4) + " " + ((cweName === undefined || "") ? "" : ("(" + cweName + ") ") )  + "| Type: " + cweType;
						diagMessage = "[Severity: " + sevClass + "] Line " + (vulnLine+1) + " may be vulnerable with " + cweID + " (" + cweType + " | " + cweName + ")";  
						break;
					}
					case InformationLevels.verbose: {
						diagMessage = "[" + lineScoreShiftMapped[i][1].toString().match(/^\d+(?:\.\d{0,2})?/) + "] Line: " + (vulnLine+1) + " | Severity: " + sevScore.toString().match(/^\d+(?:\.\d{0,2})?/) + " (" + sevClass +")" +" | " + "[" + cweIDProb.toString().match(/^\d+(?:\.\d{0,2})?/) + "] " +"CWE: " + cweID.substring(4) + " " + ((cweName === undefined || "") ? "" : ("(" + cweName + ") ") )  + "| " + "[" + cweTypeProb.toString().match(/^\d+(?:\.\d{0,2})?/) + "] " + "Type: " + cweType;
						break;
					}
					case InformationLevels.minimal: {
						diagMessage = "Line " + (vulnLine) + " may be vulnerable with " + cweID + " (Severity: " + sevClass + ")";
					}
				};

				const diagnostic = new vscode.Diagnostic(
					new vscode.Range(vulnLine, doc?.lineAt(vulnLine).firstNonWhitespaceCharacterIndex, vulnLine, line.text.length),
					diagMessage,
					config.diagnosticSeverity ?? vscode.DiagnosticSeverity.Error
				);

				diagnostic.code = {
					value: "More Details",
					target: vscode.Uri.parse(url)
				};

				diagnostic.source = "AIBugHunter";
				
				diagnostics.push(diagnostic);

				if(config.showDescription){
					const diagnosticDescription = new vscode.Diagnostic(
						new vscode.Range(vulnLine, doc?.lineAt(vulnLine).firstNonWhitespaceCharacterIndex, vulnLine, line.text.length),
						cweDescription,
						config.diagnosticSeverity ?? vscode.DiagnosticSeverity.Error
					);
	
					diagnosticDescription.code = {
						value: "More Details",
						target: vscode.Uri.parse(url)
					};
	
					// diagnosticDescription.source = "AIBugHunter";
	
					diagnostics.push(diagnosticDescription);
				}
			}
			vulCount++;
		}
	});

	progressEmitter.emit("end", ProgressStages.inferenceEnd);

	diagnosticCollection.delete(doc.uri);

	diagnosticCollection.set(doc.uri, diagnostics);
	
	return 0;
}

/**
 * Takes a list of CWE Types and CWE IDs and fetches the CWE data from the CWE xml
 * It stores the name and description into new fields in object: predictions.cwe.names and predictions.cwe.descriptions
 * @param list List of CWE IDs ( [[CWE Type, CWE ID]] )
 * @returns Promise that resolves when successfully retrieved CWE data from XML, rejects otherwise
 */
async function getCWEData(list:any){
	progressEmitter.emit("update", ProgressStages.descSearch);

	try{
		const data = await fsa.readFile(config.xmlPath);
		debugMessage(DebugTypes.info, "CWE XML file read");

		try{
			debugMessage(DebugTypes.info, "Parsing CWE XML file");
			
			const parsed:any = await new Promise((resolve, reject) => parser.parseString(data, (err: any, result: any) => {
				if (err) {reject(err); return Promise.reject(err);}
				else {resolve(result);}
			  }));

			  if(!parsed){
				  debugMessage(DebugTypes.error, "Error parsing CWE XML file");
				  progressEmitter.emit("end", ProgressStages.error);
				  return Promise.reject();
			  } else{
				
				debugMessage(DebugTypes.info, "Parsed CWE XML file. Getting data");
				const weaknessDescriptions: any[] = [];
				const weaknessNames: any[] = [];

				list.forEach((element:any, i: number) => {
					
					let weakness: any;
					let weaknessDescription: string = "";
					let weaknessName: string = "";

					switch(element[0]){
						case "Base": {
							weakness = parsed.Weakness_Catalog.Weaknesses[0].Weakness.find((obj:any) =>{
								return obj.$.ID === element[1].toString();
							});
							weaknessDescription = weakness.Description[0];
							break;
						}
						case "Category": {
							weakness = parsed.Weakness_Catalog.Categories[0].Category.find((obj:any) =>{
								return obj.$.ID === element[1].toString();
							});
							weaknessDescription = weakness.Summary[0];
							break;
						}
					}

					weaknessName = weakness.$.Name;
					
					// console.log(predictions.cwe);

					weaknessDescriptions.push(weaknessDescription);
					weaknessNames.push(weaknessName);

				});
				
				predictions.cwe.descriptions = weaknessDescriptions;
				predictions.cwe.names = weaknessNames;

				return Promise.resolve();
			} 
		} catch(err){
			debugMessage(DebugTypes.error, "Error Parsing CWE XML file");
			progressEmitter.emit("end", ProgressStages.error);
			return Promise.reject(err);
		}
	
	} catch(err:any){
		debugMessage(DebugTypes.error, "Error while reading CWE XML file: " + err);
		progressEmitter.emit("end", ProgressStages.error);
		return Promise.reject(err);
	}
}

export class RepairCodeAction implements vscode.CodeActionProvider {
	provideCodeActions(document: vscode.TextDocument, range: vscode.Range | vscode.Selection, context: vscode.CodeActionContext, token: vscode.CancellationToken): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
		return context.diagnostics.filter(diagnostic => diagnostic.source === "AIBugHunter").map(diagnostic => this.createCommand(diagnostic));
	}
	public static readonly providedCodeActionKinds: vscode.CodeActionKind[] = [vscode.CodeActionKind.QuickFix];

	private createCommand(diagnostic: vscode.Diagnostic): vscode.CodeAction{
		const action = new vscode.CodeAction("Try to fix this vulnerability", vscode.CodeActionKind.QuickFix);
		action.command = {
			command: "aibughunter.repairCode",
			title: "Repair Code",
			tooltip: "Repair Code"
		};
		action.isPreferred = true;
		// action.disabled = {
		// 	reason: "Feature not yet implemented"
		// };
		action.diagnostics = [diagnostic];
		return action;
	}

}