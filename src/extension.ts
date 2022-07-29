import { rejects } from 'assert';
import { copyFileSync } from 'fs';
import { EventEmitter } from 'stream';
import { robertaProcessing } from 'tokenizers/bindings/post-processors';
import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import { MessageChannel } from 'worker_threads';
import {Config, DebugTypes, DownloadURLs, Functions, HighlightTypes, InferenceModes, InformationLevels, Predictions, ProgressStages} from './config';

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const fsa = require('fs/promises');
// const formdata = require('form-data');
const extract = require('extract-zip');
// const parser = require('xml2js');

let config:Config;
let predictions:Predictions;
let functionSymbols: Functions;
let inferenceMode: LocalInference | OnPremiseInference | CloudInference;

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
	
	progressEmitter.emit('init', ProgressStages.extInit);

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

	debugMessage(DebugTypes.info, "Extension initialised");

	// Initial analysis after initialisation, may wrap this in extInitend event

	debugMessage(DebugTypes.info, "Running initial analysis");

	const activeDocument = vscode.window.activeTextEditor?.document ?? undefined;

	if(activeDocument){
		analysis().then(() => {
			debugMessage(DebugTypes.info, "Analysis finished");
			progressEmitter.emit('end', ProgressStages.analysisEnd);
			const diagnosticCollection = vscode.languages.createDiagnosticCollection('AiBugHunter');
			context.subscriptions.push(diagnosticCollection);
			constructDiagnostics(activeDocument, diagnosticCollection);
			// console.log(diagnostics);
			context.subscriptions.push(diagnosticCollection);
		}
		).catch(err => {
			debugMessage(DebugTypes.error, err);
			debugMessage(DebugTypes.error, "Analysis failed");
			progressEmitter.end(ProgressStages.error);
		}
		);
	}

	// --------------------------------------------------------------------------

	progressEmitter.on('init', (stage:ProgressStages) => {

		progressHandler(stage);
		
		if(stage === ProgressStages.analysis){
			debugMessage(DebugTypes.info, "Analysis started");
			
			analysis().then(() => {
				debugMessage(DebugTypes.info, "Analysis finished");
				progressEmitter.emit('end', ProgressStages.analysisEnd);
			}
			).catch(err => {
				debugMessage(DebugTypes.error, err);
				debugMessage(DebugTypes.error, "Analysis failed");
				progressEmitter.end(ProgressStages.error);
			}
			);
		}
	}
	);


	progressEmitter.emit('end', ProgressStages.extInitEnd);

	debugMessage(DebugTypes.info, "Extension initialised");
	vscode.window.showInformationMessage('AIBugHunter: Extension Initialised!');

	let wait: NodeJS.Timeout;

	vscode.workspace.onDidChangeTextDocument((e) =>{

		if(e.contentChanges.length > 0){

			clearTimeout(wait);

			wait = setTimeout(() => {
				debugMessage(DebugTypes.info, "Typing stopped for " + config.delay + "ms");
				
				progressEmitter.emit('init', ProgressStages.analysis);

			}, config.delay);
	
		}
	});

	// Reinitialise interfaces on configuration modification
	vscode.workspace.onDidChangeConfiguration((e) => {
		debugMessage(DebugTypes.info, "Configuration Changed");
		interfaceInit();
		// console.log(e);
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
		inferenceURL: vsconfig.inference.inferenceServerURL,
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
		case InferenceModes.onpremise:inferenceMode = new OnPremiseInference();break;
		case InferenceModes.cloud:inferenceMode = new CloudInference();break;
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

export class LocalInference{
	public async line(list: Array<string>): Promise<any>{
		console.log("Line detection");
	}

	public async cwe(list: Array<string>): Promise<any>{
		console.log("CVE detection");
	}

	public async sev(list: Array<string>): Promise<any>{
		console.log("Severity detection");
	}
}


export class OnPremiseInference{

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
		
		debugMessage(DebugTypes.info, "Sending line detection request to " + config.inferenceURL + ((config.gpu)? "/v1/gpu/predict" : "/v1/cpu/predict"));
		progressEmitter.emit('update', ProgressStages.line);

		await axios({
			method: "post",
			url: config.inferenceURL + ((config.gpu)? "/v1/gpu/predict" : "/v1/cpu/predict"),
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

		debugMessage(DebugTypes.info, "Sending CWE detection request to " + config.inferenceURL + ((config.gpu)? "/v1/gpu/cwe" : "/v1/cpu/cwe"));
		progressEmitter.emit('update', ProgressStages.cwe);
		await axios({
			method: "post",
			url: config.inferenceURL + ((config.gpu)? "/v1/gpu/cwe" : "/v1/cpu/cwe"),
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

		debugMessage(DebugTypes.info, "Sending security score request to " + config.inferenceURL + ((config.gpu)? "/v1/gpu/sev" : "/v1/cpu/sev"));
		progressEmitter.emit('update', ProgressStages.sev);

		await axios({
			method: "post",
			url: config.inferenceURL + ((config.gpu)? "/v1/gpu/sev" : "/v1/cpu/sev"),
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

export class CloudInference{
	public async line(list: Array<string>): Promise<any>{
		console.log("Line detection");
	}

	public async cwe(list: Array<string>): Promise<any>{
		console.log("CVE detection");
	}

	public async sev(list: Array<string>): Promise<any>{
		console.log("Severity detection");
	}
}

/**
 * Extract list of functions from the current editor using DocumentSymbolProvider
 * @returns Promise that rejects on error
 */
async function extractFunctions(){

	var editor = vscode.window.activeTextEditor;

	if(editor === undefined){
		debugMessage(DebugTypes.error, "No editor found");
		return Promise.reject("No editor found");
	}
	var text = editor.document.getText();
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

	let start = new Date().getTime();

	let symbols: vscode.DocumentSymbol[] = [];
	for(var i = 0; i < 3; i++){
		symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>('vscode.executeDocumentSymbolProvider', uri);
		if(symbols === undefined){
			debugMessage(DebugTypes.error, "No symbols found, retrying... [Attempt " + (i+1) + "]");
		} else{
			continue;
		}
	}

	let end = new Date().getTime();

	if(symbols === undefined){
		debugMessage(DebugTypes.error, "No symbols found after 3 attempts");
		return Promise.reject("No symbols found");
	} else{
		debugMessage(DebugTypes.info, "Found " + symbols.length + " symbols in " + (end - start) + " milliseconds");
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

	console.log(text);

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

async function analysis(){

	// console.log(vscode.window.activeTextEditor?.document.getText());

	if(vscode.window.activeTextEditor?.document.getText() === ""){
		debugMessage(DebugTypes.error, "Document is empty, aborting analysis");
		return Promise.reject("Document is empty, aborting analysis");
	}

	await extractFunctions().then(() => {
		debugMessage(DebugTypes.info, "Finished extracting functions");
	}
	).catch(err => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);

	progressEmitter.emit('update', ProgressStages.line);

	await inferenceMode.line(functionSymbols.functions).then(() => {
		debugMessage(DebugTypes.info, "Finished analysing lines");

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

	await inferenceMode.cwe(functionSymbols.vulnFunctions).then(() => {
		debugMessage(DebugTypes.info, "CWE type retrieved");
	}
	).catch((err: string) => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);

	progressEmitter.emit('update', ProgressStages.sev);

	await inferenceMode.sev(functionSymbols.vulnFunctions).then(() => {
		debugMessage(DebugTypes.info, "Severity score retrieved");	}
	).catch((err: string) => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);

	progressEmitter.emit('end', ProgressStages.analysis);

	return Promise.resolve();

	// Can promise all for cwe and sev for higher performance but error messages are consolidated

}

function constructDiagnostics(doc: vscode.TextDocument | undefined, diagnosticCollection: vscode.DiagnosticCollection){

	if(doc === undefined){
		debugMessage(DebugTypes.error, "No document found to construct diagnostics");
		return 1;
	}

	let vulCount = 0;
	let diagnostics: vscode.Diagnostic[] = [];

	console.log(functionSymbols);
	console.log(predictions);
	
	functionSymbols.range.forEach((value: any, i: number) => {
		if(predictions.line.batch_vul_pred[i] === 1){
			debugMessage(DebugTypes.info, "Constructing diagnostic for function: " + i);

			// console.log(predictions.line);
			// console.log(predictions.sev);
			// console.log(predictions.cwe);
			
			// functionSymbols.* contains all functions
			// predictions.line contains all functions
			// predictions.cwe and predictions.sev contain only vulnerable functions

			const cweID = predictions.cwe.cwe_id[vulCount];
			const cweIDProb = predictions.cwe.cwe_id_prob[vulCount];
			const cweType = predictions.cwe.cwe_type[vulCount];
			const cweTypeProb = predictions.cwe.cwe_type_prob[vulCount];

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

			let cweData : any[] = [];

			getCWEData([[cweType,cweID.substring(4)]]).then((cweData: any) => {
				cweData = cweData;
			}).catch((err: string) => {
				debugMessage(DebugTypes.error, err);
			}
			);

			for(var i = 0; i < config.maxLines; i++){
				
				const vulnLine = lineScoreShiftMapped[i][0];

				const lines = doc?.getText().split("\n") ?? [];

				let line = doc?.lineAt(vulnLine);

				let diagMessage = "";

				switch(config.informationLevel){
					case InformationLevels.core: {
						diagMessage = "Line: " + (vulnLine+1) + " | Severity: " + sevScore.toString().match(/^\d+(?:\.\d{0,2})?/) + " | CWE: " + cweID.substring(4) + " " +( (cweData === undefined || "") ? "" : "(" + cweData + ") ")  + "| Type: " + cweType;
						break;
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

				diagnostic.source = "AiBugHunter";

				
				diagnostics.push(diagnostic);
			}
			vulCount++;
		}
	});

	diagnosticCollection.set(doc.uri, diagnostics);
	
	return diagnostics;
}

async function getCWEData(list:any){
	return "Not Implemented";
}