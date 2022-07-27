import { rejects } from 'assert';
import { copyFileSync } from 'fs';
import { EventEmitter } from 'stream';
import { robertaProcessing } from 'tokenizers/bindings/post-processors';
import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import {Config, DebugTypes, DownloadURLs, FunctionSymbols, HighlightTypes, InferenceModes, InformationLevels, Predictions, ProgressStages} from './config';

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const fsa = require('fs/promises');
// const formdata = require('form-data');
const extract = require('extract-zip');
// const parser = require('xml2js');

let config:Config;
let predictions:Predictions;
let functionSymbols: FunctionSymbols;


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

	let inference;

	switch(config.inferenceMode){
		case InferenceModes.local:inference = new LocalInference();break; 
		case InferenceModes.onpremise:inference = new OnPremiseInference();break;
		case InferenceModes.cloud:inference = new CloudInference();break;
		default:inference = new LocalInference();break;
	}

	var arr = ["a", "b", "c"];
	
	progressEmitter.emit('init', ProgressStages.analysis);

	progressEmitter.emit('update', ProgressStages.symbol);

	await extractFunctions().then(() => {
		debugMessage(DebugTypes.info, "Finished extracting functions");
		progressEmitter.emit('update', ProgressStages.line);
		// progressEmitter.emit('end', ProgressStages.analysis);
	}
	).catch(err => {
		debugMessage(DebugTypes.error, err);
	}
	);

	await inference.line(functionSymbols.functions).then(() => {
		debugMessage(DebugTypes.info, "Finished analysing lines");
		progressEmitter.emit('update', ProgressStages.sev);
	}
	).catch((err: string) => {
		debugMessage(DebugTypes.error, err);
	}
	);

	progressEmitter.emit('end', ProgressStages.analysisEnd);

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

	predictions = {
		line: new Object(),
		sev: new Object(),
		cwe: new Object()
	};

	functionSymbols = {
		functions: Array<string>(),
		shift: Array<Array<number>>(),
		range: Array<vscode.Range>()
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

export class LocalInference{
	public async line(list: Array<string>): Promise<any>{
		console.log("Line detection");
	}

	public cwe(list: Array<string>){
		console.log("CVE detection");
	}

	public severity(list: Array<string>){
		console.log("Severity detection");
	}
}


export class OnPremiseInference{
	public async line(list: Array<string>): Promise<any>{

		let jsonObject = JSON.stringify(list);
		var signal = new AbortController;
		signal.abort;
		var start = new Date().getTime();
		
		debugMessage(DebugTypes.info, "Sending line detection request to " + config.inferenceURL);
		progressEmitter.emit('update', ProgressStages.line);

		await axios({
			method: "post",
			url: config.inferenceURL + "/predict",
			data: jsonObject,
			signal: signal.signal,
			headers: { "Content-Type":"application/json"},
		  })
			.then(async function (response: any) {
				var end = new Date().getTime();
				var diffInSeconds = (end - start) / 1000;

				predictions.line = response.data;

				debugMessage(DebugTypes.info, "Received response from model in " + diffInSeconds + " seconds");
				return Promise.resolve();
			})
			.catch(function (err: any) {
				debugMessage(DebugTypes.error, err);
				return Promise.reject(err);
			});

			// return Promise.resolve(this);
	}

	public cwe(list: Array<string>){
		console.log("CVE detection");
	}

	public severity(list: Array<string>){
		console.log("Severity detection");
	}
}

export class CloudInference{
	public async line(list: Array<string>): Promise<any>{
		console.log("Line detection");
	}

	public cwe(list: Array<string>){
		console.log("CVE detection");
	}

	public severity(list: Array<string>){
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

	const symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>(
		'vscode.executeDocumentSymbolProvider',
		uri
	);

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

		text = text.replace(match[0], newline.repeat(diff));
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

		text = text.replace(match[0], newline.repeat(diff));
	}

	return text;
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