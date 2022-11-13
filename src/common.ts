import { EventEmitter } from "stream";
import { DebugTypes, ProgressStages } from "./config";
import * as vscode from 'vscode';
import { progressEmitter } from "./extension";

const axios = require('axios');

export class Progress extends EventEmitter{
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


/**
 * Downloads stream from specified URL then writes to file
 * @param writer Stream to write to
 * @param url Download URL
 * @returns Promise that resolves when download is complete
 */
export async function downloadEngine(writer:any, url: string | undefined){

	if(url === undefined){
		return Promise.reject("No URL specified");
	}

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
export function debugMessage(type:string, message:string){
	console.log("[" + type + "] [" + new Date().toISOString() + "] " + message);
}


/**
 * Creates a new progress bar when init is emitted from ProgressEmitter, and handle events until 'end' is emitted
 * @param stage Stages in the progress
 */

 export async function progressHandler(stage: ProgressStages){
	await vscode.window.withProgress({
		location: vscode.ProgressLocation.Window,
		title: "AIBugHunter",
		cancellable: true
	}, (progress, token) => {

		token.onCancellationRequested(() => {
			debugMessage(DebugTypes.info, "User canceled the running operation");
		});

		switch(stage){
			case ProgressStages.extensionInitStart: progress.report({ message: "Initialisation - Downloading models and CWE List...", increment: 0}); break;
			case ProgressStages.analysisStart: progress.report({ message: "Starting analysis...", increment: 0}); break;
		}
		
		progressEmitter.on('update', (stage: ProgressStages) =>{
			switch(stage){
				case ProgressStages.downloadCWEXMLStart: progress.report({ message: "Downloading CWE XML file...", increment: 5}); break;
				case ProgressStages.downloadModelStart: progress.report({ message: "Downloading ML models...", increment: 5}); break;
				case ProgressStages.fetchSymbolStart: progress.report({message: "Getting symbols...", increment:10}); break;
				case ProgressStages.inferenceLineStart: progress.report({message:"Detecting vulnerabilities...", increment: 20}); break;
				case ProgressStages.inferenceCweStart: progress.report({message: "Identifying CWEs...", increment: 50}); break;
				case ProgressStages.inferenceSevStart: progress.report({message: "Getting severity scores...", increment: 70}); break;
				case ProgressStages.predictionEnd: progress.report({message: "Prediction complete", increment: 75}); break;
				case ProgressStages.cweSearchStart: progress.report({message: "Searching CWE descriptions in XML...", increment: 80}); break;
				case ProgressStages.constructDiagnosticsStart: progress.report({message: "Constructing diagnostic collection...", increment: 90}); break;
			}
		});

		const promise = new Promise<void>(resolve => {
			progressEmitter.on('end', (stage:ProgressStages) => {
				switch(stage){
					case ProgressStages.extensionInitEnd: progress.report({message: "Initialisation complete", increment: 100}); break;
					case ProgressStages.error: progress.report({message: "Error occured. Terminating...", increment: 100}); break;
					case ProgressStages.noDocument: progress.report({message: "No document found. Skipping...", increment: 100}); break;
					case ProgressStages.analysisEnd: progress.report({message: "Analysis complete", increment: 100}); break;
					case ProgressStages.ignore: progress.report({message: "Analysis complete (Ignored)", increment: 100}); break;
				}
				setTimeout(() => {
					resolve();
				}, 2000);
			});
		});

		return promise;
	});
}

/**
 * Remove comments from the given string
 * @param text Text to remove comments from
 * @returns Text without comments
 */
 export function removeComments(text:string): string{

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
export function removeBlankLines(text:string): [string,number[]]{

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