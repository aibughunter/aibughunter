/* eslint-disable @typescript-eslint/naming-convention */
import { DebugTypes, InferenceModes, ProgressStages } from "./config";
import { debugMessage } from "./common";
import { PythonShell } from 'python-shell';
import { config, progressEmitter, VulDiagnostic } from "./extension";
import path = require("path");

const axios = require('axios');

export interface Inference {
	line(list: Array<string>): Promise<any>;
	cwe(list: Array<string>): Promise<any>;
	sev(list: Array<string>): Promise<any>;
}

export abstract class InferenceEngine implements Inference {

	targetDiagnostic: VulDiagnostic;

	constructor(targetDiagnostic: VulDiagnostic) {
		this.targetDiagnostic = targetDiagnostic;
	}

	line(list: string[]): Promise<any> {
		throw new Error("Method not implemented.");
	}
	cwe(list: string[]): Promise<any> {
		throw new Error("Method not implemented.");
	}
	sev(list: string[]): Promise<any> {
		throw new Error("Method not implemented.");
	}
}
export class LocalInference extends InferenceEngine implements Inference{

	scriptLocation: string = path.join(__dirname, "..", "resources", "local-inference");

	public async line(list: Array<string>): Promise<any>{

		if(this.targetDiagnostic.ignore){
			return Promise.resolve();
		}

		debugMessage(DebugTypes.info, "Starting line inference");

		const shell = new PythonShell('local.py', {mode:'text', args: ["line", (config.useCUDA ? "True" : "False")], scriptPath: this.scriptLocation});

		debugMessage(DebugTypes.info, "Sending data to python script");
		let start = new Date().getTime();
		shell.send(JSON.stringify(list));


		return new Promise((resolve, reject) => {
			shell.on('message', async (message: any) => {
				let end = new Date().getTime();
				debugMessage(DebugTypes.info, "Received response from python script in " + (end - start) + "ms");
				this.targetDiagnostic.predictions.line = JSON.parse(message);
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

		if(this.targetDiagnostic.ignore){
			return Promise.resolve();
		}

		debugMessage(DebugTypes.info, "Starting CWE prediction");

		const shell = new PythonShell('local.py', {mode:'text', args: ["cwe", (config.useCUDA ? "True" : "False")], scriptPath: this.scriptLocation});

		debugMessage(DebugTypes.info, "Sending data to python script");
		let start = new Date().getTime();
		shell.send(JSON.stringify(list));

		return new Promise((resolve, reject) => {
			shell.on('message', async (message: any) => {
				let end = new Date().getTime();
				debugMessage(DebugTypes.info, "Received response from python script in " + (end - start) + "ms");
				this.targetDiagnostic.predictions.cwe = JSON.parse(message);
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

		if(this.targetDiagnostic.ignore){
			return Promise.resolve();
		}

		debugMessage(DebugTypes.info, "Starting severity prediction");

		const shell = new PythonShell('local.py', {mode:'text', args: ["sev", (config.useCUDA ? "True" : "False")], scriptPath: this.scriptLocation});

		debugMessage(DebugTypes.info, "Sending data to python script");
		let start = new Date().getTime();
		shell.send(JSON.stringify(list));

		return new Promise((resolve, reject) => {
			shell.on('message', async (message: any) => {
				let end = new Date().getTime();
				debugMessage(DebugTypes.info, "Received response from python script in " + (end - start) + "ms");
				this.targetDiagnostic.predictions.sev = JSON.parse(message);
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

export class RemoteInference extends InferenceEngine implements Inference{

	/**
	 * Takes a list of all functions in the document, sends them to the remote inference engine and returns the results
	 * @param list List of functions to analyse
	 * @returns Promise that resolves when successfully received results, rejects if error occurs
	 */
	public async line(list: Array<string>): Promise<any>{

		if(this.targetDiagnostic.ignore){
			return Promise.resolve();
		}

		let jsonObject = JSON.stringify(list);
		
		var signal = new AbortController;
		signal.abort;
		var start = new Date().getTime();
		
		debugMessage(DebugTypes.info, "Sending line detection request to " + ((config.inferenceMode === InferenceModes.onpremise)? config.inferenceURLs.onPremise : config.inferenceURLs.cloud) + ((config.useCUDA)? config.endpoints.line.gpu : config.endpoints.line.cpu));
		progressEmitter.emit('update', ProgressStages.inferenceLineStart);

		await axios({
			method: "post",
			url: ((config.inferenceMode === InferenceModes.onpremise)? config.inferenceURLs.onPremise : config.inferenceURLs.cloud) + ((config.useCUDA)? "/api/v1/gpu/predict" : "/api/v1/cpu/predict"),
			data: jsonObject,
			signal: signal.signal,
			headers: { "Content-Type":"application/json"},
		  })
			.then(async  (response: any) => {
				var end = new Date().getTime();
				var diffInSeconds = (end - start) / 1000;

				this.targetDiagnostic.predictions.line = JSON.parse(response.data);

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

		if(this.targetDiagnostic.ignore){
			return Promise.resolve();
		}

		let jsonObject = JSON.stringify(list);

		var signal = new AbortController;
		signal.abort;
		var start = new Date().getTime();

		debugMessage(DebugTypes.info, "Sending CWE detection request to " + ((config.inferenceMode === InferenceModes.onpremise)? config.inferenceURLs.onPremise : config.inferenceURLs.cloud) + ((config.useCUDA)? config.endpoints.cwe.gpu : config.endpoints.cwe.cpu));
		progressEmitter.emit('update', ProgressStages.inferenceCweStart);
		await axios({
			method: "post",
			url: ((config.inferenceMode === InferenceModes.onpremise)? config.inferenceURLs.onPremise : config.inferenceURLs.cloud) + ((config.useCUDA)? "/api/v1/gpu/cwe" : "/api/v1/cpu/cwe"),
			data: jsonObject,
			signal: signal.signal,
			headers: { "Content-Type":"application/json"},
		})
			.then( (response: any) => {
				var end = new Date().getTime();
				var diffInSeconds = (end - start) / 1000;

				debugMessage(DebugTypes.info, "Received response from model in " + diffInSeconds + " seconds");
				this.targetDiagnostic.predictions.cwe = JSON.parse(response.data);

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

		if(this.targetDiagnostic.ignore){
			return Promise.resolve();
		}

		let jsonObject = JSON.stringify(list);
		var signal = new AbortController;
		signal.abort;
		var start = new Date().getTime();

		debugMessage(DebugTypes.info, "Sending security score request to " + ((config.inferenceMode === InferenceModes.onpremise)? config.inferenceURLs.onPremise : config.inferenceURLs.cloud) + ((config.useCUDA)? config.endpoints.sev.gpu : config.endpoints.sev.cpu));
		progressEmitter.emit('update', ProgressStages.inferenceSevStart);

		await axios({
			method: "post",
			url: ((config.inferenceMode === InferenceModes.onpremise)? config.inferenceURLs.onPremise : config.inferenceURLs.cloud) + ((config.useCUDA)? "/api/v1/gpu/sev" : "/api/v1/cpu/sev"),
			data: jsonObject,
			signal: signal.signal,
			headers: { "Content-Type":"application/json"},
			})
			.then( (response: any) => {
				var end = new Date().getTime();
				var diffInSeconds = (end - start) / 1000;

				debugMessage(DebugTypes.info, "Received response from model in " + diffInSeconds + " seconds");
				this.targetDiagnostic.predictions.sev = JSON.parse(response.data);

				return Promise.resolve(response.data);
			})
			.catch(function (response: any) {
				debugMessage(DebugTypes.error, response);
				return Promise.reject(response);
			});
	}
}
