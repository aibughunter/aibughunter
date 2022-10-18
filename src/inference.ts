import { DebugTypes, InferenceModes, ProgressStages, remoteInferenceURLs } from "./config";
import { debugMessage } from "./core";
import { PythonShell } from 'python-shell';
import { config, predictions, progressEmitter } from "./extension";

const axios = require('axios');

export class LocalInference{
	public async line(list: Array<string>): Promise<any>{

		debugMessage(DebugTypes.info, "Starting line inference");

		const shell = new PythonShell('deploy.py', {mode:'text', args: ["line", (config.gpu ? "True" : "False")], scriptPath: config.localInferenceDir});

		debugMessage(DebugTypes.info, "Sending data to python script");
		let start = new Date().getTime();
		shell.send(JSON.stringify(list));


		return new Promise((resolve, reject) => {
			shell.on('message', async (message: any) => {
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

		const shell = new PythonShell('deploy.py', {mode:'text', args: ["cwe", (config.gpu ? "True" : "False")], scriptPath: config.localInferenceDir});

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

		const shell = new PythonShell('deploy.py', {mode:'text', args: ["sev", (config.gpu ? "True" : "False")], scriptPath: config.localInferenceDir});

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

				predictions.line = JSON.parse(response.data);

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
				predictions.cwe = JSON.parse(response.data);

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
				predictions.sev = JSON.parse(response.data);

				return Promise.resolve(response.data);
			})
			.catch(function (response: any) {
				debugMessage(DebugTypes.error, response);
				return Promise.reject(response);
			});
	}
}
