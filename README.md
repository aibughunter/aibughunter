# AI Bug Hunter VSCode Extension

AI-based software vulnerability prediction IDE plug-in that was trained using data from National Vulnerability Database (NVD), which can generate vulnerability predictions for a source code function.

Specifically, the model will highlight the vulnerable line in the source code and predict:

1. The potentially vulnerable line in a function
2. The types of the predicted vulnerability (i.e., CWE-ID, CWE Type)
3. The severity of the predicted vulnerability
4. The potential fix to the vulnerability

AIBugHunter will provide accurate vulnerability predictions that enable software developers to detect vulnerabilities in their IDEs.

## Known Issues

- Native implementation of model inference not possible as RoBERTa tokeniser is not available on npm/Node JS
- GPU mode on local inference does not provide any benefits (potentially due to dependencies?)
- Unzip may take longer than individually downloading each files

## TODO

- File checking for individual files (Checksum?)
- Cloud inference option
