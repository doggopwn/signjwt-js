const repl = require('repl')
const readline = require('readline')
const interf = readline.createInterface({
	input: process.stdin,
	output: process.stdout
})
function waitForResponse(q) {
	return new Promise(res => {
		interf.question(q, res)
	})
}

const snakeToCamel = str => str.toLowerCase().replace(/([-_][a-z])/g, group => group.toUpperCase().replace('-', '').replace('_', ''))

let SSL;
async function makeSSLFunction(func, returnTypePassed, argTypesPassed){
	if (func === "ENABLE_DEBUG"){
		SSL["ENABLE_DEBUG"] = SSL.cwrap(func, null, null);
		SSL.ENABLE_DEBUG();
		return `\x1b[32m\u2713 Enabled DEBUG logging\x1b[0m`;
	} else {
		const jsName = snakeToCamel(func);
		const returnType = returnTypePassed||(await waitForResponse(`Return type of ${func}?: `)) || null
		const argTypesStr = argTypesPassed||(await waitForResponse(`Argument types of ${func} (number/string/array or empty)?: `));
		const argTypes = argTypesStr?.split(",") || null;

		SSL[jsName] = SSL.cwrap(func, returnType, argTypes)
		return `\x1b[32m\u2713 SSL.${jsName}(${argTypes.join(", ")}) => ${returnType}\x1b[0m`
	}
}

async function makeSSLFunctions(funcs){
	const logList = [];
	for (const func of funcs){
		const types = func.split(":");
		if (types.length > 1){
			logList.push(await makeSSLFunction(...types));
		} else {
			logList.push(await makeSSLFunction(func));	
		}
	}
	interf.close()
	for (const log of logList){
		console.log(log)
	}
}


console.log("Importing SSL module..")

async function init(funcArgs){
	return new Promise(res => {
		const parsePromise = require('./libssl.js')().then(retSSL => {
			SSL = retSSL;
			const fromArgvs = process.argv[2]?.split(",");
			const fromArgs = funcArgs?.split(";")
			let parsedFuncs;
			if (fromArgs && fromArgs.length > 1){
				parsedFuncs = fromArgs.map(f => f.slice(1))
			} else {
				parsedFuncs = fromArgvs.map(f => f.slice(1))
			}
			makeSSLFunctions(parsedFuncs||funcArgs, SSL).then(_ => res(SSL))
		})
	})
}

module.exports = init;

if (require.main === module){
	init().then(_ => {
		repl.start().context.SSL = SSL;
	})
}




