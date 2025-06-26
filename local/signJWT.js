// Expecting SSL to be emscripten 'Module'
// Error codes //
// -1 = Invalid private key data (not array)
// -2 = Invalid passphrase (not string)
// -3 = Invalid header (not string/JSON)
// -4 = Invalid payload (not string/JSON)

module.exports = async function(SSL, pkeyData, passphrase, header, payload){
	const errorTable = {
			1: "Invalid private key data",
			2: "Invalid passphrase",
			3: "Invalid header",
			4: "Invalid payload",
			5: "Incorrect PEM passphrase",
			6: "Failed to parse private key data",
		}
	function error(code, retry){
		return {error: errorTable[-1*code], retry, code};
	}
	function tryJSON(str){
		try {
			return JSON.stringify(str);
		} catch (e) {
			return null;
		}
	}

	if (typeof SSL === 'function'){
		SSL = await SSL();
	}

	// Enable debug if built in debug mode
	if (SSL._ENABLE_DEBUG) SSL._ENABLE_DEBUG();

	// Typechecks
	if (!Array.isArray(pkeyData)){
		if (Uint8Array && pkeyData instanceof Uint8Array){ // node 
			pkeyData = Array.from(pkeyData);
		} else {
			return error(-1, false);
		}
	}
	if (typeof passphrase !== "string"){
			return error(-2, false);
	}
	if (typeof header !== "string"){
		header = tryJSON(header);
		if (!header) return error(-3, false);
	}
	if (typeof payload !== "string"){
		payload = tryJSON(payload);
		if (!payload) return error(-4, false);
	}

	// Disable entropy requirements - secure for RSA-SHA256 with PKCS#1-v1.5 padding
	SSL._disable_entropy_requirement();
	
	// Generate private key object

	const pkeyPtrPtr = SSL._malloc(4); // !! free
	SSL.setValue(pkeyPtrPtr, 0, '*');

	const pkeyDataPtr = SSL._malloc(pkeyData.length+1); // !! free
	SSL.writeArrayToMemory(Array.from(pkeyData), pkeyDataPtr);

	// Assuming passphrase is ASCII only!!
	const passphrasePtr = SSL._malloc(passphrase.length+1); // !! free
	SSL.stringToUTF8(passphrase, passphrasePtr, passphrase.length+1);

	const pkeyResult = SSL._make_PEM_key(pkeyPtrPtr, pkeyDataPtr, passphrasePtr);
	if (pkeyResult == -1){
		return error(-5, true);
	} else if (pkeyResult == -2){
		return error(-6, false);
	}
	
	const pkeyPtr = SSL.getValue(pkeyPtrPtr, '*'); // !! free

	// Free pkey memory
	SSL._free(pkeyDataPtr)
	SSL._free(pkeyPtrPtr);
	SSL._free(passphrasePtr);
	
	// Sign string

	const headerPtr = SSL._malloc(header.length+1); // !! free
	SSL.stringToUTF8(header, headerPtr, header.length+1);

	const payloadPtr = SSL._malloc(payload.length+1); // !! free
	SSL.stringToUTF8(payload, payloadPtr, payload.length+1);

	const signedPtr = SSL._sign_jwt(pkeyDataPtr, pkeyPtr, headerPtr, payloadPtr); // !! free this addr
	const signedString = SSL.UTF8ToString(signedPtr);

	// free sign_jwt memory
	SSL._free(pkeyPtr);
	//SSL._free(headerPtr); // buffer is deallocated already due to encode_base64 in c++ 
	//SSL._free(payloadPtr); // -//-
	SSL._free(signedPtr);

	return signedString;

}
