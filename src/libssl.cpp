#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/decoder.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <cstring>
#include <cmath>
#include <prov/names.h>
#include <stdexcept>

extern "C" {
	int DEBUG_ON=0;

	// call to enable debug - called automatically by linux/importSSL.js when function exported (in dev env)
	void ENABLE_DEBUG(){
	//	fakerand_enable_debug();
		DEBUG_ON = 1;
	}

	void DEBUG(const char* msg, ...){
		va_list args;
		va_start (args, msg);
		if (DEBUG_ON == 1){	
			vprintf (msg, args);
		}
		va_end (args);
	}


	// Automatically frees original buffer
	// Returns new buffer that needs to be FREED BY CALLER
	void to_base64url(unsigned char** src){
		size_t src_len = strlen((char*)*src);
		DEBUG("Encoding to base64url, input length %i\n", src_len);
		
		unsigned char* new_buffer = new unsigned char[src_len+1]();
		unsigned char* read;
		unsigned char* write;
		read=*src;
		write=new_buffer;

		int i;
		for (i=0; i < src_len; i++){
			if (*read == '=') break;
			else if (*read == '/') *write = '_';
			else if (*read == '+') *write = '-';
			else *write = *read;

			read++;
			write++;
		}
		*write = '\0';

		DEBUG("Produced %i bytes of base64url\n", strlen((char*)new_buffer));
		delete[] *src;
		*src=new_buffer;
	}

	// Automatically frees original buffer
	// Returns new buffer that needs to be FREED BY CALLER
	/*void to_base64(unsigned char** src){
		size_t src_len = strlen((char*)*src);
		size_t padding = (src_len % 4);
		DEBUG("Encoding to base64, input length %i, adding padding of %i\n", src_len, padding);
	

		unsigned char* new_buffer = new unsigned char[src_len+padding+1]();
		unsigned char* read;
		unsigned char* write;
		read=*src;
		write = new_buffer;

		int i;
		for (i=0; i < src_len; i++){
			if (*read == '_') *write = '/';
			else if (*read == '-') *write = '+';
			else *write = *read;
			read++;
			write++;
		}
		for (i = 0; i < padding; i++){
			*write = '=';
			write++;
		}
		*write = '\0';

		DEBUG("Produced %i bytes of base64\n", strlen((char*)new_buffer));
		delete[] *src;
		*src=new_buffer;
	}*/

	void replace_all(unsigned char** source, char delim){
		size_t source_len = strlen((char*)*source);

		int i;
		unsigned char* read;
		unsigned char* write;
		unsigned char* stripped = new unsigned char[source_len]();
		
		read=*source;
		write=stripped;
		
		for (i=0; i < source_len; i++){
			if (*read != delim){
				*write = *read;
				write++;
			}
			read++;
		}
		*write = '\0';

		delete[] *source;
		*source=stripped;
	}

	// Automatically clears input buffer
	// Allow to query for new buffer length by setting output pointer to NULL
	void encode_base64(unsigned char** output, int* output_len, const unsigned char* input, size_t input_len)
	{
		int req_output_len = std::ceil(input_len/48.0)*65 + 1;	
		if (output == NULL){
			*output_len = req_output_len; 
			return;
		} else {
			if (*output_len < req_output_len){
				delete[] input;
				delete[] *output;
				DEBUG("Provided buffer is insufficiently large for base64 encoding. Run function with first argument as NULL to query needed size. Would cause buffer overflow.");
				throw std::runtime_error("Provided buffer is insufficiently large for base64 encoding. Run function with first argument as NULL to query needed size. Would cause buffer overflow.");
			}	
		}
		
		DEBUG("Encoding %i bytes of data..\n", input_len);


		EVP_ENCODE_CTX* encode_ctx = EVP_ENCODE_CTX_new();
		if (encode_ctx == NULL){
			DEBUG("Failed to initialize Base64 encoding context.");
			throw std::runtime_error("Failed to initialize Base64 encoding context.");
		}

		int written_size = 0;
		int total_encoded = 0;

		EVP_EncodeInit(encode_ctx);
		if (EVP_EncodeUpdate(encode_ctx, *output, &written_size, input, input_len) <= 0){
			DEBUG("Failed to encode block of data as Base64.");
			throw std::runtime_error("Failed to encode block of data as Base64");
		}

		DEBUG("First block: %s", *output);
		total_encoded += written_size;

		EVP_EncodeFinal(encode_ctx, *output+written_size, &written_size);	

		total_encoded += written_size;	
		DEBUG("Encoded %i bytes in total (with newlines)\n", total_encoded);

		replace_all(output, '\n');
		DEBUG("Encoded %i bytes in total (without newlines)\n", strlen((char*)*output));
		DEBUG("Pointer: %p\n", output);

		EVP_ENCODE_CTX_free(encode_ctx);
		delete[] input;

	}

	// assumes RSA with SHA256
	// Returned buffer must be FREED BY CALLER (e.g. free_string)
	unsigned char* sign_string(unsigned char* pkeyData, EVP_PKEY* pkey, const unsigned char* string){


		EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (pkey_ctx == NULL){
			DEBUG("Failed to initialize private key context\n");	
			throw std::runtime_error("Failed to initialize private key context");
		}

		EVP_SIGNATURE* algo = EVP_SIGNATURE_fetch(NULL, "RSA-SHA256", NULL);
		if (algo == NULL){
			DEBUG("Failed to fetch RSA-SHA256 algorithm\n");
			throw std::runtime_error("Failed to fetch RSA-SHA256 algorithm.");
		}

		DEBUG("Attempting to sign %i bytes of data with private key\n", strlen((char*)string));
		if (EVP_PKEY_sign_message_init(pkey_ctx, algo, NULL) <= 0){
			DEBUG("Failed to initialize key signing process\n");
			throw std::runtime_error("Failed to initialize key signing process");
		}

		int padding = 0;
		EVP_PKEY_CTX_get_rsa_padding(pkey_ctx, &padding);

		size_t max_output_size;
		if (EVP_PKEY_sign(pkey_ctx, NULL, &max_output_size, string, strlen((char*)string)) <= 0){
			DEBUG("Error getting output length\n");
			throw std::runtime_error("Failed to get output length from signing function");
		}
	
		unsigned char* output = new unsigned char[max_output_size]();
		DEBUG("Allocated %i bytes of data for signing output\n", max_output_size);
	

		if (EVP_PKEY_sign(pkey_ctx, output, &max_output_size, string, strlen((char*)string)) <= 0){
			DEBUG("Failed to sign given data with private key.\n");
			unsigned long error = ERR_get_error();
			char* error_str = ERR_error_string(error, NULL);
			

			DEBUG("Error: %llu\n", error);
			DEBUG("Error msg: %s\n", error_str);
			throw std::runtime_error("Failed to sign given data with private key.");
		}


		DEBUG("Successfuly produced signature. Encoding in Base64...\n");

		int b64_output_len;
		encode_base64(NULL, &b64_output_len, NULL, max_output_size);
		unsigned char* encoded = new unsigned char[b64_output_len]();

		DEBUG("Allocated %i bytes for encoding output\n", b64_output_len);

		encode_base64(&encoded, &b64_output_len, output, max_output_size);
		
		DEBUG("Encoded b64: %s\n", encoded);

		to_base64url(&encoded);
		DEBUG("Base64url: %s\n", encoded);

		EVP_SIGNATURE_free(algo);
		EVP_PKEY_CTX_free(pkey_ctx);

		return encoded;

		
	}
	// Return values //
	// 0 = OK
	// -1 = Write error	
	int BIO_from_data(BIO** bio, const char* data){
		*bio = BIO_new(BIO_s_mem());
		if (bio == NULL){ 
			throw std::runtime_error("Failed to initialize memory BIO.");
		}
		if (BIO_puts(*bio, data) <= 0) {
			BIO_free(*bio);
			return -1;
		}
		DEBUG("Created memory BIO with %i bytes of data\n", strlen((char*)data));
		DEBUG("Pointer: %p\n", bio);
		
		return 0;
	}

	// Return values //
	// 0 = OK
	// -1 = Invalid data or incorrect passphrase
	// -2 = Invalid data (error during BIO creation)
	// (implicit casting of nullptr ptr from (void**) to (EVP_PKEY**) by emscripten)
	// Allocated private_key must be FREED BY CALLER (e.g. free_PEM_key)
	int make_PEM_key(EVP_PKEY** private_key_ptr, const char* data, const unsigned char* passphrase){
		BIO* data_bio;
		int bio_success = BIO_from_data(&data_bio, data);
		if (bio_success < 0){
			return -2;
		}

		OSSL_DECODER_CTX* dctx;
		const char* format = "PEM";
		const char* structure = NULL;
		const char* keytype = "RSA";
		
		// 0x01 = Private key
		dctx = OSSL_DECODER_CTX_new_for_pkey(private_key_ptr, format, structure, keytype, 0x01, NULL, NULL);
		if (dctx == NULL){
			throw std::runtime_error("Failed to create decoder context.");
		}
		if (passphrase != NULL){
			if (OSSL_DECODER_CTX_set_passphrase(dctx, passphrase, strlen((char*)passphrase)) < 0){
				throw std::runtime_error("Failed to set passphrase");
			}
		}
		if (!OSSL_DECODER_from_bio(dctx, data_bio)){
			return -1;
		}
		DEBUG("Successfully decoded private PEM (RSA) key\n");
		DEBUG("Pointer: %p\n", *private_key_ptr);

		OSSL_DECODER_CTX_free(dctx);
		BIO_free(data_bio);
		
		return 0;
	}


	// Returned buffer must be FREED BY CALLER (e.g. free_string)
	unsigned char* sign_jwt(unsigned char* pkeyData, EVP_PKEY* pkey, unsigned char* header_JSON, unsigned char* payload_JSON){

		DEBUG("header (unencoded): %s\n", header_JSON);
		DEBUG("payload (unencoded): %s\n", payload_JSON);

		size_t header_JSON_len = strlen((char*)header_JSON);
		int header_enc_len;
		encode_base64(NULL, &header_enc_len, NULL, header_JSON_len);

		unsigned char* header_enc = new unsigned char[header_enc_len]();	
		encode_base64(&header_enc, &header_enc_len, header_JSON, header_JSON_len);
		to_base64url(&header_enc);
		
		DEBUG("header: %s\n", header_enc);

		size_t payload_JSON_len = strlen((char*)payload_JSON);
		int payload_enc_len;
		encode_base64(NULL, &payload_enc_len, NULL, payload_JSON_len);

		unsigned char* payload_enc = new unsigned char[payload_enc_len]();
		encode_base64(&payload_enc, &payload_enc_len, payload_JSON, payload_JSON_len);
		to_base64url(&payload_enc);

		DEBUG("payload: %s\n", payload_enc);

		char delim[2] = ".";

		size_t tosign_string_len = strlen((char*)header_enc)+strlen((char*)payload_enc)+2;
		unsigned char* tosign_string = new unsigned char[tosign_string_len]();

		strcpy((char*)tosign_string, (char*)header_enc);
		strcat((char*)tosign_string, delim);
		strcat((char*)tosign_string, (char*)payload_enc);

		DEBUG("Signing combined string: %s\n", tosign_string);

		unsigned char* signed_string = sign_string(pkeyData, pkey, tosign_string);
		
		size_t full_jwt_len = tosign_string_len + strlen((char*)signed_string) + 1;
		unsigned char* full_jwt = new unsigned char[full_jwt_len]();

		strcpy((char*)full_jwt, (char*)tosign_string);
		strcat((char*)full_jwt, delim);
		strcat((char*)full_jwt, (char*)signed_string);

		delete[] tosign_string;
		delete[] header_enc;
		delete[] payload_enc;

		return full_jwt;	
	}

	void disable_entropy_requirement(){

		OSSL_PROVIDER* fakerand;
		fakerand = OSSL_PROVIDER_load(NULL, "fakerand");
		if (!fakerand) {
			DEBUG("[fakerand] Failed to load fakerand provider\n");
			return;
		}
		DEBUG("[fakerand] Successfully loaded fakerand provider\n");

		OSSL_PROVIDER* default_prov;
		default_prov = OSSL_PROVIDER_load(NULL, "default");
		if (!default_prov){
			DEBUG("Failed to load default provider\n");
		}

		EVP_RAND* rand = EVP_RAND_fetch(NULL, PROV_NAMES_SEED_SRC, "provider=fakerand");
		
		EVP_RAND_CTX* rand_ctx = EVP_RAND_CTX_new(rand, NULL);
		if (!rand_ctx) {
			DEBUG("Failed to create fakerand RAND context\n");
		}	

	//	int result = RAND_set1_random_provider(NULL, fakerand);
	//	DEBUG("Setting random provider to fakerand: %i\n", result);
	}


}
