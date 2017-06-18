#include "aes_def.h"

// code from stackoverflow
// https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl

typedef struct {
    unsigned char ivec[16];  /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned int num;
    unsigned char ecount[16];
} ctr_state;

int init_ctr(
	ctr_state *state, 
	const unsigned char* iv
)
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, 16);

    // /* Initialise counter in 'ivec' to 0 */
    // memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 16);

	return 0;
}

Handle<std::string> AES_CTR_encrypt
(
	Handle<std::string> hKey, 
	Handle<std::string> hMsg, 
	Handle<std::string> hCounter, 
	int length, 
	bool encrypt
) 
{
	LOG_FUNC();

	LOG_INFO("AES key");

	const byte *key = reinterpret_cast<const byte*>(hKey->c_str());
	uint8_t keylen = (uint8_t)hKey->length();

	if (!keylen) {
		THROW_ERROR("Error on AES key getting");
	}

	LOG_INFO("data");
	const byte *data = reinterpret_cast<const byte*> (hMsg->c_str());
	int datalen = (int)hMsg->length();

	LOG_INFO("counter");
	const byte *counter = reinterpret_cast<const byte*>(hCounter->c_str());
	uint8_t counterLength = (uint8_t)hCounter->length();
    if (counterLength != 16) {
        THROW_ERROR("Wrong size of 'counter'");
    }

	LOG_INFO("length");
	if (length < 1 || length > 128) {
		THROW_ERROR("Incorrect value 'length'. Must be between 1 and 128.");
	}

	AES_KEY aesKey;
	if (AES_set_encrypt_key(key, keylen << 3, &aesKey)) {
		THROW_OPENSSL("AES_set_encrypt_key");
	}

	ctr_state state;

	init_ctr(&state, counter);

	Handle<std::string> hOutput(new std::string(""));
	hOutput->resize(datalen);
	unsigned char *output = (unsigned char*)hOutput->c_str();

    AES_ctr128_encrypt(data, output, datalen, &aesKey, state.ivec, state.ecount, &state.num);

	LOG_INFO("Resize output");

	return hOutput;
}

Handle<std::string> ScopedAES::encryptCtr(Handle<std::string> hMsg, Handle<std::string> hCounter, int length) {
	LOG_FUNC();

	return AES_CTR_encrypt(this->value, hMsg, hCounter, length, true);
}

Handle<std::string> ScopedAES::decryptCtr(Handle<std::string> hMsg, Handle<std::string> hCounter, int length) {
	LOG_FUNC();

	return AES_CTR_encrypt(this->value, hMsg, hCounter, length, false);
}
