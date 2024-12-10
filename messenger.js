'use strict'

const {
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')
class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
      // the certificate authority DSA public key is used to
      // verify the authenticity and integrity of certificates
      // of other users (see handout and receiveCertificate)

      this.caPublicKey = certAuthorityPublicKey;
      this.govPublicKey = govPublicKey;
      this.conns = {}; // data for each active connection
      this.certs = {}; // certificates of other users
      this.myKeyPairs = {}; // store the EG key pairs for all the people I talk to! 

    };

  async generateCertificate(username) {
    const certificate = {};
    certificate.username = username;
    const key_pair = await generateEG();
    certificate.pub_key = key_pair.pub;
    
    // this.conns.seenPks = new Set();
    this.myKeyPairs = {cert_pk: key_pair.pub, cert_sk: key_pair.sec};
    return certificate;
  }
  async receiveCertificate(certificate, signature) {
    //check this is a valid signature on the certificate

    const valid = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature)
    if(!valid) throw("invalid signature provided");
    this.certs[certificate.username] = certificate;
  }

  async sendMessage(name, plaintext) {    
    //generate rk / ck if user has not communicated with name before.
    if (!(name in this.conns)) {
      const bob_public_key = this.certs[name].pub_key;

      const raw_root_key = await computeDH(this.myKeyPairs.cert_sk, bob_public_key);

      const fresh_pair = await generateEG();
      this.myKeyPairs[name] = {pub_key: fresh_pair.pub, sec_key: fresh_pair.sec}; //to be updated further during DH ratchet in receiveMessage();

      const hkdf_input_key = await computeDH(this.myKeyPairs[name].sec_key, bob_public_key); //const hkdf_input_key = await computeDH(this.myKeyPairs.sec_key, header.pk_sender);

      const [root_key, chain_key] = await HKDF(hkdf_input_key, raw_root_key, "ratchet-salt");
      
      this.conns[name] = {rk: root_key, ck_s: chain_key};

      this.conns[name].seenPks = new Set()

    }
    //at this point we know we have a rk and ck_s

    const N = this.conns[name].N || 0
    const PN = this.conns[name].PN || 0

    //ck_s is undefined because receive() is first called, which adds rk and ck_r but not ck_s
    const ck_s = await HMACtoHMACKey(this.conns[name].ck_s, "ck-str");
    const mk = await HMACtoAESKey(this.conns[name].ck_s, "mk-str");
    const mk_buffer = await HMACtoAESKey(this.conns[name].ck_s, "mk-str", true);
    this.conns[name].ck_s = ck_s; 

    //form header
    const ivGov = genRandomSalt();
    const receiverIV = genRandomSalt();
    const new_gov_pair = await generateEG();

    //gov needs to be able to derive dh_secret given 1) govPublicKey and 2) new_gov_par.pub (vGov)
    const dh_secret = await computeDH(new_gov_pair.sec, this.govPublicKey); // pub^sec --> (g^b)^a
    const dh_secret_key = await HMACtoAESKey(dh_secret, govEncryptionDataStr); //k = H(v, m) Since computeDH() output is configured with HMAC, need to run the output through HMACtoAESKey() to generate a key that can be used with AES-GCM
    const cGov = await encryptWithGCM(dh_secret_key, mk_buffer, ivGov); 
    
    
    //form header 
    const header = {
      vGov: new_gov_pair.pub, 
      cGov: cGov, 
      receiverIV: receiverIV, 
      ivGov: ivGov,
      pk_sender: this.myKeyPairs[name].pub_key,
      N: N,
      PN: PN
     }; 

    this.conns[name].N = N + 1

    //encrypt message
    const ciphertext = await encryptWithGCM(mk, plaintext, receiverIV, JSON.stringify(header));

    return [header, ciphertext];
  }

  async receiveMessage(name, [header, ciphertext]) {
    if (!(name in this.conns)) {
      const sender_cerk_pk = this.certs[name].pub_key;
      const raw_root_key = await computeDH(this.myKeyPairs.cert_sk, sender_cerk_pk);
      const hkdf_input_key = await computeDH(this.myKeyPairs.cert_sk, header.pk_sender);
      const [root_key, chain_key] = await HKDF(hkdf_input_key, raw_root_key, "ratchet-salt");

      const fresh_pair = await generateEG();
      this.myKeyPairs[name] = {pub_key: fresh_pair.pub, sec_key: fresh_pair.sec};

      const dh_result = await computeDH(this.myKeyPairs[name].sec_key, header.pk_sender);

      const [final_root_key, ck_s] = await HKDF(dh_result, root_key, "ratchet-salt");
    
      this.conns[name] = {rk: final_root_key, ck_r: chain_key, ck_s: ck_s};

      //create seen pks set
      this.conns[name].seenPks = new Set()
      this.conns[name].skippedKeys = {};  // Changed to object to store keys by chain
      this.conns[name].N = 0
      this.conns[name].PN = 0
      this.conns[name].messageKeys = new Set(); // Store message keys by chain and number
      this.conns[name].previousChain = null;
      
    } else if (!(this.conns[name].seenPks.has(header.pk_sender))) {

      // Save the current chain state before ratchet
      this.conns[name].previousChain = {
        ck_r: this.conns[name].ck_r,
        N: this.conns[name].N
      };

      // Store skipped messages from current chain
      const skippedInPreviousChain = header.PN - this.conns[name].N;
      if (skippedInPreviousChain > 0) {
        let chainCk = this.conns[name].ck_r;
        for (let i = this.conns[name].N; i < header.PN; i++) {
          const mk = await HMACtoAESKey(chainCk, "mk-str");
          chainCk = await HMACtoHMACKey(chainCk, "ck-str");
          this.conns[name].messageKeys.add(`prev:${i}`, mk);
        }
      }

      const first_dh_output = await computeDH(this.myKeyPairs[name].sec_key, header.pk_sender);
      let [rk_first, ck_r] = await HKDF(first_dh_output, this.conns[name].rk, "ratchet-salt"); //see Signal diagram

      const fresh_pair = await generateEG();
      this.myKeyPairs[name] = {pub_key: fresh_pair.pub, sec_key: fresh_pair.sec}

      const second_dh_output = await computeDH(this.myKeyPairs[name].sec_key, header.pk_sender);
      const [rk, ck_s] = await HKDF(second_dh_output, rk_first, "ratchet-salt"); //see Signal diagram
      this.conns[name].rk = rk;
      this.conns[name].ck_s = ck_s;
      this.conns[name].ck_r = ck_r;
      this.conns[name].PN = this.conns[name].N;
      this.conns[name].N = 0;

    }

    //Apply symmetric-key ratchet on receiving chain to get message key for the received message
    const ck_r = await HMACtoHMACKey(this.conns[name].ck_r, "ck-str");
    const mk = await HMACtoAESKey(this.conns[name].ck_r, "mk-str");
    
    //update ck_r and the public key of the last sender
    this.conns[name].ck_r = ck_r;
    this.conns[name].seenPks.add(header.pk_sender)
    
    const plaintext = await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header));
    this.conns[name].N = header.N + 1;
    return bufferToString(plaintext);
  }
};

module.exports = { MessengerClient }