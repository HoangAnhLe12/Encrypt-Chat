'use strict';

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
   govEncryptionDataStr,
} = require('./lib');
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
   }

   async generateCertificate(username) {
      const certificate = {};
      certificate.username = username;
      const key_pair = await generateEG();
      certificate.pub_key = key_pair.pub;

      // this.conns.seenPks = new Set();
      this.myKeyPairs = { cert_pk: key_pair.pub, cert_sk: key_pair.sec };
      return certificate;
   }
   async receiveCertificate(certificate, signature) {
      //check this is a valid signature on the certificate

      const valid = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature);
      if (!valid) throw 'invalid signature provided';
      this.certs[certificate.username] = certificate;
   }

   async sendMessage(name, plaintext) {
      if (!(name in this.conns)) {
         const bob_public_key = this.certs[name].pub_key;
         const raw_root_key = await computeDH(this.myKeyPairs.cert_sk, bob_public_key);
         const fresh_pair = await generateEG();
         this.myKeyPairs[name] = { pub_key: fresh_pair.pub, sec_key: fresh_pair.sec };
         const hkdf_input_key = await computeDH(this.myKeyPairs[name].sec_key, bob_public_key);
         const [root_key, chain_key] = await HKDF(hkdf_input_key, raw_root_key, 'ratchet-salt');

         this.conns[name] = { rk: root_key, ck_s: chain_key, sendingN: 0, prevSendingN: 0, skippedKeys: {} };
         this.conns[name].seenPks = new Set();
      }

      const ck_s = await HMACtoHMACKey(this.conns[name].ck_s, 'ck-str');
      const mk = await HMACtoAESKey(this.conns[name].ck_s, 'mk-str');
      const mk_buffer = await HMACtoAESKey(this.conns[name].ck_s, 'mk-str', true);
      this.conns[name].ck_s = ck_s;

      const ivGov = genRandomSalt();
      const receiverIV = genRandomSalt();
      const new_gov_pair = await generateEG();
      const dh_secret = await computeDH(new_gov_pair.sec, this.govPublicKey);
      const dh_secret_key = await HMACtoAESKey(dh_secret, govEncryptionDataStr);
      const cGov = await encryptWithGCM(dh_secret_key, mk_buffer, ivGov);

      const header = {
         vGov: new_gov_pair.pub,
         cGov: cGov,
         receiverIV: receiverIV,
         ivGov: ivGov,
         pk_sender: this.myKeyPairs[name].pub_key,
         N: this.conns[name].sendingN,
         PN: this.conns[name].prevSendingN,
      };

      const ciphertext = await encryptWithGCM(mk, plaintext, receiverIV, JSON.stringify(header));

      this.conns[name].sendingN++;
      return [header, ciphertext];
   }

   async receiveMessage(name, [header, ciphertext]) {
      if (!(name in this.conns)) {
         //Tạo kết nối nếu là lần đầu
         const sender_cerk_pk = this.certs[name].pub_key;
         const raw_root_key = await computeDH(this.myKeyPairs.cert_sk, sender_cerk_pk);
         const hkdf_input_key = await computeDH(this.myKeyPairs.cert_sk, header.pk_sender);
         const [root_key, chain_key] = await HKDF(hkdf_input_key, raw_root_key, 'ratchet-salt');
         const fresh_pair = await generateEG();
         this.myKeyPairs[name] = { pub_key: fresh_pair.pub, sec_key: fresh_pair.sec };
         const dh_result = await computeDH(this.myKeyPairs[name].sec_key, header.pk_sender);
         const [final_root_key, ck_s] = await HKDF(dh_result, root_key, 'ratchet-salt');

         this.conns[name] = {
            rk: final_root_key,
            ck_r: chain_key,
            ck_s: ck_s,
            sendingN: 0,
            receivingN: 0,
            skippedKeys: {},
         };
         this.conns[name].seenPks = new Set();
      } else if (!this.conns[name].seenPks.has(header.pk_sender)) {
         //Ratchet với khoá công khai mới
         const first_dh_output = await computeDH(this.myKeyPairs[name].sec_key, header.pk_sender);
         let [rk_first, ck_r] = await HKDF(first_dh_output, this.conns[name].rk, 'ratchet-salt');
         const fresh_pair = await generateEG();
         this.myKeyPairs[name] = { pub_key: fresh_pair.pub, sec_key: fresh_pair.sec };
         const second_dh_output = await computeDH(this.myKeyPairs[name].sec_key, header.pk_sender);
         const [rk, ck_s] = await HKDF(second_dh_output, rk_first, 'ratchet-salt');

         // Cập nhật trạng thái
         this.conns[name].rk = rk;
         this.conns[name].ck_s = ck_s;
         this.conns[name].ck_r = ck_r;
         this.conns[name].receivingN = header.N;
      }
      console.log(`Skipped keys:`, this.conns[name].skippedKeys);
      console.log(`Processing message with N=${header.N}`);
      console.log(`Current receivingN=${this.conns[name].receivingN}`);
      // Nếu header.N nhỏ hơn receivingN, bỏ qua tin nhắn (skip) và cập nhật skippedKeys
      let mk;
      if (header.N in this.conns[name].skippedKeys) {
         mk = this.conns[name].skippedKeys[header.N];
         delete this.conns[name].skippedKeys[header.N];
      } else {
         // Sinh khoá cho các tin nhắn bị bỏ qua
         while (this.conns[name].receivingN < header.N) {
            const ck_r = await HMACtoHMACKey(this.conns[name].ck_r, 'ck-str');
            const mk_temp = await HMACtoAESKey(this.conns[name].ck_r, 'mk-str');
            this.conns[name].skippedKeys[this.conns[name].receivingN] = mk_temp;
            this.conns[name].ck_r = ck_r;
            this.conns[name].receivingN++;
         }
         // Sinh khoá cho tin nhắn hiện tại
         const ck_r = await HMACtoHMACKey(this.conns[name].ck_r, 'ck-str');
         mk = await HMACtoAESKey(this.conns[name].ck_r, 'mk-str');
         this.conns[name].ck_r = ck_r;
      }

      this.conns[name].receivingN = Math.max(this.conns[name].receivingN, header.N + 1);
      this.conns[name].seenPks.add(header.pk_sender);

      const plaintext = await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header));
      return bufferToString(plaintext);
   }
}

module.exports = { MessengerClient };
