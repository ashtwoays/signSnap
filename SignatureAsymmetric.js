/**
 * Required Resource
 * Credential Models
 * Moment
 * Crypto
 * FS 
 */
const { CredentialModels } = require('../../models');
const moment = require('moment');
const time = moment();
const crypto = require('crypto');
const fs = require('fs');
const {client_id} = process.env


module.exports = async function(req, res){
    // Get Credentials Data
    // const Credential = await CredentialModels.findAll();

    // Init Credentials Data
    // const client_ID  = Credential[0].client_id;
    const client_ID  = client_id;
    const XTimestamp = moment().format();

    // Init Resource
    const StringToSign = `${client_ID}|${XTimestamp}`;
    const privateKey = fs.readFileSync("private-key.pem", 'utf8');

    // Create Sign
    const sign = crypto.createSign('sha256');
    sign.update(StringToSign);
    sign.end();
    const AsymmetricSignature = sign.sign(privateKey, 'base64');

    // Return Data
    const data = {
        signature : AsymmetricSignature,
        time      : XTimestamp,
        client_ID : client_ID
    }

    // Return
    return (data)

}





