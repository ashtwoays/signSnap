/**
 * Required Resource
 * Credential Models
 * Moment
 * Crypto
 */
const { CredentialModels } = require('../../models');
const moment = require('moment');
const time = moment();
const crypto = require('crypto');



module.exports = async function (req,res){

    /**
     * Catch Request
     */
    const ClientSecret      = req.ClientSecret;
    const HTTPMethod        = req.HTTPMethod;
    const RelativeUrl       = req.RelativeUrl; 
    const AccessToken       = req.AccessToken; 
    const RequestBody       = req.RequestBody;
    const Timestamp         = req.Timestamp;
     
    
    

    /**
     * Generate Signature
     */
    const hmac = crypto.createHmac('sha512', ClientSecret);
    const sha256 = crypto.createHash('sha256');
    const sha256Body = sha256.update(RequestBody.replace(/\s/g, ' '));
    const digestedBody = sha256Body.digest('hex');
    // const signature = `${HTTPMethod}:${encodeURI(RelativeUrl)}:${AccessToken}:${digestedBody}:${Timestamp}`;

    if(RelativeUrl.split(",").length > 1){
        var signature = hmac.update(`${HTTPMethod}:${RelativeUrl.split(",").join("%2C")}:${AccessToken}:${digestedBody}:${Timestamp}`);
    }else{
        var signature = hmac.update(`${HTTPMethod}:${encodeURI(RelativeUrl)}:${AccessToken}:${digestedBody}:${Timestamp}`);
    }

    /**
     * Response
     */
    const response = {
        ClientSecret  : ClientSecret,
        HTTPMethod    : HTTPMethod,
        RelativeUrl   : RelativeUrl,
        AccessToken   : AccessToken, 
        RequestBody   : RequestBody,
        Timestamp     : req.Timestamp,
        HMAC          : signature.digest('base64') 
    }

    /**
     * Return
     */
    return (response);

}