'use strict';

const jsonwebtoken    = require('jsonwebtoken');
const request         = require('request');
const cache           = require('./azure-ad-cache');

function AzureActiveDirectoryValidationManager() {
    const self = this;

    function convertCertificateToBeOpenSSLCompatible(cert) {
        //Certificate must be in this specific format or else the function won't accept it
        const beginCert = '-----BEGIN CERTIFICATE-----';
        const endCert = '-----END CERTIFICATE-----';
        const EOL = '\n'; //PEM files use unix style EOL.

        cert = cert.replace(EOL, '');
        cert = cert.replace(beginCert, '');
        cert = cert.replace(endCert, '');

        let result = beginCert;
        while (cert.length > 0) {
            
            if (cert.length > 64) {
                result += EOL + cert.substring(0, 64);
                cert = cert.substring(64, cert.length);
            } else {
                result += EOL + cert;
                cert = '';
            }

        }

        if (result[result.length ] !== EOL) {
            result += EOL;
        }
        result += endCert + EOL;
        return result;
    }

    /*
     * Extracts the tenant id from the give jwt token
     */
    self.getTenantId = function(jwtString) {
        var decodedToken = jsonwebtoken.decode(jwtString);

        if (decodedToken) {
            return decodedToken.tid;
        } else {
            return null;
        }
    };

    /*
     * This function loads the open-id configuration for a specific AAD tenant
     * from a well known application.
     */
    self.requestOpenIdConfig = function(tenantId, cb) {
        // we need to load the tenant specific open id config
        const tenantOpenIdconfig = {
            url: `https://login.windows.net/${tenantId}/.well-known/openid-configuration`,
            json: true
        };

        const cachedValue = cache.get(tenantOpenIdconfig);
        if (cachedValue) return cb(null, cachedValue);

        request.get(tenantOpenIdconfig, function(error, response, result) {
            if (error) {
                return cb(error);
            } else {
                cache.put(tenantOpenIdconfig, result);
                return cb(null, result);
            }
        });
    };

    /*
     * Download the signing certificates which is the public portion of the
     * keys used to sign the JWT token.  Signature updated to include options for the kid.
     */
    self.requestSigningCertificates = function(jwtSigningKeysLocation, options, cb) {

        const jwtSigningKeyRequestOptions = {
            url: jwtSigningKeysLocation,
            json: true
        };

        const cachedValue = cache.get(jwtSigningKeysLocation);
        if (cachedValue) { 
            return cb(null, cachedValue);
        }

        request.get(jwtSigningKeyRequestOptions, function(error, response, result) {
            if (error) {
                return cb(error);
            } else {
                const certificates = [];

                //Use KID to locate the public key and store the certificate chain.
                if (options && options.kid) {
                    result.keys.find(function(publicKey) {
                        if (publicKey.kid === options.kid) {
                            publicKey.x5c.forEach(function(certificate) {
                                certificates.push(convertCertificateToBeOpenSSLCompatible(certificate));
                            });
                        }
                    });
                } else {
                    result.keys.forEach(function(publicKeys) {
                        publicKeys.x5c.forEach(function(certificate) {
                            certificates.push(convertCertificateToBeOpenSSLCompatible(certificate));
                        });
                    });
                }

                // good to go
                cache.put(jwtSigningKeysLocation, certificates);
                return cb(null, certificates);
            }
        });
    };

    /*
     * This function tries to verify the token with every certificate until
     * all certificates was testes or the first one matches. After that the token is valid
     */
    self.verify = function(jwt, certificates, options = {}, cb) {

        // set the correct algorithm
        options.algorithms = ['RS256'];

        // set the issuer we expect
        options.issuer = `https://sts.windows.net/${self.getTenantId(jwt)}/`;

        let valid = false;
        let lastError = null;
        
        certificates.every(function(certificate) {
            // verify the token
            try {
                // verify the token
                jsonwebtoken.verify(jwt, certificate, options);

                // set the state
                valid = true;
                lastError = null;

                // abort the enumeration
                return false;
            } catch(error) {

                // set teh error state
                lastError = error;

                // check if we should try the next certificate
                if (error.message === 'invalid signature') {
                    return true;
                } else {
                    return false;
                }
            }
        });     
    
        // done
        if (valid) {
            return cb(null, jsonwebtoken.decode(jwt));
        } else {
            return cb(lastError, null);
        }
    };
}

module.exports = exports = AzureActiveDirectoryValidationManager;
