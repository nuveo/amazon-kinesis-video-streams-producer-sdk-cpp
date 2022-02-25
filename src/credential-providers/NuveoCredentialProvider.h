#ifndef __NUVEO_CREDENTIAL_PROVIDER_H__
#define __NUVEO_CREDENTIAL_PROVIDER_H__
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "Auth.h"
#include "json.hpp"
#include <chrono>
#include <iostream>

namespace com { namespace amazonaws { namespace kinesis { namespace video {

    class NuveoCredentialProvider : public CredentialProvider {
        std::string SV_COGNITO_AUTH;
        std::string SV_AUTH;
        std::string client_id_;
        std::string client_secret_;
        PAuthCallbacks rotating_callbacks;
        const std::chrono::duration<uint64_t> ROTATION_PERIOD = std::chrono::seconds(3500);
    public:
        NuveoCredentialProvider(std::string client_id, std::string client_secret) : client_id_(client_id), client_secret_(client_secret) {
            NuveoCredentialProvider::SV_COGNITO_AUTH = "https://smartvision.auth.us-east-1.amazoncognito.com";
            NuveoCredentialProvider::SV_AUTH = "https://auth.smartvision.nuveo.ai";
        }
        
        void setSVAuth(std::string svAuth) {
            NuveoCredentialProvider::SV_AUTH = svAuth;
        }

        void setCognitoAuth(std::string cognitoAuth) {
            NuveoCredentialProvider::SV_COGNITO_AUTH = cognitoAuth;
        }

        void updateCredentials(Credentials& credentials) override {
            auto sts_credentials = exchange_credentials(
                NuveoCredentialProvider::client_id_,
                NuveoCredentialProvider::client_secret_);

            credentials.setAccessKey(sts_credentials["AccessKeyId"]);
            credentials.setSecretKey(sts_credentials["SecretKey"]);
            credentials.setSessionToken(sts_credentials["SessionToken"]);
            auto expiration = sts_credentials["Expiration"].get<std::string>();
            std::tm tm = {};
            strptime(expiration.c_str(), "%Y-%m-%dT%H:%M:%S%z", &tm);
            time_t tLoc = mktime(&tm);
            tm = *gmtime(&tLoc);
            time_t tRev = mktime(&tm);
            time_t tDiff = tLoc - tRev;
            time_t tUTC = tLoc + tDiff;
            auto exp = std::chrono::system_clock::from_time_t(tUTC);

            auto exp_time = std::chrono::duration_cast<std::chrono::seconds>(
                exp.time_since_epoch());
            credentials.setExpiration(std::chrono::seconds(exp_time.count()));

        }

        nlohmann::json exchange_credentials(std::string, std::string);

        callback_t getCallbacks(PClientCallbacks) override;
    };

}
}
}
}


#endif /* __NUVEO_CREDENTIAL_PROVIDER_H__ */