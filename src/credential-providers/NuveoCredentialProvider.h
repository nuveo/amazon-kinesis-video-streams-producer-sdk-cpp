#ifndef __NUVEO_CREDENTIAL_PROVIDER_H__
#define __NUVEO_CREDENTIAL_PROVIDER_H__
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "Auth.h"
#include "json.hpp"
#include <chrono>


namespace com { namespace amazonaws { namespace kinesis { namespace video {

    class NuveoCredentialProvider : public CredentialProvider {
        std::string client_id_;
        std::string client_secret_;
        PAuthCallbacks rotating_callbacks;
        const std::chrono::duration<uint64_t> ROTATION_PERIOD = std::chrono::seconds(3500);
    public:
        NuveoCredentialProvider(std::string client_id, std::string client_secret) : client_id_(client_id), client_secret_(client_secret) {}
        nlohmann::json exchange_credentials(std::string, std::string);
        void updateCredentials(Credentials& credentials) override {
            auto sts_credentials = exchange_credentials(
                NuveoCredentialProvider::client_id_,
                NuveoCredentialProvider::client_secret_);

            credentials.setAccessKey(sts_credentials["access_key_id"]);
            credentials.setSecretKey(sts_credentials["secret_key"]);
            credentials.setSessionToken(sts_credentials["session_token"]);

            auto now_time = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            );
            auto expiration_seconds = now_time + std::chrono::seconds(31); // TODO: change this
            credentials.setExpiration(std::chrono::seconds(expiration_seconds.count()));

        }
        callback_t getCallbacks(PClientCallbacks) override;
    };

}
}
}
}


#endif /* __NUVEO_CREDENTIAL_PROVIDER_H__ */