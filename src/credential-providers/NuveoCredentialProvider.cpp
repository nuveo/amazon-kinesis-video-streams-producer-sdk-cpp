#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "NuveoCredentialProvider.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include "httplib.h"
#include "json.hpp"

LOGGER_TAG("com.amazonaws.kinesis.video");

using namespace com::amazonaws::kinesis::video;
using namespace std;

static std::string base64_encode(const std::string &in)
{

    std::string out;

    int val = 0, valb = -6;
    for (u_char c : in)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

nlohmann::json NuveoCredentialProvider::exchange_credentials(string client_id, string client_secret)
{
    // OAuth with Cognito
    httplib::Client cli(NuveoCredentialProvider::SV_COGNITO_AUTH);
    cli.enable_server_certificate_verification(false);

    auto to_encode = client_id + ":" + client_secret;
    httplib::Headers headers = {
                         {"Authorization", "Basic " + base64_encode(to_encode)}};

    auto res = cli.Post(
        "/oauth2/token",
        headers,
        "grant_type=client_credentials",
        "application/x-www-form-urlencoded");

    if (!res) {
        auto err = res.error();
        std::stringstream ss;
        ss << "Error while trying to get access_token: " << err << std::endl;
        LOG_DEBUG(NuveoCredentialProvider::SV_COGNITO_AUTH)
        LOG_AND_THROW(ss.str());
    }

    if (res->status != 200) {
        std::stringstream ss;
        ss << "Got status code: " << res->status << std::endl;
        LOG_DEBUG(ss.str());

        auto err_details = nlohmann::json::parse(res->body);
        LOG_AND_THROW(err_details);
    }

    auto parsed_res = nlohmann::json::parse(res->body);
    auto access_token = parsed_res["access_token"].get<std::string>();

    // Call STS Credentials endpoint
    httplib::Client sv_auth(NuveoCredentialProvider::SV_AUTH);
    sv_auth.enable_server_certificate_verification(false);
    LOG_INFO("Calling endpoint for getting STS credentials");

    headers = {
        {"Authorization", "Bearer " + access_token}};

    res = sv_auth.Get(
        "/v1/credentials",
        headers);

    if (!res) {
        auto err = res.error();
        std::stringstream ss;
        ss << "Error while trying to get STS credentials: " << err << std::endl;
        LOG_DEBUG(NuveoCredentialProvider::SV_AUTH)
        LOG_AND_THROW(ss.str());
    }

    if (res->status != 200) {
        std::stringstream ss;
        ss << "Got status code: " << res->status << std::endl;
        LOG_DEBUG(ss.str());

        auto err_details = nlohmann::json::parse(res->body);
        LOG_AND_THROW(err_details);
    }

    auto credentials = nlohmann::json::parse(res->body);

    return credentials;
}

NuveoCredentialProvider::callback_t NuveoCredentialProvider::getCallbacks(PClientCallbacks client_callbacks) 
{
    auto rc = CredentialProvider::getCallbacks(client_callbacks);
    return rc;
}
