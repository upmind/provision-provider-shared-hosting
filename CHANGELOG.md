# Changelog

All notable changes to the package will be documented in this file.

## [v6.6.30](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.30) - 2025-12-17

- Implement SPanel provider

## [v6.6.29](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.29) - 2025-10-14

- Fix illuminate/support dependency

## [v6.6.28](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.28) - 2025-10-14

- Implement Webuzo provider

## [v6.6.27](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.27) - 2025-10-10

- Implement PanelAlpha provider

## [v6.6.26](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.26) - 2025-05-08

- Update upmind/enhance-sdk to v12.3.0

## [v6.6.25](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.25) - 2025-04-24

- Relax username restrictions around login/changePassword() to allow the configuration username in:
  - CentosWeb
  - InterWorx
  - Plesk
  - SolidCP
  - cPanel/WHM

## [v6.6.24](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.24) - 2025-04-14

- Prevent login or change password of the admin/root username in the following providers:
  - CentosWeb
  - DirectAdmin
  - InterWorx
  - Plesk
  - SolidCP
  - cPanel/WHM

## [v6.6.23](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.23) - 2025-04-11

- To avoid issues after migrating accounts from one server to another, remove
  use of `subscription_id` in Plesk provider
- Fix some type errors with reseller accounts in Plesk provider

## [v6.6.22](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.22) - 2025-04-03

- Apply natsort to nameservers before returning them in Plesk provider

## [v6.6.21](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.21) - 2025-02-19

- Update upmind/enhance-sdk to v12

## [v6.6.20](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.20) - 2025-01-16

- Fix Centos Web Panel PHP 7.4 compatibility

## [v6.6.19](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.19) - 2024-12-22

- Implement CentOS Web Panel (CWP) provider

## [v6.6.18](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.18) - 2024-12-04

- Update Enhance getInfo()
  - Increase page size during findCustomerIdByEmail() to improve speed for larger organisations
  - Handle cases where website is not associated with a subscription

## [v6.6.17](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.17) - 2024-12-04

- Update WHMv1 create() add additional debug data to error results

## [v6.6.16](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.16) - 2024-12-02

- Fix getLoginUrl() for newer versions of DirectAdmin

## [v6.6.15](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.15) - 2024-11-13

- Fix CustomerAddressParams make all optional to avoid errors for partial data

## [v6.6.14](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.14) - 2024-11-12

- Update 20i to send additional customer data when creating stack users
  - Attempt to update newly created stack users with name, address and phone number (in EPP format)

## [v6.6.13](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.13) - 2024-11-11

- Update Enhance findPlan() and findServerGroup() to match name case-insensitively

## [v6.6.12](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.12) - 2024-10-15

- Update Plesk
  - Add API request/response debug logging
  - Ignore errors fetching NS when DNS service is not enabled during getInfo()

## [v6.6.11](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.11) - 2024-09-30

- Update 20i getLoginUrl() to always return a HTTPS link

## [v6.6.10](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.10) - 2024-07-25

- Update WHMv1/Provider::processResponse() return response_body in result data when response_data is empty

## [v6.6.9](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.9) - 2024-07-19

- Update DirectAdmin add configuration value to notify client upon account creation

## [v6.6.8](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.8) - 2024-07-19

- Update DirectAdmin/Provider::handleException() with handling for cURL errors
- Update DirectAdmin configuration add optional port
- Update DirectAdmin/Api:getUserConfig() trim username to avoid strange errors

## [v6.6.7](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.7) - 2024-07-16

- Update TwentyI/Data/TwentyICredentials add control_panel_hostname to return in GetInfo for server hostname

## [v6.6.6](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.6) - 2024-07-16

- Update TwentyI/Api::searchForStackUser() to use new explicitStackUserCheck endpoint
- Fix TwentyI/Api::getPackageInfo(): trim $hostingId to prevent cURL errors due to whitespace
- Update TwentyI/Api::handleException() to append result error message if available

## [v6.6.5](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.5) - 2024-07-09

- Fix TwentyI\Provider::getAccountInfoData() type error when IP is unknown

## [v6.6.4](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.4) - 2024-07-09

- Update TwentyI/Provider::getAccountInfoData() fix php error when web.info is missing

## [v6.6.3](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.3) - 2024-07-09

- Update TwentyI/Api::searchForStackUser() with an initial call to attempt to create the stack user before searching for it

## [v6.6.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.2) - 2024-05-31

- Update TwentyI\Api::searchForStackUser() to use new explicitStackUser endpoint to improve performance for larger reseller accounts

## [v6.6.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.1) - 2024-04-05

- Update WHMv1 create() to drop www. prefix from domain names

## [v6.6.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.6.0) - 2024-02-19

- Add optional `location` parameter value to `CreateParams` and return value to `AccountInfo`
  - Add logic to Enhance to select server group based on `location` parameter and return group name in `AccountInfo`
  - Add logic to 20i to select data centre based on `location` parameter and return zone name in `AccountInfo`
- Improve error messages for Enhance 409 "already_exists" errors
- Add Enhance configuration value `create_subscription_only` to skip creating a website when calling `create()`
- Delete newly created Enhance customers if subscription or website creation fails

## [v6.5.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.5.2) - 2024-01-08

- Update DirectAdmin add `ip_status` configuration value to specify IP status type
  when allocating IPs to new accounts
    - By default, automatically prefer `server` then `shared` then `free`

## [v6.5.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.5.1) - 2023-12-22

- Update DirectAdmin\\Api::getLoginUrl() to add 127.0.0.1 to session IPs

## [v6.5.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.5.0) - 2023-12-19

- Update getLoginUrl()
  - Add optional support for passing `current_password`
  - Add optional support for returning `post_fields`
  - Implement SolidCP post fields response

## [v6.4.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.4.1) - 2023-12-19

- Update upmind/enhance-sdk to v10

## [v6.4.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.4.0) - 2023-12-19

- Implement DirectAdmin

## [v6.3.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.3.1) - 2023-10-30

- Fix 20i API requests where logging was previously missing

## [v6.3.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.3.0) - 2023-10-05

- Implement SolidCP provider

## [v6.2.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.2.1) - 2023-09-29

- Remove Enhance website PHP version update API call

## [v6.2.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.2.0) - 2023-09-22

- Add InterWorx provider

## [v6.1.3](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.1.3) - 2023-08-10

- Update Enhance createCustomer() improve error message when customer email already exists

## [v6.1.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.1.2) - 2023-06-30

- Update 20i TwentyI\\Api error handling; add request url and response data to error data

## [v6.1.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.1.1) - 2023-06-30

- Update 20i TwentyI\\Api error handling; improve error message for 401 errors

## [v6.1.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.1.0) - 2023-06-29

- Update upmind/enhance-sdk to v9.4.0

## [v6.0.3](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.0.3) - 2023-06-14

- Update 20i provider to fall back to finding package info by domain if username is not valid
  - This fixes issues where orders imported from WHMCS have false usernames
  - When a match is found by domain, return the hosting id as username to correct for future requests

## [v6.0.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.0.2) - 2023-06-05

- Implement TwentyI getUsage() function

## [v6.0.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.0.1) - 2023-05-31

- Update WHMv1 API error result data/debug

## [v6.0.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v6.0.0) - 2023-04-21

- Fix WHMv1 revokeReseller() return data
- Add `is_reseller` to AccountUsername params
- Add getUsage() function
- Implement getUsage() function for WHMv1 and Enhance providers

## [v5.8.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.8.2) - 2023-04-07

- Update Enhance provider, add better tolerance for website domain not found

## [v5.8.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.8.1) - 2023-03-15

- Update Demo provider AccountInfo

## [5.8](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/5.8) - 2023-03-15

- Add Example provider as a basic template for creating new providers
- Add stateless Demo provider which returns fake data

## [v5.7](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.7) - 2023-02-24

- Add SoftwareInstallation datasets
- Implement Wordpress installation via softaculous as a WHMv1 configuration variable
- Implement softaculous installation SSO in WHMv1 getLoginUrl()
- Add debug logging to WHMv1 provider

## [v5.6.6](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.6.6) - 2023-02-13

- Fix implementation of `remove_www` in v5.6.5

## [v5.6.5](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.6.5) - 2023-02-13

- Update Enhance configuration add `remove_www` setting to optionally remove www.
  subdomain from hostnames during create()

## [v5.6.4](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.6.4) - 2023-02-13

- Update WHMv1 Provider asyncApiCall() exception handling to catch and re-throw
  any Guzzle TransferException (incl. connection errors/timeouts)

## [v5.6.3](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.6.3) - 2023-01-25

- Update `upmind/enhance-sdk` to v9

## [v5.6.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.6.2) - 2023-01-17

- Update Enhance handleException() improve 404 error messages

## [v5.6.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.6.1) - 2023-01-17

- Handle + debug null $result in Enhance findWebsite()

## [v5.6.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.6.0) - 2023-01-10

- Make domain optional when creating new Enhance subscriptions

## [v5.5.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.5.1) - 2023-01-10

- Fix Enhance findWebsite() domain search logic where subscription contained
  subdomains of the searched root domain

## [v5.5.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.5.0) - 2023-01-09

- Add optional domain param to GetLoginUrlParams
- Utilize domain param for Enhance Wordpress login

## [v5.4.4](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.4.4) - 2023-01-03

- Fix Enhance provider findWebsite() to exclude deleted websites

## [v5.4.3](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.4.3) - 2022-12-16

- Fix Enhance getLoginUrl() where websiteId is not known
- Update Enhance findWebsite() to load whole website object including IPs

## [v5.4.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.4.2) - 2022-12-14

- Update Enhance provider with QoL improvements for manually importing accounts
  - Make customer_id optional, falling back to finding customer by username (owner
    email address)
  - Update getInfo() to find subscription by domain if subscription id is not passed

## [v5.4.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.4.1) - 2022-12-05

- Fix Enhance getLoginUrl() for configurations with null sso_destination

## [v5.4.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.4.0) - 2022-12-05

- Update to Enhance SDK v8.1.0
- Implement Enhance CP SSO for panels running v8.2+

## [v5.3.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.3.0) - 2022-11-23

- Add optional domain parameter for getInfo(), changePackage(), suspend()
  unsuspend() & terminate() functions
- Update Plesk provider to make use of customer_id and subscription_id with fall-
  back to domain for cases where username is re-used across subscriptions, and
  subscription_id is not known (non-reseller)
- Improve Plesk error handling / messages

## [v5.2.5](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.2.5) - 2022-11-09

- Fix Enhance getWordpressLoginUrl() return value

## [v5.2.4](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.2.4) - 2022-11-09

- Update Enhance sso_destination configuration field options to be lowercase (fixes
  an issue with consumers using HtmlField which doesnt support uppercase chars in
  option values)

## [v5.2.3](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.2.3) - 2022-11-09

- Update to Enhance SDK v8.0.0
- Append Enhance CP status + version meta-data to error result data
- Add Enhance configuration value for getLoginUrl() to return either Enhance or
  Wordpress SSO urls

## [v5.2.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.2.2) - 2022-11-08

- Improve handling of cURL errors (e.g., SSL issues) in Enhance provider
- Add option to ignore Enhance SSL errors

## [v5.2.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.2.1) - 2022-11-07

- Fix several Enhance provider type errors

## [v5.2.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.2.0) - 2022-10-21

- Require upmind/provision-provider-base ^3.4
- Update Enhance Api config to use https instead of http
- Update Enhance createCustomer() return debug error if customer id is empty
- Update Enhance handleException() append response message to result error message

## [v5.1.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.1.1) - 2022-10-20

- Make CreateParams `customer_name` optional

## [v5.1.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.1.0) - 2022-10-20

- Require upmind/provision-provider-base ^3.3
- Fix Enhance provider generateRandomPassword() so a valid password is always
  returned

## [v5.0.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v5.0.0) - 2022-10-20

#### New
- Implement Enhance provider using OpenAPI sdk
- Change param and result sets to include optional subscription_id

#### Breaking
- Require customer_name in param dataset CreateParams
- Make expires optional in result dataset LoginUrl

## [v4.3.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.3.1) - 2022-10-18

- Update TwentyI Provider to not implement LogsDebugData twice

## [v4.3.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.3.0) - 2022-10-14

- Update to `upmind/provision-provider-base` v3.0.0
- Add icon to Category AboutData
- Add logo_url to Providers' AboutData

## [v4.2.6](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.2.6) - 2022-09-23

- Update WHMv1\Provider to automatically prepend reseller username to package names
  when needed

## [v4.2.5](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.2.5) - 2022-09-23

- Fix WHMv1\Provider::processResponse()

## [v4.2.4](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.2.4) - 2022-09-23

- Improve debug data for WHMv1 error results when API response contains no parsable
  result data

## [v4.2.3](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.2.3) - 2022-09-12

- Fix PleskOnyxRPC provider

## [v4.2.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.2.2) - 2022-08-26

- Treat WHMv1 HTTP 524 responses as regular request timeouts [#11](https://github.com/upmind-automation/provision-provider-shared-hosting/issues/11)

## [v4.2.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.2.1) - 2022-08-25

- Increase WHMv1 createacct timeout to 240
- Attempt to recover from create/suspend/unsuspend timeouts by checking the status
  of the account and returning success if it appears the operation has succeeded
  but is still in progress [#11](https://github.com/upmind-automation/provision-provider-shared-hosting/issues/11)

## [v4.2](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.2) - 2022-07-12

- Add support for optional hosting platform customer_id
- Update 20i provider; add API call debug logging, always find or create an
  explicit stack user when creating new accounts, and implement support for customer_id

## [v4.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.1) - 2022-06-07

Update cPanel (WHMv1) provider; remove confusing configuration values, simplify
HTTP client creation, and increase request timeout for suspend/unsuspend/terminate
functions for reseller accounts
## [v4.0.1](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.0.1) - 2022-05-30

Fix WHMv1 Api ClientFactory compatibility with base ClientFactory

## [v4.0](https://github.com/upmind-automation/provision-provider-shared-hosting/releases/tag/v4.0) - 2022-04-29

Initial public release
