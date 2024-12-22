# [Upmind Provision Providers](https://github.com/upmind-automation) - Shared Hosting

[![Latest Version on Packagist](https://img.shields.io/packagist/v/upmind/provision-provider-shared-hosting.svg?style=flat-square)](https://packagist.org/packages/upmind/provision-provider-shared-hosting)

This provision category contains the common functions used in provisioning flows for accounts/websites on various popular shared hosting platforms.

- [Installation](#installation)
- [Usage](#usage)
  - [Quick-start](#quick-start)
- [Supported Providers](#supported-providers)
- [Functions](#functions)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)
- [Upmind](#upmind)

## Installation

```bash
composer require upmind/provision-provider-shared-hosting
```

## Usage

This library makes use of [upmind/provision-provider-base](https://packagist.org/packages/upmind/provision-provider-base) primitives which we suggest you familiarize yourself with by reading the usage section in the README.

### Quick-start

The easiest way to see this provision category in action and to develop/test changes is to install it in [upmind/provision-workbench](https://github.com/upmind-automation/provision-workbench#readme).

Alternatively you can start using it for your business immediately with [Upmind.com](https://upmind.com/start) - the ultimate web hosting billing and management solution.

**If you wish to develop a new Provider, please refer to the [WORKFLOW](WORKFLOW.md) guide.**

## Supported Providers

The following providers are currently implemented:
  - [cPanel/WHM](https://api.docs.cpanel.net/)
  - [Plesk (Onyx/Obsidian)](https://docs.plesk.com/en-US/onyx/api-rpc/introduction.79358/)
  - [20i](https://www.20i.com/reseller-hosting)
  - [Enhance](https://enhance.com/)
  - [InterWorx](https://appendix.interworx.com/current/api/index.html)
  - [SolidCP](https://solidcp.com/kb/)
  - [DirectAdmin](https://www.directadmin.com/api.php)
  - [CentOS Web Panel (CWP)](https://docs.control-webpanel.com/docs/developer-tools/api-manager/functions)

## Functions

| Function | Parameters | Return Data | Description |
|---|---|---|---|
| create() | [_CreateParams_](src/Data/CreateParams.php) | [_AccountInfo_](src/Data/AccountInfo.php) | Create a web hosting account / website |
| getInfo() | [_AccountUsername_](src/Data/AccountUsername.php) | [_AccountInfo_](src/Data/AccountInfo.php) | Get information about a hosting account such as the main domain name, whether or not it is suspended, the hostname of it's server, nameservers etc |
| getUsage() | [_AccountUsername_](src/Data/AccountUsername.php) | [_AccountUsage_](src/Data/AccountUsage.php) | Gets usage information about an account/reseller such as disk space, bandwidth, number of sub-accounts etc |
| getLoginUrl() | [_GetLoginUrlParams_](src/Data/GetLoginUrlParams.php) | [_LoginUrl_](src/Data/LoginUrl.php) | Obtain a signed URL to automatically log into a hosting account |
| changePassword() | [_ChangePasswordParams_](src/Data/ChangePasswordParams.php) | [_EmptyResult_](src/Data/EmptyResult.php) | Change the password of a hosting account |
| changePackage() | [_ChangePackageParams_](src/Data/ChangePackageParams.php) | [_AccountInfo_](src/Data/AccountInfo.php) | Update the product/package a hosting account is set to |
| suspend() | [_SuspendParams_](src/Data/SuspendParams.php) | [_AccountInfo_](src/Data/AccountInfo.php) | Suspend service for a hosting account |
| unSuspend() | [_AccountUsername_](src/Data/AccountUsername.php) | [_AccountInfo_](src/Data/AccountInfo.php) | Un-suspend service for a hosting account |
| terminate() | [_AccountUsername_](src/Data/AccountUsername.php) | [_EmptyResult_](src/Data/EmptyResult.php) | Completely delete a hosting account |
| grantReseller() | [_GrantResellerParams_](src/Data/GrantResellerParams.php) | [_ResellerPrivileges_](src/Data/ResellerPrivileges.php) | Grant reseller privileges to a web hosting account, if supported |
| revokeReseller() | [_AccountUsername_](src/Data/AccountUsername.php) | [_ResellerPrivileges_](src/Data/ResellerPrivileges.php) | Revoke reseller privileges from a web hosting account, if supported |

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Credits

 - [Harry Lewis](https://github.com/uphlewis)
 - [Nikolai Arsov](https://github.com/nikiarsov777)
 - [Codeline](https://github.com/CodelineNL)
 - [Nikolay Bogdanov](https://github.com/nikolay-mocha)
 - [Ana Carrasco](https://github.com/AnaGema)
 - [Roussetos Karafyllakis](https://github.com/RoussKS)
 - [All Contributors](../../contributors)

## License

GNU General Public License version 3 (GPLv3). Please see [License File](LICENSE.md) for more information.

## Upmind

Sell, manage and support web hosting, domain names, ssl certificates, website builders and more with [Upmind.com](https://upmind.com/start).
