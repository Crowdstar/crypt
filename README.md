[![Build Status](https://travis-ci.org/Crowdstar/crypt.svg?branch=master)](https://travis-ci.org/Crowdstar/crypt)
[![Latest Stable Version](https://poser.pugx.org/Crowdstar/crypt/v/stable.svg)](https://packagist.org/packages/crowdstar/crypt)
[![Latest Unstable Version](https://poser.pugx.org/Crowdstar/crypt/v/unstable.svg)](https://packagist.org/packages/crowdstar/crypt)
[![License](https://poser.pugx.org/Crowdstar/crypt/license.svg)](https://packagist.org/packages/crowdstar/crypt)

# Summary

The crypt package creates a simple interface for the phpseclib AES-128 library. Its interface allows encryption and decryption of strings with a layer of base64 encoding for easy transmission including the initialization vector.

# Installation

```bash
composer require crowdstar/crypt:~1.0.0
```

# Sample Usage

#### 1. Encrypt and Encode plain text data for storage or transmission


```php
<?php
use CrowdStar\Crypt\Crypt;

$encodedEncryptedData = (new Crypt("secret_key"))->encrypt("message");

```

#### 2. Decoding and Decrypting stored or received data
```php
<?php
use CrowdStar\Crypt\Crypt;

$encodedEncryptedData = (new Crypt("secret_key"))->decrypt("encoded_encrypted_data");
```

#### 3. Encrypting and Decrypting with an alternate length initialization vector
```php
<?php
use CrowdStar\Crypt\Crypt;

$crypt = new Crypt("secret_key");

$alternateIVLength = 8;
$encodedEncryptedData = $crypt->encrypt("message", $alternateIVLength);
$plainText = $crypt->decrypt($encodedEncryptedData, $alternateIVLength);
```
