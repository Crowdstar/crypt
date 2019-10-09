<?php
/**************************************************************************
 * Copyright 2018 Glu Mobile Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *************************************************************************/

namespace CrowdStar\Crypt;

use phpseclib\Crypt\AES;

/**
 * Class Crypt
 *
 * This class encrypts and decrypts plain text using AES-128 with a variable length initialization vector
 *
 * IV is generated using openssl pseudo random
 *
 * @package CrowdStar\Home
 */
class Crypt
{
    const DEFAULT_IV_LENGTH = 16;

    /**
     * @var AES A CBC-mode AES object using the RSA PKCS padding standards for padding.
     */
    protected $aesCrypt;

    /**
     * Crypt constructor.
     *
     * @param string $secretKey
     */
    public function __construct($secretKey)
    {
        $aesCrypt = new AES();
        $aesCrypt->setKey($secretKey);
        $this->setAesCrypt($aesCrypt);
    }

    /**
     * @return AES
     */
    public function getAesCrypt(): AES
    {
        return $this->aesCrypt;
    }

    /**
     * @param AES $aesCrypt
     * @return Crypt $this
     */
    protected function setAesCrypt(AES $aesCrypt): Crypt
    {
        $this->aesCrypt = $aesCrypt;
        return $this;
    }

    /**
     * generate initialization vector of specified length in bytes
     * @see https://stackoverflow.com/questions/7280769/how-to-securely-generate-an-iv-for-aes-cbc-encryption
     *
     * @param int $length
     * @return string
     * @throws Exception
     */
    private function generateIV(int $length): string
    {
        $iv = openssl_random_pseudo_bytes($length, $wasItSecure);
        if ($wasItSecure) {
            return $iv;
        } else {
            throw new Exception("Non-cryptographically strong algorithm used for iv generation. This IV is not safe to use.");
        }
    }

    /**
     * @param string $plainText
     * @param int $ivLength should match AES block size which is 16/128 bytes/bits
     * @return string
     * @throws Exception
     */
    public function encrypt(string $plainText, int $ivLength = self::DEFAULT_IV_LENGTH): string
    {
        $iv = $this->generateIV($ivLength);
        $aesCrypt = $this->getAesCrypt();
        $aesCrypt->setIV($iv);

        return base64_encode($aesCrypt->encrypt($plainText) . $iv);
    }

    /**
     * @param string $encodedData
     * @param int $ivLength
     * @return string|null
     */
    public function decrypt(string $encodedData, int $ivLength = self::DEFAULT_IV_LENGTH): string
    {
        $data = base64_decode($encodedData);
        $iv = substr($data, -$ivLength);
        $cipherText = substr($data, 0, -$ivLength);
        $aesCrypt = $this->getAesCrypt();
        $aesCrypt->setIV($iv);

        return $aesCrypt->decrypt($cipherText);
    }
}
