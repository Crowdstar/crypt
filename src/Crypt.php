<?php
/**
 * Copyright 2021 Glu Mobile Inc.
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
 */

declare(strict_types=1);

namespace CrowdStar\Crypt;

use phpseclib3\Crypt\AES;
use phpseclib3\Exception\BadDecryptionException;

/**
 * This class encrypts and decrypts plain text using AES-128 with a variable length initialization vector. IV is
 * generated using openssl pseudo random.
 */
class Crypt
{
    public const DEFAULT_IV_LENGTH = 16;

    /**
     * A CBC-mode AES object using the RSA PKCS padding standards for padding.
     */
    protected AES $aesCrypt;

    public function __construct(string $secretKey)
    {
        $aesCrypt = new AES('cbc');
        $aesCrypt->setKey($secretKey);
        $this->setAesCrypt($aesCrypt);
    }

    /**
     * @param int $ivLength should match AES block size which is 16/128 bytes/bits
     * @throws Exception
     */
    public function encrypt(string $plainText, int $ivLength = self::DEFAULT_IV_LENGTH): string
    {
        $iv       = $this->generateIV($ivLength);
        $aesCrypt = $this->getAesCrypt();
        $aesCrypt->setIV($iv);

        return base64_encode($aesCrypt->encrypt($plainText) . $iv);
    }

    /**
     * @return string when bad data is passed in, the return value will be an empty string
     */
    public function decrypt(string $encodedData, int $ivLength = self::DEFAULT_IV_LENGTH): string
    {
        $data       = base64_decode($encodedData);
        $iv         = substr($data, -$ivLength);
        $cipherText = substr($data, 0, -$ivLength);
        $aesCrypt   = $this->getAesCrypt();

        try {
            $aesCrypt->setIV($iv);
        } catch (\LengthException $e) {
            return '';
        }

        try {
            return $aesCrypt->decrypt($cipherText);
        } catch (BadDecryptionException|\LengthException $e) {
            return '';
        }
    }

    protected function setAesCrypt(AES $aesCrypt): self
    {
        $this->aesCrypt = $aesCrypt;
        return $this;
    }

    protected function getAesCrypt(): AES
    {
        return $this->aesCrypt;
    }

    /**
     * Generate initialization vector of specified length in bytes.
     *
     * @throws Exception
     * @see https://stackoverflow.com/questions/7280769/how-to-securely-generate-an-iv-for-aes-cbc-encryption
     */
    private function generateIV(int $length): string
    {
        if ($length < 1) {
            throw new Exception('The length of the desired string of bytes must be a positive integer.');
        }
        $iv = openssl_random_pseudo_bytes($length, $wasItSecure);
        if (!$wasItSecure) {
            throw new Exception('Non-cryptographically strong algorithm used for iv generation. This IV is not safe to use.');
        }
        return $iv;
    }
}
