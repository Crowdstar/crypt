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

namespace CrowdStar\Tests;

use CrowdStar\Crypt\Crypt;
use CrowdStar\Crypt\Exception;
use PHPUnit\Framework\TestCase;

/**
 * Tests for class \CrowdStar\Crypt\Crypt.
 */
class CryptTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testEncryptionDecryption()
    {
        $testMessage = 'test_message';
        $crypt = new Crypt('test_secret');

        $encodedData = $crypt->encrypt($testMessage);

        // ensure message is encrypted
        $data = base64_decode($encodedData);
        $cipherText = substr($data, 0, -Crypt::DEFAULT_IV_LENGTH);

        // does not measure security but ensures the cipher text is some distance away from the original message
        $this->assertGreaterThan(5, levenshtein($testMessage, $cipherText));

        // ensure message is decrypted correctly
        $this->assertEquals($testMessage, $crypt->decrypt($encodedData));
    }

    /**
     * @throws Exception
     */
    public function testBadIVLength()
    {
        $this->expectExceptionMessage("Non-cryptographically strong algorithm used for iv generation. This IV is not safe to use.");
        (new Crypt('test_secret'))->encrypt('test_message', 0);
    }
}
